"""
Unit and integration tests for Phase 8: Audit and Observability.
Verifies tamper-evident audit records, secret redaction, multi-destination sinks,
retention management (age and volume), interceptor integration, and CLI commands.
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import pytest
from typer.testing import CliRunner

from runtimeverify.audit import (
    AuditRecord,
    AuditRecordType,
    AuditRetentionConfig,
    AuditService,
    AuditSeverity,
    CompositeAuditSink,
    ConsoleAuditSink,
    FileAuditRepository,
    FileAuditSink,
    MemoryAuditRepository,
    MemoryAuditSink,
    ObjectStorageAuditSink,
    PostgresAuditSink,
    SIEMAuditSink,
    SecretRedactor,
    redact_secrets,
)
from runtimeverify.cli import app as cli_app
from runtimeverify.events.canonical import CanonicalEvent
from runtimeverify.events.enums import EventAction, EventType
from runtimeverify.interception import (
    Action,
    ExecutionBlockedError,
    InterceptionMode,
    RuntimeActionInterceptor,
)
from runtimeverify.policy.evaluator import PolicyEvaluator
from runtimeverify.policy.loader import load_policy_from_yaml
from runtimeverify.policy.models import PolicyDecisionType


# ============================================================================
# 1. Secret Redactor Tests
# ============================================================================


class TestSecretRedaction:
    def test_redact_sensitive_keys(self):
        redactor = SecretRedactor()
        payload = {
            "username": "alice",
            "password": "super-secret-password-123",
            "api_key": "my-api-key-value",
            "client_secret": "oauth-client-secret-999",
            "nested": {
                "auth_token": "token-xyz",
                "safe_field": "visible_value",
            },
        }
        sanitized, modified = redactor.redact(payload)
        assert modified is True
        assert sanitized["username"] == "alice"
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["client_secret"] == "[REDACTED]"
        assert sanitized["nested"]["auth_token"] == "[REDACTED]"
        assert sanitized["nested"]["safe_field"] == "visible_value"

    def test_redact_openai_key(self):
        redactor = SecretRedactor()
        text = "Calling OpenAI using key sk-proj-123456789012345678901234567890123456789012345678 for completions"
        sanitized, modified = redactor.redact(text)
        assert modified is True
        assert "sk-proj-1234" not in sanitized
        assert "[REDACTED_OPENAI_KEY]" in sanitized

    def test_redact_aws_key(self):
        redactor = SecretRedactor()
        text = "Connecting with AWS access key AKIAIOSFODNN7EXAMPLE to S3"
        sanitized, modified = redactor.redact(text)
        assert modified is True
        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
        assert "[REDACTED_AWS_KEY_ID]" in sanitized

    def test_redact_github_token(self):
        redactor = SecretRedactor()
        token = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
        text = f"git clone https://{token}@github.com/repo.git"
        sanitized, modified = redactor.redact(text)
        assert modified is True
        assert "ghp_" not in sanitized
        assert "[REDACTED_GITHUB_TOKEN]" in sanitized

    def test_redact_bearer_token(self):
        redactor = SecretRedactor()
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        sanitized, modified = redactor.redact(text)
        assert modified is True
        assert "eyJhbGci" not in sanitized
        assert "Bearer [REDACTED_BEARER_TOKEN]" in sanitized

    def test_redact_private_key(self):
        redactor = SecretRedactor()
        key_block = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y7x...dummy-rsa-key-data...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        sanitized, modified = redactor.redact(key_block)
        assert modified is True
        assert "dummy-rsa-key-data" not in sanitized
        assert "[REDACTED_PRIVATE_KEY]" in sanitized

    def test_redact_database_url_credentials(self):
        redactor = SecretRedactor()
        url = "postgres://admin:SuperSecretPass123!@db.internal.net:5432/production"
        sanitized, modified = redactor.redact(url)
        assert modified is True
        assert "SuperSecretPass123!" not in sanitized
        assert "postgres://admin:[REDACTED_PASSWORD]@db.internal.net:5432/production" in sanitized

    def test_redact_no_secrets_unchanged(self):
        redactor = SecretRedactor()
        safe_data = {
            "action": "git status",
            "file": "README.md",
            "count": 42,
            "items": ["one", "two"],
        }
        sanitized, modified = redactor.redact(safe_data)
        assert modified is False
        assert sanitized == safe_data

    def test_redact_secrets_module_function(self):
        token = "ghp_" + "012345678901234567890123456789012345"
        text = f"My secret token is {token}"
        sanitized, mod = redact_secrets(text)
        assert mod is True
        assert "ghp_" not in sanitized


# ============================================================================
# 2. Audit Record Models Tests
# ============================================================================


class TestAuditRecordModels:
    def test_record_creation_defaults(self):
        record = AuditRecord(
            record_type=AuditRecordType.POLICY_DECISION,
            severity=AuditSeverity.INFO,
            summary="Policy evaluated successfully",
            agent_id="agent-007",
            trace_id="trace-abc",
        )
        assert record.record_id is not None
        assert len(record.record_id) == 36  # UUID4 format
        assert record.timestamp.tzinfo is not None
        assert record.record_type == AuditRecordType.POLICY_DECISION
        assert record.severity == AuditSeverity.INFO
        assert record.summary == "Policy evaluated successfully"
        assert record.agent_id == "agent-007"
        assert record.trace_id == "trace-abc"
        assert record.redacted is False

    def test_record_ndjson_serialization(self):
        record = AuditRecord(
            record_type=AuditRecordType.EVENT,
            severity=AuditSeverity.WARNING,
            summary="Shell command executed",
            agent_id="dev-agent",
            session_id="session-1",
            details={"command": "ls -la"},
        )
        line = record.to_ndjson()
        assert "\n" not in line
        parsed = json.loads(line)
        assert parsed["record_type"] == "EVENT"
        assert parsed["severity"] == "WARNING"
        assert parsed["details"]["command"] == "ls -la"

        deserialized = AuditRecord.model_validate(parsed)
        assert deserialized.record_id == record.record_id
        assert deserialized.summary == record.summary


# ============================================================================
# 3. Sinks Tests
# ============================================================================


class TestAuditSinks:
    def test_memory_audit_sink(self):
        sink = MemoryAuditSink()
        rec = AuditRecord(
            record_type=AuditRecordType.EVENT,
            severity=AuditSeverity.INFO,
            summary="Action observed",
            details={"password": "secret-plaintext"},
        )
        sink.emit(rec)
        assert len(sink.records) == 1
        stored = sink.records[0]
        # Memory sink sanitizes records
        assert stored.details["password"] == "[REDACTED]"
        assert stored.redacted is True

        sink.clear()
        assert len(sink.records) == 0

    def test_file_audit_sink(self, tmp_path: Path):
        log_file = tmp_path / "sub" / "audit.log"
        sink = FileAuditSink(file_path=str(log_file))

        token = "ghp_" + "111122223333444455556666777788889999"
        rec = AuditRecord(
            record_type=AuditRecordType.POLICY_DECISION,
            severity=AuditSeverity.HIGH,
            summary=f"Blocked access with token {token}",
            details={"target": "/etc/passwd"},
        )
        sink.emit(rec)

        assert log_file.exists()
        content = log_file.read_text(encoding="utf-8")
        assert "ghp_" not in content
        assert "[REDACTED_GITHUB_TOKEN]" in content
        assert "/etc/passwd" in content

    def test_console_audit_sink(self, capsys):
        sink = ConsoleAuditSink()
        rec = AuditRecord(
            record_type=AuditRecordType.SPRT_STATE_CHANGE,
            severity=AuditSeverity.WARNING,
            summary="SPRT threshold reached",
        )
        sink.emit(rec)
        captured = capsys.readouterr()
        assert "SPRT_STATE_CHANGE" in captured.out
        assert "SPRT threshold reached" in captured.out

    def test_composite_audit_sink(self, tmp_path: Path):
        mem_sink = MemoryAuditSink()
        file_path = tmp_path / "comp.log"
        file_sink = FileAuditSink(file_path=str(file_path))

        comp = CompositeAuditSink([mem_sink, file_sink])
        rec = AuditRecord(
            record_type=AuditRecordType.APPROVAL_REQUEST,
            severity=AuditSeverity.HIGH,
            summary="Approval requested",
        )
        comp.emit(rec)

        assert len(mem_sink.records) == 1
        assert file_path.exists()
        assert "APPROVAL_REQUEST" in file_path.read_text(encoding="utf-8")

    def test_enterprise_sink_stubs(self):
        pg_sink = PostgresAuditSink("postgresql://localhost/audit")
        rec = AuditRecord(
            record_type=AuditRecordType.EVENT,
            severity=AuditSeverity.INFO,
            summary="DB audit event",
        )
        pg_sink.emit(rec)
        assert len(pg_sink._buffer) == 1
        pg_sink.flush()
        assert len(pg_sink._buffer) == 0

        obj_sink = ObjectStorageAuditSink("s3://bucket/audit")
        obj_sink.emit(rec)
        assert len(obj_sink._buffer) == 1
        obj_sink.flush()
        assert len(obj_sink._buffer) == 0

        siem_sink = SIEMAuditSink("https://siem.internal:8088", auth_token="token-xyz")
        siem_sink.emit(rec)
        assert siem_sink.endpoint_url == "https://siem.internal:8088"
        assert siem_sink.auth_token == "token-xyz"


# ============================================================================
# 4. Audit Repository and Retention Tests
# ============================================================================


class TestAuditRepositories:
    def test_retention_config(self):
        cfg = AuditRetentionConfig(max_age_days=30, max_records=1000)
        assert cfg.max_age_days == 30
        assert cfg.max_records == 1000

    def test_memory_repository_query_and_retention(self):
        repo = MemoryAuditRepository()
        now = datetime.now(timezone.utc)

        # Insert 5 records over time
        for i in range(5):
            t = now - timedelta(days=i * 10)
            rec = AuditRecord(
                record_id=f"rec-{i}",
                timestamp=t,
                record_type=AuditRecordType.EVENT if i % 2 == 0 else AuditRecordType.POLICY_DECISION,
                severity=AuditSeverity.INFO if i < 3 else AuditSeverity.HIGH,
                agent_id="agent-A" if i < 3 else "agent-B",
                trace_id="trace-1" if i == 0 else "trace-2",
                summary=f"Event {i}",
            )
            repo.store(rec)

        assert repo.count() == 5
        assert repo.get("rec-0") is not None
        assert repo.get("rec-nonexistent") is None

        # Query by agent
        agent_a = repo.query(agent_id="agent-A")
        assert len(agent_a) == 3

        # Query by record type
        events = repo.query(record_type=AuditRecordType.EVENT)
        assert len(events) == 3

        # Query with limit
        limited = repo.query(limit=2)
        assert len(limited) == 2

        # Apply retention: prune older than 25 days (should prune rec-3 (30d) and rec-4 (40d))
        pruned = repo.apply_retention(max_age_days=25)
        assert pruned == 2
        assert repo.count() == 3

        # Apply volume retention: max 2 records
        pruned_vol = repo.apply_retention(max_records=2)
        assert pruned_vol == 1
        assert repo.count() == 2

    def test_file_repository_query_and_retention(self, tmp_path: Path):
        log_file = tmp_path / "repo_audit.log"
        repo = FileAuditRepository(log_path=str(log_file))
        now = datetime.now(timezone.utc)

        for i in range(6):
            t = now - timedelta(days=i * 5)
            rec = AuditRecord(
                record_id=f"file-rec-{i}",
                timestamp=t,
                record_type=AuditRecordType.EVENT,
                severity=AuditSeverity.INFO,
                agent_id="worker-01",
                session_id="sess-xyz",
                summary=f"Audit item {i}",
            )
            repo.store(rec)

        assert repo.count() == 6
        assert repo.get("file-rec-2") is not None

        # Query with session_id
        res = repo.query(session_id="sess-xyz")
        assert len(res) == 6

        # Prune older than 12 days (items 3, 4, 5 are 15, 20, 25 days old)
        pruned = repo.apply_retention(max_age_days=12)
        assert pruned == 3
        assert repo.count() == 3

        # Volume prune: retain 2
        pruned_vol = repo.apply_retention(max_records=2)
        assert pruned_vol == 1
        assert repo.count() == 2


# ============================================================================
# 5. AuditService Integration Tests
# ============================================================================


class TestAuditService:
    @pytest.fixture
    def audit_service(self):
        mem_sink = MemoryAuditSink()
        mem_repo = MemoryAuditRepository()
        return AuditService(sink=mem_sink, repository=mem_repo)

    def test_audit_event_emission(self, audit_service: AuditService):
        event = CanonicalEvent(
            event_type=EventType.SHELL_COMMAND,
            action=EventAction.EXECUTE,
            target="npm test",
            agent_id="test-agent",
            session_id="sess-100",
            trace_id="tr-100",
        )
        rec = audit_service.log_event(
            summary=f"Event {event.event_type} on {event.target}",
            event_id=event.event_id,
            agent_id=event.agent_id,
            session_id=event.session_id,
            trace_id=event.trace_id,
            details={"target": event.target},
        )
        assert rec.record_type == AuditRecordType.EVENT
        assert rec.agent_id == "test-agent"
        assert rec.session_id == "sess-100"
        assert rec.trace_id == "tr-100"
        assert "npm test" in rec.summary
        assert audit_service.repository.count() == 1

    def test_audit_policy_decision_emission(self, audit_service: AuditService):
        rec = audit_service.log_policy_decision(
            decision_verdict="BLOCK",
            policy_id="block-rm-rf",
            reason="Attempted to delete root directory",
            severity_str="CRITICAL",
            agent_id="rogue-agent",
            action_id="act-block-1",
            matched_rule={"id": "block-rm-rf"},
        )
        assert rec.record_type == AuditRecordType.POLICY_DECISION
        assert rec.severity == AuditSeverity.CRITICAL
        assert "BLOCK" in rec.summary
        assert rec.details["matched_rule"]["id"] == "block-rm-rf"

    def test_audit_semantic_decision_emission(self, audit_service: AuditService):
        rec = audit_service.log_semantic_decision(
            engine_name="laya-v1",
            decision_signal="REVIEW",
            risk_level="HIGH",
            confidence=0.88,
            explanation="high confidence exfiltration pattern",
            agent_id="agent-sem",
        )
        assert rec.record_type == AuditRecordType.SEMANTIC_DECISION
        assert rec.severity == AuditSeverity.HIGH
        assert "0.88" in rec.summary

    def test_audit_behavioral_and_sprt(self, audit_service: AuditService):
        rec_beh = audit_service.log_behavioral_decision(
            from_state="SHELL_SAFE",
            to_state="SHELL_NETWORK",
            transition_prob=0.002,
            is_anomaly=True,
            agent_id="agent-markov",
        )
        assert rec_beh.record_type == AuditRecordType.BEHAVIORAL_DECISION
        assert rec_beh.severity == AuditSeverity.HIGH

        rec_sprt = audit_service.log_sprt_state_change(
            status="REJECT_H0",
            log_likelihood_ratio=3.8,
            observation_count=12,
            is_drift=True,
            agent_id="agent-sprt",
        )
        assert rec_sprt.record_type == AuditRecordType.SPRT_STATE_CHANGE
        assert rec_sprt.severity == AuditSeverity.CRITICAL

    def test_audit_approval_workflow(self, audit_service: AuditService):
        rec_req = audit_service.log_approval_request(
            request_id="req-999",
            reason="High risk deploy",
            risk="CRITICAL",
            expiration_iso=datetime.now(timezone.utc).isoformat(),
            action_type="shell",
            target="production-cluster",
            agent_id="agent-appr",
        )
        assert rec_req.record_type == AuditRecordType.APPROVAL_REQUEST
        assert rec_req.severity == AuditSeverity.HIGH

        rec_dec = audit_service.log_approval_decision(
            request_id="req-999",
            verdict="APPROVE",
            decided_by="admin-user",
            reason="Signed off for release",
            agent_id="agent-appr",
        )
        assert rec_dec.record_type == AuditRecordType.APPROVAL_DECISION
        assert "APPROVE" in rec_dec.summary
        assert rec_dec.details["decided_by"] == "admin-user"

    def test_audit_execution_and_error(self, audit_service: AuditService):
        rec_exec = audit_service.log_execution_result(
            action_id="act-ok",
            success=True,
            output="exit 0",
            duration_ms=45.2,
            agent_id="exec-agent",
        )
        assert rec_exec.record_type == AuditRecordType.EXECUTION_RESULT
        assert rec_exec.severity == AuditSeverity.INFO

        rec_err = audit_service.log_error(
            error_type="PermissionDenied",
            error_message="Access to AWS credentials denied by policy",
            agent_id="exec-agent",
        )
        assert rec_err.record_type == AuditRecordType.ERROR
        assert rec_err.severity == AuditSeverity.CRITICAL


# ============================================================================
# 6. Interception Integration with AuditService
# ============================================================================


class TestInterceptionAuditIntegration:
    def test_interceptor_records_audit_on_allow(self):
        policy = load_policy_from_yaml(Path("examples/policies/default.yaml"))
        evaluator = PolicyEvaluator(policy_set=policy)
        mem_sink = MemoryAuditSink()
        mem_repo = MemoryAuditRepository()
        audit_service = AuditService(sink=mem_sink, repository=mem_repo)

        interceptor = RuntimeActionInterceptor(
            policy_evaluator=evaluator,
            mode=InterceptionMode.ENFORCE,
            audit_service=audit_service,
        )

        action = Action.shell(
            command="git status",
            agent_id="cli-agent",
            session_id="sess-run-1",
        )
        dec, result = interceptor.intercept(action)
        assert dec.status == PolicyDecisionType.ALLOW.value
        assert result.success is True

        # Check audit records emitted
        records = mem_repo.query(agent_id="cli-agent")
        types = [r.record_type for r in records]
        assert AuditRecordType.EVENT in types
        assert AuditRecordType.POLICY_DECISION in types
        assert AuditRecordType.EXECUTION_RESULT in types

    def test_interceptor_records_audit_on_block(self):
        policy = load_policy_from_yaml(Path("examples/policies/default.yaml"))
        evaluator = PolicyEvaluator(policy_set=policy)
        mem_sink = MemoryAuditSink()
        mem_repo = MemoryAuditRepository()
        audit_service = AuditService(sink=mem_sink, repository=mem_repo)

        interceptor = RuntimeActionInterceptor(
            policy_evaluator=evaluator,
            mode=InterceptionMode.ENFORCE,
            audit_service=audit_service,
        )

        action = Action.shell(
            command="rm -rf /",
            agent_id="attacker-agent",
            session_id="sess-block-1",
        )

        with pytest.raises(ExecutionBlockedError):
            interceptor.intercept(action)

        records = mem_repo.query(agent_id="attacker-agent")
        types = [r.record_type for r in records]
        assert AuditRecordType.EVENT in types
        assert AuditRecordType.POLICY_DECISION in types
        pd_rec = [r for r in records if r.record_type == AuditRecordType.POLICY_DECISION][0]
        assert pd_rec.severity == AuditSeverity.CRITICAL
        assert "BLOCK" in pd_rec.summary


# ============================================================================
# 7. CLI Audit Commands Tests
# ============================================================================


class TestAuditCLI:
    @pytest.fixture
    def cli_runner(self) -> CliRunner:
        return CliRunner(env={"COLUMNS": "250"})

    @pytest.fixture
    def populated_store(self, tmp_path: Path) -> Path:
        log_file = tmp_path / "cli_audit.ndjson"
        sink = FileAuditSink(file_path=str(log_file))
        now = datetime.now(timezone.utc)

        records = [
            AuditRecord(
                record_id="00000000-0000-0000-0000-000000000001",
                timestamp=now - timedelta(days=2),
                record_type=AuditRecordType.EVENT,
                severity=AuditSeverity.INFO,
                agent_id="agent-smith",
                trace_id="tr-1111",
                summary="Agent started execution",
                details={"cmd": "python run.py"},
            ),
            AuditRecord(
                record_id="00000000-0000-0000-0000-000000000002",
                timestamp=now - timedelta(days=1),
                record_type=AuditRecordType.POLICY_DECISION,
                severity=AuditSeverity.HIGH,
                agent_id="agent-smith",
                trace_id="tr-1111",
                summary="Policy blocked dangerous command",
                details={"blocked": True, "token": "ghp_" + "000000000000000000000000000000000000"},
            ),
            AuditRecord(
                record_id="00000000-0000-0000-0000-000000000003",
                timestamp=now,
                record_type=AuditRecordType.ERROR,
                severity=AuditSeverity.CRITICAL,
                agent_id="agent-jones",
                trace_id="tr-2222",
                summary="Execution halted due to policy violation",
                details={"error": "BlockedAction"},
            ),
        ]
        for r in records:
            sink.emit(r)
        return log_file

    def test_audit_list_empty(self, cli_runner: CliRunner, tmp_path: Path):
        empty_log = tmp_path / "empty.log"
        res = cli_runner.invoke(cli_app, ["audit", "list", "--store", str(empty_log)])
        assert res.exit_code == 0
        assert "No audit records found" in res.output

    def test_audit_list_all(self, cli_runner: CliRunner, populated_store: Path):
        res = cli_runner.invoke(cli_app, ["audit", "list", "--store", str(populated_store)])
        assert res.exit_code == 0
        assert "agent-smith" in res.output
        assert "agent-jones" in res.output
        assert "EVENT" in res.output
        assert "POLICY_DECISION" in res.output
        assert "ERROR" in res.output

    def test_audit_list_filtered(self, cli_runner: CliRunner, populated_store: Path):
        # Filter by agent
        res = cli_runner.invoke(
            cli_app,
            ["audit", "list", "--store", str(populated_store), "--agent", "agent-jones"],
        )
        assert res.exit_code == 0
        assert "agent-jones" in res.output
        assert "agent-smith" not in res.output

        # Filter by type
        res_type = cli_runner.invoke(
            cli_app,
            ["audit", "list", "--store", str(populated_store), "--type", "ERROR"],
        )
        assert res_type.exit_code == 0
        assert "ERROR" in res_type.output
        assert "EVENT" not in res_type.output

    def test_audit_list_invalid_filter(self, cli_runner: CliRunner, populated_store: Path):
        res = cli_runner.invoke(
            cli_app,
            ["audit", "list", "--store", str(populated_store), "--type", "NONEXISTENT_TYPE"],
        )
        assert res.exit_code == 1
        assert "Invalid record type" in res.output

    def test_audit_show_full_and_prefix(self, cli_runner: CliRunner, populated_store: Path):
        # Full ID
        res = cli_runner.invoke(
            cli_app,
            ["audit", "show", "00000000-0000-0000-0000-000000000001", "--store", str(populated_store)],
        )
        assert res.exit_code == 0
        assert "00000000-0000-0000-0000-000000000001" in res.output
        assert "Agent started execution" in res.output
        assert "Correlation Context:" in res.output

        # Prefix match
        res_prefix = cli_runner.invoke(
            cli_app,
            ["audit", "show", "00000000-0000-0000-0000-000000000003", "--store", str(populated_store)],
        )
        assert res_prefix.exit_code == 0
        assert "agent-jones" in res_prefix.output

    def test_audit_show_not_found(self, cli_runner: CliRunner, populated_store: Path):
        res = cli_runner.invoke(
            cli_app,
            ["audit", "show", "ffffffff-ffff-ffff-ffff-ffffffffffff", "--store", str(populated_store)],
        )
        assert res.exit_code == 1
        assert "not found" in res.output

    def test_audit_prune_command(self, cli_runner: CliRunner, populated_store: Path):
        # Retain only 1 record
        res = cli_runner.invoke(
            cli_app,
            ["audit", "prune", "--max-records", "1", "--store", str(populated_store)],
        )
        assert res.exit_code == 0
        assert "pruned 2 record(s)" in res.output

        # Verify listing shows only 1 record remaining
        res_list = cli_runner.invoke(cli_app, ["audit", "list", "--store", str(populated_store)])
        assert res_list.exit_code == 0
        assert "1 shown" in res_list.output
