"""
Unit and integration tests for Phase 7: Human Approval Workflow.
Verifies approval, denial, expiration, duplicate approval replay prevention,
unknown requests, unauthorized approver rejection, interceptor pause/resume,
CLI commands, and REST API endpoints.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from starlette.testclient import TestClient
from typer.testing import CliRunner

from runtimeverify.api.app import app as fastapi_app
from runtimeverify.approvals import (
    APIApprovalProvider,
    ApprovalDecision,
    ApprovalDecisionType,
    ApprovalExpiredError,
    ApprovalProvider,
    ApprovalRequest,
    ApprovalStatus,
    ApprovalStore,
    ApprovalTimeoutBehavior,
    CLIApprovalProvider,
    DuplicateApprovalError,
    UnauthorizedApproverError,
    UnknownApprovalRequestError,
    set_default_approval_store,
)
from runtimeverify.cli import app as cli_app
from runtimeverify.interception import (
    Action,
    ExecutionBlockedError,
    InterceptionMode,
    RuntimeActionInterceptor,
)
from runtimeverify.policy.evaluator import PolicyEvaluator
from runtimeverify.policy.loader import load_policy_from_yaml


@pytest.fixture
def fresh_store(tmp_path: Path) -> ApprovalStore:
    """Provides an isolated ApprovalStore with a temporary persistence path."""
    store_file = str(tmp_path / "approvals_test.json")
    store = ApprovalStore(persistence_path=store_file)
    set_default_approval_store(store)
    return store


@pytest.fixture
def sample_request() -> ApprovalRequest:
    return ApprovalRequest(
        action_id="act-1234",
        agent_id="test-agent-01",
        session_id="session-alpha",
        action={"action_type": "git", "target": "origin/main", "operation": "push"},
        risk="HIGH",
        reason="Action requires human review under policy review-git-push",
        expiration=datetime.now(timezone.utc) + timedelta(seconds=60),
        timeout_seconds=60.0,
    )


class TestApprovalStoreCore:
    """Verifies core storage, state transitions, replay prevention, and expiration enforcement."""

    def test_approval(self, fresh_store: ApprovalStore, sample_request: ApprovalRequest):
        fresh_store.save_request(sample_request)
        assert sample_request.status == ApprovalStatus.PENDING

        decision = ApprovalDecision(
            request_id=sample_request.request_id,
            decision=ApprovalDecisionType.APPROVE,
            decided_by="admin-user",
            reason="Approved after manual inspection",
        )
        updated = fresh_store.record_decision(sample_request.request_id, decision)

        assert updated.status == ApprovalStatus.APPROVED
        assert updated.decision is not None
        assert updated.decision.decision == ApprovalDecisionType.APPROVE
        assert updated.decision.decided_by == "admin-user"

        # Verify audit log
        audits = fresh_store.get_audit_log(sample_request.request_id)
        assert len(audits) >= 2
        assert any(a.event_type == "REQUEST_CREATED" for a in audits)
        assert any(a.event_type == "DECISION_RECORDED" for a in audits)

    def test_denial(self, fresh_store: ApprovalStore, sample_request: ApprovalRequest):
        fresh_store.save_request(sample_request)

        decision = ApprovalDecision(
            request_id=sample_request.request_id,
            decision=ApprovalDecisionType.DENY,
            decided_by="secops-lead",
            reason="Unapproved target branch push",
        )
        updated = fresh_store.record_decision(sample_request.request_id, decision)

        assert updated.status == ApprovalStatus.DENIED
        assert updated.decision is not None
        assert updated.decision.decision == ApprovalDecisionType.DENY
        assert updated.decision.decided_by == "secops-lead"

    def test_expiration(self, fresh_store: ApprovalStore):
        # Create request that expired 10 seconds ago
        expired_req = ApprovalRequest(
            action_id="act-expired",
            agent_id="agent-01",
            action={"action_type": "shell", "target": "rm test.txt"},
            risk="HIGH",
            reason="Requires approval",
            expiration=datetime.now(timezone.utc) - timedelta(seconds=10),
            timeout_seconds=10.0,
        )
        fresh_store.save_request(expired_req)

        # Confirm store reports it as expired
        assert expired_req.is_expired() is True

        decision = ApprovalDecision(
            request_id=expired_req.request_id,
            decision=ApprovalDecisionType.APPROVE,
            decided_by="late-user",
        )
        with pytest.raises(ApprovalExpiredError) as exc_info:
            fresh_store.record_decision(expired_req.request_id, decision)

        assert expired_req.request_id in str(exc_info.value)
        # Status transitioned to EXPIRED
        peeked = fresh_store.peek_request(expired_req.request_id)
        assert peeked is not None
        assert peeked.status == ApprovalStatus.EXPIRED

    def test_duplicate_approval_replay_prevention(self, fresh_store: ApprovalStore, sample_request: ApprovalRequest):
        fresh_store.save_request(sample_request)

        # First approval succeeds
        decision1 = ApprovalDecision(
            request_id=sample_request.request_id,
            decision=ApprovalDecisionType.APPROVE,
            decided_by="approver-1",
        )
        fresh_store.record_decision(sample_request.request_id, decision1)

        # Second attempt (replay or tamper) must fail
        decision2 = ApprovalDecision(
            request_id=sample_request.request_id,
            decision=ApprovalDecisionType.DENY,
            decided_by="attacker",
        )
        with pytest.raises(DuplicateApprovalError) as exc_info:
            fresh_store.record_decision(sample_request.request_id, decision2)

        assert "already been decided" in str(exc_info.value)
        assert "Replay attack prevented" in str(exc_info.value)

        # State remains unchanged
        req = fresh_store.get_request(sample_request.request_id)
        assert req.status == ApprovalStatus.APPROVED
        assert req.decision.decided_by == "approver-1"

    def test_unknown_request(self, fresh_store: ApprovalStore):
        with pytest.raises(UnknownApprovalRequestError):
            fresh_store.get_request("non-existent-uuid-0000")

        dummy_decision = ApprovalDecision(
            request_id="non-existent-uuid-0000",
            decision=ApprovalDecisionType.APPROVE,
            decided_by="user",
        )
        with pytest.raises(UnknownApprovalRequestError):
            fresh_store.record_decision("non-existent-uuid-0000", dummy_decision)

    def test_unauthorized_approval(self, fresh_store: ApprovalStore, sample_request: ApprovalRequest):
        fresh_store.save_request(sample_request)

        authorized_users = {"alice", "bob", "security-admin"}

        # Unauthorized user
        unauthorized_decision = ApprovalDecision(
            request_id=sample_request.request_id,
            decision=ApprovalDecisionType.APPROVE,
            decided_by="malicious-mallory",
        )
        with pytest.raises(UnauthorizedApproverError) as exc_info:
            fresh_store.record_decision(
                sample_request.request_id,
                unauthorized_decision,
                authorized_approvers=authorized_users,
            )

        assert "malicious-mallory" in str(exc_info.value)
        assert sample_request.status == ApprovalStatus.PENDING

        # Authorized user succeeds
        valid_decision = ApprovalDecision(
            request_id=sample_request.request_id,
            decision=ApprovalDecisionType.APPROVE,
            decided_by="alice",
        )
        updated = fresh_store.record_decision(
            sample_request.request_id,
            valid_decision,
            authorized_approvers=authorized_users,
        )
        assert updated.status == ApprovalStatus.APPROVED


class TestApprovalProviders:
    """Verifies CLIApprovalProvider and APIApprovalProvider behaviors."""

    def test_cli_provider_async_poll_approve(self, fresh_store: ApprovalStore):
        provider = CLIApprovalProvider(
            store=fresh_store,
            interactive=False,
            poll_interval=0.05,
        )

        req = ApprovalRequest(
            action_id="act-cli-01",
            agent_id="agent-01",
            action={"action_type": "git", "target": "origin/main"},
            risk="HIGH",
            reason="review-git-push",
            expiration=datetime.now(timezone.utc) + timedelta(seconds=2),
            timeout_seconds=2.0,
        )

        # Simulate human approving via another thread or background callback
        import threading

        def background_approve():
            import time

            time.sleep(0.1)
            dec = ApprovalDecision(
                request_id=req.request_id,
                decision=ApprovalDecisionType.APPROVE,
                decided_by="cli-user",
                reason="Looks good",
            )
            fresh_store.record_decision(req.request_id, dec)

        threading.Thread(target=background_approve, daemon=True).start()

        decision = provider.request_approval(req)
        assert decision.decision == ApprovalDecisionType.APPROVE
        assert decision.decided_by == "cli-user"

    def test_cli_provider_timeout_fail_closed(self, fresh_store: ApprovalStore):
        provider = CLIApprovalProvider(
            store=fresh_store,
            interactive=False,
            poll_interval=0.05,
        )

        req = ApprovalRequest(
            action_id="act-cli-timeout",
            agent_id="agent-01",
            action={"action_type": "git", "target": "origin/main"},
            risk="HIGH",
            reason="review-git-push",
            expiration=datetime.now(timezone.utc) + timedelta(seconds=0.2),
            timeout_seconds=0.2,
            timeout_behavior=ApprovalTimeoutBehavior.DENY,
        )

        decision = provider.request_approval(req)
        assert decision.decision == ApprovalDecisionType.DENY
        assert "timed out" in decision.reason
        assert decision.decided_by == "system:timeout"

    def test_api_provider_webhook_and_approve(self, fresh_store: ApprovalStore):
        webhook_called_with = []

        def mock_webhook(request: ApprovalRequest):
            webhook_called_with.append(request.request_id)
            # Immediately resolve decision
            dec = ApprovalDecision(
                request_id=request.request_id,
                decision=ApprovalDecisionType.APPROVE,
                decided_by="webhook-service",
            )
            fresh_store.record_decision(request.request_id, dec)

        provider = APIApprovalProvider(
            store=fresh_store,
            webhook_fn=mock_webhook,
            poll_interval=0.05,
        )

        req = ApprovalRequest(
            action_id="act-api-01",
            agent_id="agent-api",
            action={"action_type": "git", "target": "main"},
            risk="HIGH",
            reason="Push to main branch",
            expiration=datetime.now(timezone.utc) + timedelta(seconds=2.0),
            timeout_seconds=2.0,
        )

        decision = provider.request_approval(req)
        assert decision.decision == ApprovalDecisionType.APPROVE
        assert decision.decided_by == "webhook-service"
        assert len(webhook_called_with) == 1
        assert webhook_called_with[0] == req.request_id


class TestInterceptorApprovalIntegration:
    """Verifies RuntimeActionInterceptor with active ApprovalProvider."""

    @pytest.fixture(autouse=True)
    def setup_interceptor(self, fresh_store: ApprovalStore):
        self.policy_evaluator = PolicyEvaluator(load_policy_from_yaml("examples/policies/default.yaml"))
        self.store = fresh_store

    def test_review_action_paused_and_approved(self):
        class InstantApproveProvider(ApprovalProvider):
            def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
                dec = ApprovalDecision(
                    request_id=request.request_id,
                    decision=ApprovalDecisionType.APPROVE,
                    decided_by="lead-architect",
                    reason="Authorized for deployment",
                )
                self.store.save_request(request)
                self.store.record_decision(request.request_id, dec)
                return dec

        provider = InstantApproveProvider(store=self.store)
        interceptor = RuntimeActionInterceptor(
            mode=InterceptionMode.ENFORCE,
            policy_evaluator=self.policy_evaluator,
            approval_provider=provider,
        )

        # Action: git push (triggers review-git-push)
        action = Action.git(operation="push", branch="main", session_id="s1", agent_id="a1")
        decision, result = interceptor.intercept(action)

        assert decision.status == "ALLOW"
        assert decision.execution_permitted is True
        assert decision.effective_action == "EXECUTE"
        assert "[HUMAN APPROVED: lead-architect]" in decision.reason
        assert result is not None
        assert result.success is True

    def test_review_action_paused_and_denied(self):
        class InstantDenyProvider(ApprovalProvider):
            def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
                dec = ApprovalDecision(
                    request_id=request.request_id,
                    decision=ApprovalDecisionType.DENY,
                    decided_by="security-auditor",
                    reason="Unverified changes",
                )
                self.store.save_request(request)
                self.store.record_decision(request.request_id, dec)
                return dec

        provider = InstantDenyProvider(store=self.store)
        interceptor = RuntimeActionInterceptor(
            mode=InterceptionMode.ENFORCE,
            policy_evaluator=self.policy_evaluator,
            approval_provider=provider,
        )

        action = Action.git(operation="push", branch="main", session_id="s1", agent_id="a1")
        with pytest.raises(ExecutionBlockedError) as exc_info:
            interceptor.intercept(action)

        assert exc_info.value.policy_id == "human-approval-denied"
        assert "HUMAN DENIED: security-auditor" in exc_info.value.reason


class TestApprovalCLI:
    """Verifies CLI commands: approvals list, approve, deny, show."""

    def setup_method(self):
        self.runner = CliRunner()

    def test_cli_list_empty(self, fresh_store: ApprovalStore):
        res = self.runner.invoke(cli_app, ["approvals", "list", "--store", fresh_store._persistence_path])
        assert res.exit_code == 0
        assert "No approval requests found." in res.output

    def test_cli_approve_flow(self, fresh_store: ApprovalStore, sample_request: ApprovalRequest):
        fresh_store.save_request(sample_request)

        # List request
        res_list = self.runner.invoke(cli_app, ["approvals", "list", "--store", fresh_store._persistence_path])
        assert res_list.exit_code == 0
        assert sample_request.request_id[:8] in res_list.output
        assert "PENDING" in res_list.output

        # Approve request
        res_approve = self.runner.invoke(
            cli_app,
            [
                "approvals",
                "approve",
                sample_request.request_id,
                "--user",
                "alice-dev",
                "--reason",
                "LGTM",
                "--store",
                fresh_store._persistence_path,
            ],
        )
        assert res_approve.exit_code == 0
        assert "Approval GRANTED" in res_approve.output
        assert "alice-dev" in res_approve.output

        # Verify state in store
        req = fresh_store.get_request(sample_request.request_id)
        assert req.status == ApprovalStatus.APPROVED

        # Duplicate approval attempt fails via CLI (exit code 2)
        res_dup = self.runner.invoke(
            cli_app,
            ["approvals", "approve", sample_request.request_id, "--store", fresh_store._persistence_path],
        )
        assert res_dup.exit_code == 2
        assert "Duplicate Approval Error" in res_dup.output

    def test_cli_deny_flow(self, fresh_store: ApprovalStore, sample_request: ApprovalRequest):
        fresh_store.save_request(sample_request)

        res_deny = self.runner.invoke(
            cli_app,
            [
                "approvals",
                "deny",
                sample_request.request_id,
                "--user",
                "bob-sec",
                "--reason",
                "Dangerous operation",
                "--store",
                fresh_store._persistence_path,
            ],
        )
        assert res_deny.exit_code == 0
        assert "Approval DENIED" in res_deny.output
        assert "bob-sec" in res_deny.output

        req = fresh_store.get_request(sample_request.request_id)
        assert req.status == ApprovalStatus.DENIED


class TestApprovalAPI:
    """Verifies FastAPI REST endpoints for approval requests."""

    @pytest.fixture(autouse=True)
    def setup_api(self, fresh_store: ApprovalStore):
        self.client = TestClient(fastapi_app)
        self.store = fresh_store

    def test_api_list_and_details(self, sample_request: ApprovalRequest):
        self.store.save_request(sample_request)

        # GET /api/v1/approvals
        resp = self.client.get("/api/v1/approvals")
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 1
        assert items[0]["request_id"] == sample_request.request_id

        # GET /api/v1/approvals/{id}
        resp_single = self.client.get(f"/api/v1/approvals/{sample_request.request_id}")
        assert resp_single.status_code == 200
        assert resp_single.json()["status"] == "PENDING"

    def test_api_approve_and_replay_rejection(self, sample_request: ApprovalRequest):
        self.store.save_request(sample_request)

        # POST /api/v1/approvals/{id}/approve
        resp = self.client.post(
            f"/api/v1/approvals/{sample_request.request_id}/approve",
            json={"user": "api-reviewer", "reason": "Verified via dashboard"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "APPROVED"
        assert resp.json()["decision"]["decided_by"] == "api-reviewer"

        # Replay attempt -> 409 Conflict
        resp_dup = self.client.post(
            f"/api/v1/approvals/{sample_request.request_id}/approve",
            json={"user": "api-reviewer", "reason": "Re-approving"},
        )
        assert resp_dup.status_code == 409

    def test_api_audit_trail(self, sample_request: ApprovalRequest):
        self.store.save_request(sample_request)
        self.client.post(
            f"/api/v1/approvals/{sample_request.request_id}/deny",
            json={"user": "api-auditor", "reason": "Rejected"},
        )

        resp_audit = self.client.get(f"/api/v1/approvals/{sample_request.request_id}/audit")
        assert resp_audit.status_code == 200
        audits = resp_audit.json()
        assert len(audits) >= 2
        assert any(a["event_type"] == "REQUEST_CREATED" for a in audits)
        assert any(a["event_type"] == "DECISION_RECORDED" for a in audits)
