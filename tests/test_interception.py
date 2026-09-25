from pathlib import Path
import pytest
from typer.testing import CliRunner

from runtimeverify.cli import app
from runtimeverify.events.canonical import (
    FilesystemDeleteEvent,
    FilesystemReadEvent,
    FilesystemWriteEvent,
    GitOperationEvent,
    NetworkRequestEvent,
    ProcessCreationEvent,
    ShellCommandEvent,
)
from runtimeverify.interception import (
    Action,
    ActionType,
    AuditLogEntry,
    ExecutionBlockedError,
    ExecutionReviewRequiredError,
    InterceptionMode,
    RuntimeActionInterceptor,
    SafeActionExecutor,
    SecurityFailClosedError,
)
from runtimeverify.markov.model import MarkovModel
from runtimeverify.policy.evaluator import PolicyEvaluator
from runtimeverify.policy.loader import load_policy_from_yaml
from runtimeverify.sprt import Hypothesis, SPRTDecision, SPRTEngine
from runtimeverify.state.adapter import MarkovStateAdapter
from runtimeverify.verification import VerificationResult


class TestActionModel:
    """Verifies Action factories and translation into CanonicalEvents."""

    def test_shell_action_and_event_conversion(self):
        act = Action.shell(
            command="ls -la /tmp",
            session_id="sess-01",
            agent_id="agent-01",
            working_directory="/tmp",
        )
        assert act.action_type == ActionType.SHELL
        assert act.target == "ls -la /tmp"
        assert act.agent_id == "agent-01"
        assert act.session_id == "sess-01"

        ev = act.to_canonical_event()
        assert isinstance(ev, ShellCommandEvent)
        assert ev.command == "ls -la /tmp"
        assert ev.target == "ls"
        assert ev.agent_id == "agent-01"
        assert ev.session_id == "sess-01"

    def test_filesystem_actions_and_event_conversion(self):
        # Read
        act_read = Action.filesystem(
            operation="read",
            path="/etc/hosts",
            session_id="s1",
            agent_id="a1",
        )
        ev_read = act_read.to_canonical_event()
        assert isinstance(ev_read, FilesystemReadEvent)
        assert ev_read.path == "/etc/hosts"

        # Write
        act_write = Action.filesystem(
            operation="write",
            path="/app/log.txt",
            content="test log",
            session_id="s1",
            agent_id="a1",
        )
        ev_write = act_write.to_canonical_event()
        assert isinstance(ev_write, FilesystemWriteEvent)
        assert ev_write.path == "/app/log.txt"
        assert ev_write.bytes_written == len("test log".encode("utf-8"))

        # Delete
        act_del = Action.filesystem(
            operation="delete",
            path="/tmp/cache.bin",
            session_id="s1",
            agent_id="a1",
        )
        ev_del = act_del.to_canonical_event()
        assert isinstance(ev_del, FilesystemDeleteEvent)
        assert ev_del.path == "/tmp/cache.bin"

    def test_network_action_and_event_conversion(self):
        act = Action.network(
            url="https://api.github.com/repos",
            method="GET",
            session_id="s1",
            agent_id="a1",
        )
        ev = act.to_canonical_event()
        assert isinstance(ev, NetworkRequestEvent)
        assert ev.url == "https://api.github.com/repos"
        assert ev.method == "GET"

    def test_process_action_and_event_conversion(self):
        act = Action.process(
            command_line="python worker.py --port 8000",
            session_id="s1",
            agent_id="a1",
            pid=4321,
        )
        ev = act.to_canonical_event()
        assert isinstance(ev, ProcessCreationEvent)
        assert ev.command_line == "python worker.py --port 8000"
        assert ev.pid == 4321

    def test_git_action_and_event_conversion(self):
        act = Action.git(
            operation="push",
            branch="main",
            session_id="s1",
            agent_id="a1",
        )
        ev = act.to_canonical_event()
        assert isinstance(ev, GitOperationEvent)
        assert ev.operation == "push"
        assert ev.branch == "main"


class TestSafeActionExecutor:
    """Verifies safe execution behaviors, handler registration, and error wrapping."""

    def test_dry_run_execution(self):
        executor = SafeActionExecutor(dry_run=True)
        act = Action.shell(command="rm -rf /", session_id="s1", agent_id="a1")
        res = executor.execute(act)
        assert res.success is True
        assert res.output["status"] == "simulated_success"
        assert res.metadata["dry_run"] is True

    def test_custom_handler_dispatch(self):
        executor = SafeActionExecutor(dry_run=False)

        def mock_fs_handler(action: Action):
            return f"Mock read {action.target}"

        executor.register_handler(ActionType.FILESYSTEM, mock_fs_handler)
        act = Action.filesystem(operation="read", path="/data/file.csv", session_id="s1", agent_id="a1")
        res = executor.execute(act)
        assert res.success is True
        assert res.output == "Mock read /data/file.csv"

    def test_execution_failure_wrapped(self):
        executor = SafeActionExecutor(dry_run=False)

        def faulty_handler(action: Action):
            raise PermissionError("Access denied to socket")

        executor.register_handler(ActionType.NETWORK, faulty_handler)
        act = Action.network(url="https://bad.com", session_id="s1", agent_id="a1")

        with pytest.raises(Exception) as exc_info:
            executor.execute(act)
        assert "Access denied to socket" in str(exc_info.value)


class TestRuntimeActionInterceptor:
    """Verifies observe mode, enforce mode, policy evaluation, and audit logging."""

    @pytest.fixture(autouse=True)
    def setup_interceptor(self):
        policy_set = load_policy_from_yaml(Path("examples/policies/default.yaml"))
        self.evaluator = PolicyEvaluator(policy_set=policy_set)
        self.enforce_interceptor = RuntimeActionInterceptor(
            mode=InterceptionMode.ENFORCE,
            policy_evaluator=self.evaluator,
        )
        self.observe_interceptor = RuntimeActionInterceptor(
            mode=InterceptionMode.OBSERVE,
            policy_evaluator=self.evaluator,
        )

    def test_observe_mode_permits_blocked_actions(self):
        # In OBSERVE mode, even a critical rm -rf action is permitted and audited
        act = Action.shell(command="rm -rf /", session_id="s1", agent_id="a1")
        decision, result = self.observe_interceptor.intercept(act)

        assert decision.status == "BLOCK"
        assert decision.execution_permitted is True
        assert decision.effective_action == "EXECUTE"
        assert "[OBSERVE MODE]" in decision.reason
        assert result is not None
        assert result.success is True

        # Audit log verified
        assert len(self.observe_interceptor.audit_log) == 1
        audit_entry = self.observe_interceptor.audit_log[0]
        assert audit_entry.decision.status == "BLOCK"
        assert audit_entry.result is not None

    def test_enforce_mode_blocks_destructive_shell(self):
        act = Action.shell(command="rm -rf /", session_id="s1", agent_id="a1")
        with pytest.raises(ExecutionBlockedError) as exc_info:
            self.enforce_interceptor.intercept(act)

        assert exc_info.value.policy_id == "block-destructive-rm"
        assert exc_info.value.severity == "CRITICAL"

        # Audit entry recorded even when blocked
        assert len(self.enforce_interceptor.audit_log) == 1
        entry = self.enforce_interceptor.audit_log[0]
        assert entry.decision.status == "BLOCK"
        assert entry.result is None

    def test_enforce_mode_blocks_ssh_keys(self):
        act = Action.filesystem(operation="read", path="/root/.ssh/id_rsa", session_id="s1", agent_id="a1")
        with pytest.raises(ExecutionBlockedError) as exc_info:
            self.enforce_interceptor.intercept(act)
        assert exc_info.value.policy_id == "deny-ssh-keys"

    def test_enforce_mode_requires_review_on_git_push(self):
        act = Action.git(operation="push", branch="main", session_id="s1", agent_id="a1")
        with pytest.raises(ExecutionReviewRequiredError) as exc_info:
            self.enforce_interceptor.intercept(act)
        assert exc_info.value.policy_id == "review-git-push"

    def test_enforce_mode_allows_safe_actions(self):
        act = Action.shell(command="git status", session_id="s1", agent_id="a1")
        decision, result = self.enforce_interceptor.intercept(act)
        assert decision.status == "ALLOW"
        assert decision.execution_permitted is True
        assert result is not None
        assert result.success is True

    def test_fail_closed_on_evaluator_error(self):
        class BrokenEvaluator:
            def evaluate(self, event):
                raise RuntimeError("Policy database connection failed")

        interceptor = RuntimeActionInterceptor(
            mode=InterceptionMode.ENFORCE,
            policy_evaluator=BrokenEvaluator(),  # type: ignore
            fail_closed=True,
        )
        act = Action.shell(command="ls -la", session_id="s1", agent_id="a1")

        with pytest.raises(SecurityFailClosedError) as exc_info:
            interceptor.intercept(act)
        assert "failed closed" in str(exc_info.value)

    def test_behavioral_adapter_integration(self):
        adapter = MarkovStateAdapter(markov_model=MarkovModel(smoothing=0.01))
        interceptor = RuntimeActionInterceptor(
            mode=InterceptionMode.ENFORCE,
            policy_evaluator=self.evaluator,
            behavioral_adapter=adapter,
        )

        act1 = Action.shell(command="pytest", session_id="sess-markov", agent_id="a1")
        decision1, _ = interceptor.intercept(act1)
        assert decision1.behavioral_score is not None

        act2 = Action.shell(command="pytest", session_id="sess-markov", agent_id="a1")
        decision2, _ = interceptor.intercept(act2)
        assert decision2.behavioral_score is not None

    def test_audit_sink_callback(self):
        sink_entries = []

        def my_audit_sink(entry: AuditLogEntry):
            sink_entries.append(entry)

        interceptor = RuntimeActionInterceptor(
            mode=InterceptionMode.OBSERVE,
            policy_evaluator=self.evaluator,
            audit_sink=my_audit_sink,
        )
        act = Action.shell(command="git status", session_id="s1", agent_id="a1")
        interceptor.intercept(act)

        assert len(sink_entries) == 1
        assert sink_entries[0].action.target == "git status"

    def test_verification_result_attachment_in_interception(self):
        act = Action.shell(command="git status", session_id="s-verify", agent_id="a-verify")
        decision, result = self.enforce_interceptor.intercept(act)

        assert decision.verification_result is not None
        v_res: VerificationResult = decision.verification_result
        assert v_res.decision == "ALLOW"
        assert v_res.risk_level == "LOW"
        assert v_res.confidence >= 0.90
        assert v_res.explanation.what_happened != ""
        assert v_res.explanation.action_taken == "EXECUTE"
        assert len(v_res.policy_matches) >= 1

    def test_interceptor_sprt_sequential_drift_escalation(self):
        class MockDriftSPRTEngine(SPRTEngine):
            def observe_sprt(self, state):
                return SPRTDecision(
                    status="ACCEPT_H1",
                    log_likelihood_ratio=3.45,
                    observation_count=10,
                    lower_threshold=-2.944,
                    upper_threshold=2.944,
                )

        adapter = MarkovStateAdapter(markov_model=MarkovModel())
        mock_sprt = MockDriftSPRTEngine(markov_model=MarkovModel(), hypothesis=Hypothesis(vocabulary_size=5))

        interceptor = RuntimeActionInterceptor(
            mode=InterceptionMode.ENFORCE,
            policy_evaluator=self.evaluator,
            behavioral_adapter=adapter,
            sprt_engine=mock_sprt,
        )

        act = Action.shell(command="git status", session_id="s-drift", agent_id="a-drift")
        with pytest.raises(ExecutionReviewRequiredError) as exc_info:
            interceptor.intercept(act)

        assert "SPRT DRIFT DETECTED" in exc_info.value.reason
        audit = interceptor.audit_log[-1]
        assert audit.decision.status == "REVIEW"
        assert audit.decision.verification_result.explanation.behavioral_deviation is True


class TestInterceptionCLI:
    """Verifies CLI commands: check, monitor, and policy validate."""

    def setup_method(self):
        self.runner = CliRunner()

    def test_cli_policy_validate(self):
        result = self.runner.invoke(app, ["policy", "validate", "examples/policies/default.yaml"])
        assert result.exit_code == 0
        assert "Policy Set: default-security-policy" in result.output
        assert "Policy file is valid" in result.output

    def test_cli_check_allow(self):
        result = self.runner.invoke(
            app,
            ["check", "--type", "shell", "--target", "git status", "--policy", "examples/policies/default.yaml"],
        )
        assert result.exit_code == 0
        assert "Decision: ALLOW" in result.output
        assert "allow-git-status" in result.output

    def test_cli_check_block(self):
        result = self.runner.invoke(
            app,
            ["check", "--type", "shell", "--target", "rm -rf /", "--policy", "examples/policies/default.yaml"],
        )
        assert result.exit_code == 2
        assert "Decision: BLOCK" in result.output
        assert "block-destructive-rm" in result.output

    def test_cli_check_review(self):
        result = self.runner.invoke(
            app,
            ["check", "--type", "git", "--target", "main", "--policy", "examples/policies/default.yaml"],
        )
        assert result.exit_code == 3
        assert "Decision: REVIEW REQUIRED" in result.output
        assert "review-git-push" in result.output

    def test_cli_monitor(self):
        result = self.runner.invoke(app, ["monitor", "--mode", "observe"])
        assert result.exit_code == 0
        assert "RuntimeVerify Interception Monitor" in result.output
