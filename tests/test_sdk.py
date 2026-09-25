"""
Unit and integration tests for Phase 9: Agent Integration SDK.
Verifies RuntimeVerifyClient, AgentSession, observe(), check(), authorize(), record(),
session context manager, tool execution wrapping, and in-process lightweight operation.
"""

from pathlib import Path
import pytest

import runtimeverify
from runtimeverify.audit import AuditRecordType, MemoryAuditRepository, MemoryAuditSink
from runtimeverify.events.enums import EventAction, EventType
from runtimeverify.interception import (
    Action,
    ExecutionBlockedError,
    InterceptionDecision,
    InterceptionMode,
)
from runtimeverify.policy.loader import load_policy_from_yaml
from runtimeverify.policy.models import PolicyDecisionType
from runtimeverify.sdk import (
    AgentSession,
    RuntimeVerifyClient,
    set_default_client,
)


@pytest.fixture(autouse=True)
def reset_global_sdk_client():
    """Resets the global SDK client between tests to maintain test isolation."""
    set_default_client(None)
    yield
    set_default_client(None)


# ============================================================================
# 1. RuntimeVerifyClient Initialization & Lightweight Operation
# ============================================================================


class TestRuntimeVerifyClient:
    def test_default_client_initialization(self):
        client = RuntimeVerifyClient(in_memory_audit=True)
        assert client.mode == InterceptionMode.ENFORCE
        assert client.policy_set is not None
        assert client.audit_service is not None

    def test_client_custom_policy_and_mode(self):
        policy = load_policy_from_yaml(Path("examples/policies/default.yaml"))
        client = RuntimeVerifyClient(
            mode=InterceptionMode.OBSERVE,
            policy_set=policy,
            in_memory_audit=True,
            default_agent_id="test-agent",
            environment="staging",
        )
        assert client.mode == InterceptionMode.OBSERVE
        assert client.default_agent_id == "test-agent"
        assert client.environment == "staging"

    def test_client_standalone_no_server_needed(self):
        # Verification runs completely in-process
        client = RuntimeVerifyClient(in_memory_audit=True)
        action = Action.shell(command="git status", session_id="s1", agent_id="a1")
        decision = client.check(action)
        assert isinstance(decision, InterceptionDecision)
        assert decision.status == PolicyDecisionType.ALLOW.value


# ============================================================================
# 2. AgentSession Lifecycle & Correlation
# ============================================================================


class TestAgentSessionLifecycle:
    def test_session_context_manager_and_correlation(self):
        sink = MemoryAuditSink()
        repo = MemoryAuditRepository()
        client = RuntimeVerifyClient(
            audit_sink=sink,
            audit_repository=repo,
            in_memory_audit=True,
        )

        with client.session(
            agent_id="coding-agent-01",
            session_id="custom-sess-99",
            trace_id="custom-tr-99",
            environment="production",
            metadata={"task": "bug_fix"},
        ) as sess:
            assert sess.agent_id == "coding-agent-01"
            assert sess.session_id == "custom-sess-99"
            assert sess.trace_id == "custom-tr-99"
            assert sess.environment == "production"
            assert sess.metadata["task"] == "bug_fix"
            assert sess.is_active is True

        assert sess.is_active is False
        # Audit records captured session start and close
        records = repo.query(session_id="custom-sess-99")
        assert len(records) >= 2
        summaries = [r.summary for r in records]
        assert any("started" in s for s in summaries)
        assert any("closed" in s for s in summaries)

    def test_top_level_runtimeverify_session(self):
        # Conceptual syntax test: with runtimeverify.session(...)
        with runtimeverify.session(agent_id="analyst-agent", in_memory_audit=True) as sess:
            assert isinstance(sess, AgentSession)
            assert sess.agent_id == "analyst-agent"
            assert sess.session_id.startswith("sess-")
            assert sess.trace_id.startswith("tr-")


# ============================================================================
# 3. Core SDK Operations: check(), observe(), authorize(), record()
# ============================================================================


class TestCoreSDKOperations:
    @pytest.fixture
    def test_client(self):
        sink = MemoryAuditSink()
        repo = MemoryAuditRepository()
        policy = load_policy_from_yaml(Path("examples/policies/default.yaml"))
        return RuntimeVerifyClient(
            policy_set=policy,
            audit_sink=sink,
            audit_repository=repo,
            in_memory_audit=True,
            mode=InterceptionMode.ENFORCE,
        )

    def test_check_allowed_and_blocked(self, test_client: RuntimeVerifyClient):
        sess = test_client.session(agent_id="worker")

        # Safe command check
        dec_allow = sess.check({"command": "git status"})
        assert dec_allow.status == PolicyDecisionType.ALLOW.value
        assert dec_allow.execution_permitted is True

        # Destructive command check
        dec_block = sess.check({"command": "rm -rf /"})
        assert dec_block.status == PolicyDecisionType.BLOCK.value
        assert dec_block.execution_permitted is False

    def test_observe_mode_does_not_block(self, test_client: RuntimeVerifyClient):
        sess = test_client.session(agent_id="worker")

        # In observe mode, even rm -rf is not blocked
        executed = []
        dec, res = sess.observe(
            {"command": "rm -rf /"},
            execute_fn=lambda act: executed.append(act.target),
        )
        assert dec.status == PolicyDecisionType.BLOCK.value
        assert dec.execution_permitted is True
        assert len(executed) == 1

    def test_authorize_enforce_blocks(self, test_client: RuntimeVerifyClient):
        sess = test_client.session(agent_id="worker")

        # Safe action succeeds
        res = sess.authorize({"command": "git status"})
        assert res.success is True

        # Blocked action raises ExecutionBlockedError
        with pytest.raises(ExecutionBlockedError) as exc_info:
            sess.authorize({"command": "rm -rf /"})
        assert exc_info.value.policy_id == "block-destructive-rm"

    def test_record_canonical_event(self, test_client: RuntimeVerifyClient):
        sess = test_client.session(agent_id="worker")
        ev = sess.create_event(
            event_type=EventType.SHELL_COMMAND,
            action=EventAction.EXECUTE,
            target="python -m pytest",
            payload={"args": ["-v"]},
        )
        rec = sess.record(ev)
        assert rec.record_type == AuditRecordType.EVENT
        assert rec.agent_id == "worker"
        assert rec.session_id == sess.session_id


# ============================================================================
# 4. Tool Execution Wrapping & session.execute()
# ============================================================================


class TestToolExecutionWrapping:
    @pytest.fixture
    def session_fixture(self):
        sink = MemoryAuditSink()
        repo = MemoryAuditRepository()
        policy = load_policy_from_yaml(Path("examples/policies/default.yaml"))
        client = RuntimeVerifyClient(
            policy_set=policy,
            audit_sink=sink,
            audit_repository=repo,
            in_memory_audit=True,
            mode=InterceptionMode.ENFORCE,
        )
        return client.session(agent_id="coding-agent")

    def test_execute_callable_function(self, session_fixture: AgentSession):
        def read_file(path: str) -> str:
            return f"Contents of {path}"

        # Safe read
        output = session_fixture.execute(read_file, path="README.md")
        assert output == "Contents of README.md"

        # Protected SSH key read is blocked
        with pytest.raises(ExecutionBlockedError):
            session_fixture.execute(read_file, path="~/.ssh/id_rsa")

    def test_execute_dict_tool_call(self, session_fixture: AgentSession):
        # Direct dict
        res_allow = session_fixture.execute({"command": "pwd"})
        assert res_allow.success is True

        with pytest.raises(ExecutionBlockedError):
            session_fixture.execute({"command": "rm -rf /"})

    def test_execute_openai_style_tool_call(self, session_fixture: AgentSession):
        tool_call = {
            "type": "function",
            "function": {
                "name": "run_bash",
                "arguments": '{"command": "git status"}',
            },
        }
        res = session_fixture.execute(tool_call)
        assert res.success is True

        tool_call_blocked = {
            "type": "function",
            "function": {
                "name": "run_bash",
                "arguments": '{"command": "rm -rf /"}',
            },
        }
        with pytest.raises(ExecutionBlockedError):
            session_fixture.execute(tool_call_blocked)

    def test_wrap_tool_decorator(self, session_fixture: AgentSession):
        @session_fixture.wrap_tool
        def run_terminal(command: str) -> str:
            return f"Executed: {command}"

        # Allowed command
        res = run_terminal("git status")
        assert res == "Executed: git status"

        # Blocked command
        with pytest.raises(ExecutionBlockedError):
            run_terminal("rm -rf /")

    def test_wrap_tool_filesystem_decorator(self, session_fixture: AgentSession):
        @session_fixture.wrap_tool(tool_name="read_file")
        def load_doc(path: str) -> str:
            return f"Loaded: {path}"

        assert load_doc("docs/intro.md") == "Loaded: docs/intro.md"

        with pytest.raises(ExecutionBlockedError):
            load_doc("~/.aws/credentials")
