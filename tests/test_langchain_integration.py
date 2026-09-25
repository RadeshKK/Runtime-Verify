"""
Tests for LangChain & LangGraph Integration in RuntimeVerify (Phase 9).
Verifies RuntimeVerifyCallbackHandler, guard_langchain_tool,
fail-closed enforcement, and audit integration conforming to LangChain's public contract.
"""

from pathlib import Path
import uuid
import pytest

from runtimeverify.audit import MemoryAuditRepository, MemoryAuditSink
from runtimeverify.interception.exceptions import ExecutionBlockedError
from runtimeverify.interception.models import InterceptionMode
from runtimeverify.integrations.langchain import (
    RuntimeVerifyCallbackHandler,
    guard_langchain_tool,
)
from runtimeverify.policy.loader import load_policy_from_yaml
from runtimeverify.sdk import RuntimeVerifyClient, set_default_client


@pytest.fixture(autouse=True)
def reset_global_sdk_client():
    set_default_client(None)
    yield
    set_default_client(None)


@pytest.fixture
def sdk_client():
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


class TestRuntimeVerifyCallbackHandler:
    def test_handler_initialization(self, sdk_client: RuntimeVerifyClient):
        with sdk_client.session(agent_id="test-agent") as session:
            handler = RuntimeVerifyCallbackHandler(session=session)
            assert handler.session == session
            assert handler.raise_error is True
            assert handler.run_inline is True

    def test_tool_start_allowed_action(self, sdk_client: RuntimeVerifyClient):
        with sdk_client.session(agent_id="test-agent") as session:
            handler = RuntimeVerifyCallbackHandler(session=session)
            run_id = uuid.uuid4()

            # Allowed tool (safe shell or git status)
            handler.on_tool_start(
                serialized={"name": "terminal"},
                input_str='{"command": "git status"}',
                run_id=run_id,
            )

            # Completing tool execution
            handler.on_tool_end(output="On branch main\nnothing to commit", run_id=run_id)

            # Audit record should capture the execution
            records = sdk_client.audit_repository.query(session_id=session.session_id)
            summaries = [r.summary for r in records]
            assert any("executed: SUCCESS" in s for s in summaries)

    def test_tool_start_blocked_action_raises(self, sdk_client: RuntimeVerifyClient):
        with sdk_client.session(agent_id="test-agent") as session:
            handler = RuntimeVerifyCallbackHandler(session=session)
            run_id = uuid.uuid4()

            # Blocked tool (rm -rf /)
            with pytest.raises(ExecutionBlockedError) as exc_info:
                handler.on_tool_start(
                    serialized={"name": "bash"},
                    input_str='{"command": "rm -rf /"}',
                    run_id=run_id,
                )
            assert exc_info.value.policy_id == "block-destructive-rm"

    def test_tool_start_blocked_ssh_key_access(self, sdk_client: RuntimeVerifyClient):
        with sdk_client.session(agent_id="test-agent") as session:
            handler = RuntimeVerifyCallbackHandler(session=session)
            run_id = uuid.uuid4()

            # Blocked tool (accessing ~/.ssh/id_rsa)
            with pytest.raises(ExecutionBlockedError) as exc_info:
                handler.on_tool_start(
                    serialized={"name": "file_reader"},
                    input_str='{"path": "~/.ssh/id_rsa"}',
                    run_id=run_id,
                )
            assert exc_info.value.policy_id == "deny-ssh-keys"

    def test_observe_mode_does_not_halt_langchain(self):
        policy = load_policy_from_yaml(Path("examples/policies/default.yaml"))
        repo = MemoryAuditRepository()
        client = RuntimeVerifyClient(
            policy_set=policy,
            audit_repository=repo,
            in_memory_audit=True,
            mode=InterceptionMode.OBSERVE,
        )

        with client.session(agent_id="observe-agent") as session:
            handler = RuntimeVerifyCallbackHandler(session=session)
            run_id = uuid.uuid4()

            # In observe mode, should NOT raise even on destructive command
            handler.on_tool_start(
                serialized={"name": "bash"},
                input_str='{"command": "rm -rf /"}',
                run_id=run_id,
            )
            handler.on_tool_end(output="simulated output", run_id=run_id)

    def test_tool_error_audit_logging(self, sdk_client: RuntimeVerifyClient):
        with sdk_client.session(agent_id="test-agent") as session:
            handler = RuntimeVerifyCallbackHandler(session=session)
            run_id = uuid.uuid4()

            handler.on_tool_start(
                serialized={"name": "shell"},
                input_str='{"command": "python -c 1/0"}',
                run_id=run_id,
            )

            # Error occurred during tool run
            handler.on_tool_error(
                ZeroDivisionError("division by zero"),
                run_id=run_id,
            )

            records = sdk_client.audit_repository.query(session_id=session.session_id)
            summaries = [r.summary for r in records]
            assert any("division by zero" in s for s in summaries)

    def test_agent_action_and_llm_lifecycle(self, sdk_client: RuntimeVerifyClient):
        with sdk_client.session(agent_id="test-agent") as session:
            handler = RuntimeVerifyCallbackHandler(session=session)
            run_id = uuid.uuid4()

            # LLM Start
            handler.on_llm_start(
                serialized={"name": "gpt-4"},
                prompts=["Summarize this repo"],
                run_id=run_id,
            )

            # Agent Action Decision
            class MockAgentAction:
                tool = "terminal"
                tool_input = {"command": "git status"}
                log = "Thought: I need to check git status\nAction: terminal"

            handler.on_agent_action(MockAgentAction(), run_id=run_id)

            # LLM End
            handler.on_llm_end(response={"text": "All clear"}, run_id=run_id)

            records = sdk_client.audit_repository.query(session_id=session.session_id)
            summaries = [r.summary for r in records]
            assert any("LLM request to gpt-4" in s for s in summaries)
            assert any("Agent action decided: terminal" in s for s in summaries)
            assert any("LLM response received" in s for s in summaries)


class TestGuardLangChainTool:
    def test_guard_custom_tool_run_allowed(self, sdk_client: RuntimeVerifyClient):
        class MockSafeTool:
            name = "git_tool"

            def run(self, command: str) -> str:
                return f"executed: {command}"

        with sdk_client.session(agent_id="test-agent") as session:
            tool = MockSafeTool()
            guarded = guard_langchain_tool(tool, session=session)

            res = guarded.run(command="git status")
            assert res == "executed: git status"

    def test_guard_custom_tool_run_blocked(self, sdk_client: RuntimeVerifyClient):
        class MockShellTool:
            name = "shell"

            def _run(self, command: str) -> str:
                return f"executed: {command}"

        with sdk_client.session(agent_id="test-agent") as session:
            tool = MockShellTool()
            guarded = guard_langchain_tool(tool, session=session)

            with pytest.raises(ExecutionBlockedError) as exc_info:
                guarded._run(command="rm -rf /")
            assert exc_info.value.policy_id == "block-destructive-rm"
