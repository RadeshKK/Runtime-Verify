"""
LangChain and LangGraph Integration for RuntimeVerify (Phase 9).
Provides official, non-invasive callback handlers and tool interceptors
conforming to LangChain's public BaseCallbackHandler and BaseTool interfaces.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from runtimeverify.interception.exceptions import (
    ExecutionBlockedError,
    ExecutionReviewRequiredError,
)
from runtimeverify.interception.models import Action
from runtimeverify.sdk.client import RuntimeVerifyClient
from runtimeverify.sdk.session import AgentSession

logger = logging.getLogger(__name__)

# Dynamically import LangChain BaseCallbackHandler if installed
try:
    from langchain_core.callbacks.base import BaseCallbackHandler
except ImportError:
    try:
        from langchain.callbacks.base import BaseCallbackHandler
    except ImportError:
        # Standalone duck-typed fallback matching LangChain's public callback contract
        class BaseCallbackHandler:  # type: ignore[no-redef]
            """Fallback BaseCallbackHandler matching LangChain's public specification."""

            raise_error: bool = True
            run_inline: bool = True

            def __init__(self) -> None:
                pass


class RuntimeVerifyCallbackHandler(BaseCallbackHandler):
    """
    Standard LangChain Callback Handler integrating RuntimeVerify.
    Subclasses LangChain's BaseCallbackHandler to inspect, gate, and audit tool invocations
    and agent actions in real time.

    Usage with LangChain Agent:
        from runtimeverify.sdk import session
        from runtimeverify.integrations.langchain import RuntimeVerifyCallbackHandler

        with session(agent_id="langchain-analyst") as sess:
            handler = RuntimeVerifyCallbackHandler(session=sess)
            agent_executor.invoke({"input": "..."}, config={"callbacks": [handler]})
    """

    raise_error: bool = True
    run_inline: bool = True

    def __init__(
        self,
        session: Optional[AgentSession] = None,
        client: Optional[RuntimeVerifyClient] = None,
        agent_id: str = "langchain-agent",
        fail_closed: bool = True,
    ):
        super().__init__()
        if session is not None:
            self.session = session
        else:
            cli = client or RuntimeVerifyClient()
            self.session = cli.session(agent_id=agent_id)
        self.fail_closed = fail_closed
        self._run_actions: Dict[str, Action] = {}

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: Any,
        parent_run_id: Optional[Any] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        inputs: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """
        Triggered when a LangChain tool begins execution.
        Evaluates policies and sequential verification models.
        Raises ExecutionBlockedError to halt execution if policy decides BLOCK.
        """
        tool_name = serialized.get("name") or serialized.get("id") or "tool"

        # Parse inputs
        args: Dict[str, Any] = {}
        if isinstance(inputs, dict):
            args = dict(inputs)
        elif isinstance(input_str, str):
            input_str_clean = input_str.strip()
            if input_str_clean.startswith("{") and input_str_clean.endswith("}"):
                try:
                    args = json.loads(input_str_clean)
                except Exception:
                    args = {"input": input_str}
            else:
                args = {"input": input_str}
        elif isinstance(input_str, dict):
            args = dict(input_str)

        tool_call = {
            "name": tool_name,
            "arguments": args,
            "description": serialized.get("description", ""),
        }

        # Map to canonical Action
        action = self.session.map_to_action(tool_call)
        run_key = str(run_id)
        self._run_actions[run_key] = action

        logger.debug(
            "LangChain on_tool_start: tool='%s', action_type='%s', target='%s'",
            tool_name,
            action.action_type.value,
            action.target,
        )

        try:
            # Check authorization; if blocked in enforce mode, raises ExecutionBlockedError
            decision = self.session.check(action)
            if not decision.execution_permitted:
                # Enforce mode block
                if self.session.client.mode.value == "enforce":
                    self.session.authorize(action)
        except (ExecutionBlockedError, ExecutionReviewRequiredError):
            # Re-raise to halt LangChain agent execution
            raise
        except Exception as e:
            if self.fail_closed:
                raise ExecutionBlockedError(
                    action_id=action.action_id,
                    policy_id="langchain-guard-fail-closed",
                    reason=f"RuntimeVerify evaluation error: {e}",
                    severity="CRITICAL",
                ) from e
            logger.warning("RuntimeVerify callback check encountered error: %s", e)

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: Any,
        parent_run_id: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Triggered upon successful completion of a LangChain tool."""
        run_key = str(run_id)
        action = self._run_actions.pop(run_key, None)
        action_id = action.action_id if action else str(run_id)

        if self.session.client.audit_service:
            self.session.client.audit_service.log_execution_result(
                action_id=action_id,
                success=True,
                output=str(output)[:2000],
                agent_id=self.session.agent_id,
                session_id=self.session.session_id,
                trace_id=self.session.trace_id,
                environment=self.session.environment,
            )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: Any,
        parent_run_id: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Triggered when a LangChain tool execution raises an error."""
        run_key = str(run_id)
        action = self._run_actions.pop(run_key, None)
        action_id = action.action_id if action else str(run_id)

        if self.session.client.audit_service:
            self.session.client.audit_service.log_error(
                error_type=type(error).__name__,
                error_message=str(error),
                agent_id=self.session.agent_id,
                session_id=self.session.session_id,
                trace_id=self.session.trace_id,
                action_id=action_id,
                environment=self.session.environment,
            )

    def on_agent_action(
        self,
        action: Any,
        *,
        run_id: Any,
        parent_run_id: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Triggered when a LangChain agent decides an action."""
        tool_name = getattr(action, "tool", None) or "agent_action"
        tool_input = getattr(action, "tool_input", {})
        log_text = getattr(action, "log", "")

        mapped_action = self.session.map_to_action(
            {
                "name": tool_name,
                "arguments": tool_input if isinstance(tool_input, dict) else {"input": tool_input},
                "log": log_text,
            }
        )

        if self.session.client.audit_service:
            self.session.client.audit_service.log_event(
                summary=f"Agent action decided: {tool_name}",
                agent_id=self.session.agent_id,
                session_id=self.session.session_id,
                trace_id=self.session.trace_id,
                action_id=mapped_action.action_id,
                environment=self.session.environment,
                details={"tool": tool_name, "log": log_text},
            )

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: Any,
        parent_run_id: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Triggered before an LLM call starts."""
        model_name = serialized.get("name") or serialized.get("id") or "llm"
        if self.session.client.audit_service:
            self.session.client.audit_service.log_event(
                summary=f"LLM request to {model_name} ({len(prompts)} prompt(s))",
                agent_id=self.session.agent_id,
                session_id=self.session.session_id,
                trace_id=self.session.trace_id,
                environment=self.session.environment,
                details={"model": model_name, "prompts_count": len(prompts)},
            )

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: Any,
        parent_run_id: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Triggered after an LLM call returns."""
        if self.session.client.audit_service:
            self.session.client.audit_service.log_event(
                summary="LLM response received",
                agent_id=self.session.agent_id,
                session_id=self.session.session_id,
                trace_id=self.session.trace_id,
                environment=self.session.environment,
            )


def guard_langchain_tool(tool: Any, session: AgentSession) -> Any:
    """
    Wraps a LangChain BaseTool or custom tool instance with pre-execution runtime verification.
    Guarantees that invoking the tool runs policy evaluation and verification before
    the underlying tool implementation is called.
    """
    orig_run = getattr(tool, "_run", None) or getattr(tool, "run", None)
    if orig_run is None and callable(tool):
        orig_run = tool

    tool_name = getattr(tool, "name", getattr(tool, "__name__", "langchain_tool"))

    def guarded_run(*args: Any, **kwargs: Any) -> Any:
        # Build arguments dict
        tool_args = dict(kwargs)
        if args:
            tool_args["args"] = args

        return session.execute(
            tool_call={"name": tool_name, "arguments": tool_args},
            execute_fn=lambda act: orig_run(*args, **kwargs) if orig_run else None,
        )

    if hasattr(tool, "_run"):
        tool._run = guarded_run
    elif hasattr(tool, "run"):
        tool.run = guarded_run

    return tool
