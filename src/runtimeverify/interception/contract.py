"""
Unified Interception Contract & Fail-Closed Gating Framework for RuntimeVerify (Sprint 2).
Provides standardized pre-execution action gating, timeout enforcement,
and explicit fail-closed guarantees across SDK, LangChain, CrewAI, LangGraph, and PydanticAI.
"""

from enum import Enum
import logging
from typing import Any, Callable, Optional, TypeVar
import uuid

from runtimeverify.interception.exceptions import (
    ExecutionBlockedError,
    ExecutionReviewRequiredError,
    SecurityFailClosedError,
)
from runtimeverify.interception.models import (
    Action,
    ActionType,
    ExecutionContext,
    InterceptionDecision,
    InterceptionMode,
)

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


class InterceptionFailureMode(str, Enum):
    """Failure-mode policy when verification or approval services are unavailable or timeout."""

    FAIL_CLOSED = "FAIL_CLOSED"  # Default: Deny execution on any verification error or timeout
    FAIL_OPEN = "FAIL_OPEN"  # Insecure opt-in: Allow execution on error (only for low-risk testing)


class UnifiedInterceptionContract:
    """
    Standardized pre-execution gating contract enforcing fail-closed guarantees.
    Prevents unauthorized tool execution regardless of which agent framework or SDK is used.
    """

    def __init__(
        self,
        session: Any = None,
        failure_mode: InterceptionFailureMode = InterceptionFailureMode.FAIL_CLOSED,
        default_policy_id: str = "fail-closed-gate",
    ):
        self.session = session
        self.failure_mode = failure_mode
        self.default_policy_id = default_policy_id

    def gate_action(
        self,
        action: Action,
        session: Optional[Any] = None,
    ) -> InterceptionDecision:
        """
        Gates an agent action before tool execution.

        Raises:
            ExecutionBlockedError: If policy or sequential verification blocks the action.
            ExecutionReviewRequiredError: If the action requires dual-control human approval.
            SecurityFailClosedError: If verification times out or throws an unhandled error under FAIL_CLOSED.
        """
        active_session = session or self.session
        if active_session is None:
            if self.failure_mode == InterceptionFailureMode.FAIL_CLOSED:
                raise SecurityFailClosedError(
                    action_id=action.action_id,
                    error_message="No active RuntimeVerify session available for pre-execution gating.",
                )
            logger.warning("No active session; proceeding under FAIL_OPEN.")
            return InterceptionDecision(
                action_id=action.action_id,
                mode=InterceptionMode.OBSERVE,
                status="ALLOW",
                execution_permitted=True,
                effective_action="EXECUTE",
                reason="Proceeding without active session under FAIL_OPEN.",
            )

        try:
            # Perform check through session
            decision = active_session.check(action)

            # If execution is not permitted
            if not getattr(decision, "execution_permitted", False):
                status = getattr(decision, "status", "BLOCK")
                reason = getattr(decision, "reason", "Action execution denied by policy.")
                if status == "REVIEW":
                    raise ExecutionReviewRequiredError(
                        action_id=action.action_id,
                        policy_id=getattr(decision, "policy_id", self.default_policy_id),
                        reason=reason,
                        approval_id=getattr(decision, "approval_request_id", None),
                    )
                raise ExecutionBlockedError(
                    action_id=action.action_id,
                    policy_id=getattr(decision, "policy_id", self.default_policy_id),
                    reason=reason,
                    severity=getattr(decision, "severity", "CRITICAL"),
                )

            return decision

        except (ExecutionBlockedError, ExecutionReviewRequiredError):
            raise
        except Exception as e:
            logger.error("Interception error evaluating action '%s': %s", action.action_id, e)
            if self.failure_mode == InterceptionFailureMode.FAIL_CLOSED:
                raise SecurityFailClosedError(
                    action_id=action.action_id,
                    error_message=f"Verification failure occurred under FAIL_CLOSED: {e}",
                ) from e
            return InterceptionDecision(
                action_id=action.action_id,
                mode=InterceptionMode.OBSERVE,
                status="ALLOW",
                execution_permitted=True,
                effective_action="EXECUTE",
                reason=f"Verification error bypassed under FAIL_OPEN: {e}",
            )

    def wrap_tool(
        self,
        tool_fn: Callable[..., Any],
        tool_name: Optional[str] = None,
        action_type: ActionType = ActionType.TOOL,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Callable[..., Any]:
        """
        Decorates a synchronous tool callable with deterministic pre-execution gating.
        """
        name = tool_name or getattr(tool_fn, "__name__", "tool")

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Construct Action from arguments
            action_params = {"args": list(args), "kwargs": kwargs}
            aid = agent_id or getattr(self.session, "agent_id", "agent-unknown")
            sid = session_id or getattr(self.session, "session_id", "session-unknown")
            ctx = ExecutionContext(session_id=sid, agent_id=aid)
            action = Action(
                action_id=f"act_{uuid.uuid4().hex[:12]}",
                action_type=action_type,
                name="invoke",
                target=name,
                params=action_params,
                context=ctx,
                agent_id=aid,
                session_id=sid,
            )
            self.gate_action(action)
            return tool_fn(*args, **kwargs)

        return wrapper
