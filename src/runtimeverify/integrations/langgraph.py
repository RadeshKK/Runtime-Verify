from typing import Any, Callable, Optional
import uuid

from runtimeverify.events import ToolEvent
from runtimeverify.interception.contract import InterceptionFailureMode, UnifiedInterceptionContract
from runtimeverify.interception.models import Action, ActionType, ExecutionContext
from runtimeverify.telemetry.manager import get_global_manager


class LangGraphAdapter:
    """
    Adapter for LangGraph. Wraps nodes to enforce pre-execution fail-closed gating
    and track state updates emitted as standard telemetry events.
    """

    @staticmethod
    def instrument_node(
        node_name: str,
        node_func: Callable[..., Any],
        session: Optional[Any] = None,
        fail_closed: bool = True,
    ) -> Callable[..., Any]:
        """
        Wraps a LangGraph node function with pre-execution gating and telemetry emission.
        """
        gating_contract = (
            UnifiedInterceptionContract(
                session=session,
                failure_mode=InterceptionFailureMode.FAIL_CLOSED if fail_closed else InterceptionFailureMode.FAIL_OPEN,
            )
            if session is not None
            else None
        )

        def wrapper(state: Any, *args: Any, **kwargs: Any) -> Any:
            session_id = getattr(state, "session_id", "langgraph_session")
            agent_id = getattr(state, "agent_id", "langgraph_agent")
            state_keys = list(state.keys()) if hasattr(state, "keys") else []

            # 1. Pre-Execution Security Gating
            if gating_contract is not None:
                ctx = ExecutionContext(session_id=session_id, agent_id=agent_id)
                action = Action(
                    action_id=f"act_lg_{uuid.uuid4().hex[:10]}",
                    action_type=ActionType.TOOL,
                    name="execute_node",
                    target=node_name,
                    params={"state_keys": state_keys, "args": list(args)},
                    context=ctx,
                    agent_id=agent_id,
                    session_id=session_id,
                )
                gating_contract.gate_action(action)

            manager = get_global_manager()

            # 2. Emit start event
            start_event = ToolEvent(
                session_id=session_id,
                agent_id=agent_id,
                tool_name=node_name,
                arguments={"state_keys": state_keys},
                status="running",
            )
            manager.bus.publish(start_event)

            try:
                result = node_func(state, *args, **kwargs)

                # Emit success event
                success_event = ToolEvent(
                    session_id=session_id,
                    agent_id=agent_id,
                    tool_name=node_name,
                    arguments={"state_keys": state_keys},
                    status="success",
                )
                manager.bus.publish(success_event)
                return result
            except Exception as e:
                # Emit failure event
                failure_event = ToolEvent(
                    session_id=session_id,
                    agent_id=agent_id,
                    tool_name=node_name,
                    arguments={"state_keys": state_keys},
                    status="error",
                    error_message=str(e),
                )
                manager.bus.publish(failure_event)
                raise e

        return wrapper
