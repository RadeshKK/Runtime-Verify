from typing import Any, Callable
from runtimeverify.telemetry.manager import get_global_manager
from runtimeverify.events import ToolEvent


class LangGraphAdapter:
    """
    Adapter for LangGraph. Wraps nodes to track state updates
    and emit them as standard telemetry events.
    """

    @staticmethod
    def instrument_node(node_name: str, node_func: Callable) -> Callable:
        """Wraps a LangGraph node function to automatically emit telemetry events on run."""

        def wrapper(state: Any, *args, **kwargs) -> Any:
            session_id = getattr(state, "session_id", "langgraph_session")
            agent_id = getattr(state, "agent_id", "langgraph_agent")

            manager = get_global_manager()

            # Emit start event
            start_event = ToolEvent(
                session_id=session_id,
                agent_id=agent_id,
                tool_name=node_name,
                arguments={"state_keys": list(state.keys()) if hasattr(state, "keys") else []},
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
                    arguments={"state_keys": list(state.keys()) if hasattr(state, "keys") else []},
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
                    arguments={"state_keys": list(state.keys()) if hasattr(state, "keys") else []},
                    status="error",
                    error_message=str(e),
                )
                manager.bus.publish(failure_event)
                raise e

        return wrapper
