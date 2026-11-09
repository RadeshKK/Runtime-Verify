from typing import Any, Callable, Optional

from runtimeverify.events import ToolEvent
from runtimeverify.interception.contract import InterceptionFailureMode, UnifiedInterceptionContract
from runtimeverify.interception.models import ActionType
from runtimeverify.telemetry.manager import get_global_manager


class CrewAIAdapter:
    """
    Adapter for CrewAI. Instruments task callbacks and tool callables
    to enforce pre-execution fail-closed gating and track telemetry events.
    """

    @staticmethod
    def instrument_tool(
        tool_fn: Callable[..., Any],
        tool_name: Optional[str] = None,
        session: Optional[Any] = None,
        fail_closed: bool = True,
    ) -> Callable[..., Any]:
        """
        Wraps a CrewAI tool execution callable with pre-execution gating.
        """
        contract = UnifiedInterceptionContract(
            session=session,
            failure_mode=InterceptionFailureMode.FAIL_CLOSED if fail_closed else InterceptionFailureMode.FAIL_OPEN,
        )
        return contract.wrap_tool(tool_fn, tool_name=tool_name, action_type=ActionType.TOOL)

    @staticmethod
    def create_task_callback(session_id: str, agent_id: str) -> Any:
        """
        Creates a CrewAI task callback function that emits ToolEvents on task completion.
        """

        def callback(task_output: Any) -> None:
            event = ToolEvent(
                session_id=session_id,
                agent_id=agent_id,
                tool_name="crewai_task_execution",
                arguments={
                    "description": getattr(task_output, "description", ""),
                    "agent": getattr(task_output, "agent", ""),
                },
                status="success",
                output=str(getattr(task_output, "raw", "")),
            )
            get_global_manager().bus.publish(event)

        return callback
