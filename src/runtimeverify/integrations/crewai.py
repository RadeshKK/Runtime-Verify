from typing import Any
from runtimeverify.telemetry.manager import get_global_manager
from runtimeverify.events import ToolEvent


class CrewAIAdapter:
    """
    Adapter for CrewAI. Instruments Task callbacks to track
    task state execution and tool executions.
    """

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
