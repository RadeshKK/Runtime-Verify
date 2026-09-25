from typing import Optional
from runtimeverify.events.base import Event
from runtimeverify.runtime.lifecycle import RuntimeLifecycle, RuntimeState
from runtimeverify.runtime.session import SessionManager
from runtimeverify.runtime.pipeline import RuntimePipeline
from runtimeverify.runtime.context import Decision


class RuntimeEngine:
    """
    Main orchestration engine of the runtime verification framework.
    Coordinates session context managers, encoders, dispatchers, and policy engines.
    """

    def __init__(self, pipeline: RuntimePipeline, session_manager: Optional[SessionManager] = None):
        self.pipeline = pipeline
        self.session_manager = session_manager or SessionManager()
        self.lifecycle = RuntimeLifecycle()
        self.lifecycle.transition_to(RuntimeState.INITIALIZED)

    def start(self) -> None:
        """Transitions the runtime engine into the active RUNNING phase."""
        self.lifecycle.transition_to(RuntimeState.RUNNING)

    def pause(self) -> None:
        """Suspends observation checks by transitioning to PAUSED."""
        self.lifecycle.transition_to(RuntimeState.PAUSED)

    def resume(self) -> None:
        """Resumes observation checks by transitioning back to RUNNING."""
        self.lifecycle.transition_to(RuntimeState.RUNNING)

    def stop(self) -> None:
        """Marks the execution session as successfully COMPLETED."""
        self.lifecycle.transition_to(RuntimeState.COMPLETED)

    def fail(self) -> None:
        """Flags the engine as FAILED due to operational errors."""
        self.lifecycle.transition_to(RuntimeState.FAILED)

    def observe(self, event: Event) -> Decision:
        """
        Observes a raw event, running it through the complete verification pipeline.

        Args:
            event: The incoming Telemetry Event instance.

        Returns:
            A structured Decision result detailing policy evaluation.
        """
        if self.lifecycle.current != RuntimeState.RUNNING:
            raise RuntimeError(
                f"Cannot execute observe(): Runtime Engine is in '{self.lifecycle.current.value}' state. "
                "Call start() first."
            )

        # 1. Access/Create Session Isolation Boundary
        session_id = event.session_id
        agent_id = event.agent_id

        # Get active session state
        self.session_manager.get_or_create(session_id, agent_id)

        # 2. Run sequential pipeline execution
        decision = self.pipeline.execute(event)

        # 3. Synchronize session tracking with latest resolved state
        session_states = self.pipeline.encoder._state_history.get(session_id, [])
        if session_states:
            latest_state = session_states[-1]
            self.session_manager.update_state(session_id, latest_state)

        return decision
