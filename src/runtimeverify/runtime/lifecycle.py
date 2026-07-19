from enum import Enum

class RuntimeState(str, Enum):
    """
    Represents the operational state of the runtime pipeline state machine.
    Simplifies policy enforcement and state-tracking integrations.
    """
    CREATED = "created"
    INITIALIZED = "initialized"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class RuntimeLifecycle:
    """Manages state transitions of the runtime pipeline machine, preventing illegal moves."""
    
    def __init__(self):
        self._state = RuntimeState.CREATED
        # Define allowed transitions
        self._transitions = {
            RuntimeState.CREATED: [RuntimeState.INITIALIZED, RuntimeState.FAILED],
            RuntimeState.INITIALIZED: [RuntimeState.RUNNING, RuntimeState.FAILED],
            RuntimeState.RUNNING: [RuntimeState.PAUSED, RuntimeState.COMPLETED, RuntimeState.FAILED],
            RuntimeState.PAUSED: [RuntimeState.RUNNING, RuntimeState.COMPLETED, RuntimeState.FAILED],
            RuntimeState.COMPLETED: [RuntimeState.INITIALIZED],  # Reset/Reinitialize
            RuntimeState.FAILED: [RuntimeState.INITIALIZED],
        }

    @property
    def current(self) -> RuntimeState:
        return self._state

    def transition_to(self, new_state: RuntimeState) -> None:
        """Transitions to a new state if the shift is legally permitted by the state machine."""
        allowed = self._transitions.get(self._state, [])
        if new_state not in allowed:
            raise ValueError(f"Illegal lifecycle transition: {self._state.value} -> {new_state.value}")
        self._state = new_state
