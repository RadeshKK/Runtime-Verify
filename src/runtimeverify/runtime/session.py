import threading
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from runtimeverify.state.execution import ExecutionState
from runtimeverify.runtime.lifecycle import RuntimeLifecycle

class SessionState(BaseModel):
    """Immutable/mutable boundary representing the state tracking profile of an active agent session."""
    session_id: str = Field(..., description="Unique ID of the agent session")
    agent_id: str = Field(..., description="Unique ID of the agent being monitored")
    current_state: Optional[ExecutionState] = Field(None, description="The most recently resolved semantic state")
    previous_state: Optional[ExecutionState] = Field(None, description="The preceding semantic state")
    history: List[ExecutionState] = Field(default_factory=list, description="Array sequence of all ExecutionStates in this session")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata specific to this session scope")


class SessionManager:
    """
    Manager class coordinating active session instances and isolation boundaries.
    The SessionManager is thread-safe and retains historical trace arrays.
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: Dict[str, SessionState] = {}
        self._lifecycles: Dict[str, RuntimeLifecycle] = {}

    def get_or_create(self, session_id: str, agent_id: str) -> SessionState:
        """Retrieves an active SessionState, or instantiates a new one if missing."""
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionState(session_id=session_id, agent_id=agent_id)
                self._lifecycles[session_id] = RuntimeLifecycle()
            return self._sessions[session_id]

    def get_lifecycle(self, session_id: str) -> Optional[RuntimeLifecycle]:
        """Gets the lifecycle tracker for a session, or None."""
        with self._lock:
            return self._lifecycles.get(session_id)

    def update_state(self, session_id: str, new_state: ExecutionState) -> None:
        """Updates transition fields, linking current to previous states in history."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                raise KeyError(f"Session '{session_id}' does not exist.")
            
            session.previous_state = session.current_state
            session.current_state = new_state
            session.history.append(new_state)

    def list_sessions(self) -> List[str]:
        """Lists active session IDs."""
        with self._lock:
            return list(self._sessions.keys())

    def remove_session(self, session_id: str) -> None:
        """Discards session states and lifecycle maps."""
        with self._lock:
            self._sessions.pop(session_id, None)
            self._lifecycles.pop(session_id, None)
            
    def clear(self) -> None:
        """Clears all session states."""
        with self._lock:
            self._sessions.clear()
            self._lifecycles.clear()
