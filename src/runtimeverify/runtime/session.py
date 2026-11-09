import threading
import time
from collections import OrderedDict
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
    history: List[ExecutionState] = Field(
        default_factory=list, description="Array sequence of all ExecutionStates in this session"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata specific to this session scope")


class SessionManager:
    """
    Manager class coordinating active session instances and isolation boundaries.
    The SessionManager is thread-safe and bounds active sessions and trace history.
    """

    def __init__(self, max_sessions: int = 1024, ttl_seconds: float = 3600.0, max_history: int = 1000):
        if max_sessions < 1:
            raise ValueError("max_sessions must be at least 1")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if max_history < 1:
            raise ValueError("max_history must be at least 1")
        self._lock = threading.Lock()
        self._sessions: OrderedDict[str, SessionState] = OrderedDict()
        self._lifecycles: Dict[str, RuntimeLifecycle] = {}
        self._last_access: Dict[str, float] = {}
        self.max_sessions = max_sessions
        self.ttl_seconds = ttl_seconds
        self.max_history = max_history

    def _evict_expired(self, now: float) -> None:
        """Evict idle sessions; OrderedDict keeps oldest access at the front."""
        while self._sessions:
            oldest_id = next(iter(self._sessions))
            last_access = self._last_access.get(oldest_id, 0.0)
            if now - last_access < self.ttl_seconds:
                break
            self._remove_session(oldest_id)

    def _touch(self, session_id: str, now: float) -> None:
        self._sessions.move_to_end(session_id)
        self._last_access[session_id] = now

    def _remove_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        self._lifecycles.pop(session_id, None)
        self._last_access.pop(session_id, None)

    def get_or_create(self, session_id: str, agent_id: str) -> SessionState:
        """Retrieves an active SessionState, or instantiates a new one if missing."""
        with self._lock:
            now = time.monotonic()
            self._evict_expired(now)
            if session_id not in self._sessions:
                while len(self._sessions) >= self.max_sessions:
                    self._remove_session(next(iter(self._sessions)))
                self._sessions[session_id] = SessionState(session_id=session_id, agent_id=agent_id)
                self._lifecycles[session_id] = RuntimeLifecycle()
            self._touch(session_id, now)
            return self._sessions[session_id]

    def get_lifecycle(self, session_id: str) -> Optional[RuntimeLifecycle]:
        """Gets the lifecycle tracker for a session, or None."""
        with self._lock:
            now = time.monotonic()
            self._evict_expired(now)
            if session_id in self._sessions:
                self._touch(session_id, now)
            return self._lifecycles.get(session_id)

    def update_state(self, session_id: str, new_state: ExecutionState) -> None:
        """Updates transition fields, linking current to previous states in history."""
        with self._lock:
            now = time.monotonic()
            self._evict_expired(now)
            session = self._sessions.get(session_id)
            if not session:
                raise KeyError(f"Session '{session_id}' does not exist.")

            session.previous_state = session.current_state
            session.current_state = new_state
            session.history.append(new_state)
            if len(session.history) > self.max_history:
                del session.history[: -self.max_history]
            self._touch(session_id, now)

    def list_sessions(self) -> List[str]:
        """Lists active session IDs."""
        with self._lock:
            self._evict_expired(time.monotonic())
            return list(self._sessions.keys())

    def remove_session(self, session_id: str) -> None:
        """Discards session states and lifecycle maps."""
        with self._lock:
            self._remove_session(session_id)

    def clear(self) -> None:
        """Clears all session states."""
        with self._lock:
            self._sessions.clear()
            self._lifecycles.clear()
            self._last_access.clear()
