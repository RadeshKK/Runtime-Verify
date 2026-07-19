from typing import Optional, Dict, Any
from runtimeverify.detector.interfaces import BaseDetector
from runtimeverify.encoder.models import SymbolicState

class VerificationSession:
    """
    Manages the state and verification lifecycle for a single agent session.
    """
    def __init__(self, trace_id: str, detector: BaseDetector):
        self.trace_id = trace_id
        self.detector = detector
        self.current_state: Optional[SymbolicState] = None
        self.history: list[SymbolicState] = []
        self.metadata: Dict[str, Any] = {}

    def update_state(self, state: SymbolicState) -> None:
        """Updates the session's current state and archives the transition."""
        self.current_state = state
        self.history.append(state)

    def get_transition(self) -> Dict[str, Optional[str]]:
        """Returns the transition from the previous state to the current state."""
        prev_state = self.history[-2].token if len(self.history) >= 2 else None
        curr_state = self.current_state.token if self.current_state else None
        return {
            "from_state": prev_state,
            "to_state": curr_state
        }
