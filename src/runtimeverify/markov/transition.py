from typing import List, Tuple
from runtimeverify.state.base import StateInterface

class TransitionExtractor:
    """
    Utility class that extracts sequential transition pairs from trace sequences.
    Converts list of ExecutionStates or string labels into tuples of (from_state, to_state).
    """

    @staticmethod
    def extract_pairs(sequence: List[str]) -> List[Tuple[str, str]]:
        """Extracts adjacent state transitions as string tuples."""
        if len(sequence) < 2:
            return []
        return [(sequence[i].upper(), sequence[i+1].upper()) for i in range(len(sequence) - 1)]

    @staticmethod
    def extract_pairs_from_states(sequence: List[StateInterface]) -> List[Tuple[str, str]]:
        """Extracts adjacent state transitions from ExecutionState nodes."""
        names = [state.name for state in sequence]
        return TransitionExtractor.extract_pairs(names)
