from typing import List
from runtimeverify.markov.matrix import TransitionCounter, ProbabilityMatrix


class MarkovTrainer:
    """
    Coordinates count accumulation and updates estimated probabilities.
    Supports both batch training (fit) and online incremental updates.
    """

    def __init__(self, smoothing: float = 1e-6):
        self.counter = TransitionCounter()
        self.matrix = ProbabilityMatrix(smoothing=smoothing)

    def fit(self, sequences: List[List[str]]) -> None:
        """
        Batch fits model weights over a list of state trace sequences.

        Args:
            sequences: A list of state traces, where each trace is a list of state strings.
        """
        for seq in sequences:
            self.counter.add_sequence(seq)
        self.matrix.estimate(self.counter)

    def update(self, prev_state: str, curr_state: str) -> None:
        """
        Streaming update. Increments transition counts and updates the probability matrix.

        Args:
            prev_state: Source state string.
            curr_state: Target state string.
        """
        self.counter.add_transition(prev_state, curr_state)
        self.matrix.estimate(self.counter)

    def clear(self) -> None:
        """Clears all accumulated counts and matrices."""
        self.counter = TransitionCounter()
        self.matrix = ProbabilityMatrix(smoothing=self.matrix.smoothing)
