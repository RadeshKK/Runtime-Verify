from typing import List, Dict, Set, Optional, Tuple
from runtimeverify.detector.markov.models import TransitionStats, MarkovModelSnapshot

class MarkovBehaviorModel:
    """
    Implements a first-order Markov Chain for estimating behavioral transitions.
    
    This model calculates the probability P(s_t | s_{t-1}) based on 
    frequency counts from training sequences.
    """

    def __init__(self):
        # Map of source_state -> target_state -> count
        self._counts: Dict[str, Dict[str, int]] = {}
        # Map of state -> total transitions from this state
        self._state_totals: Dict[str, int] = {}
        self._alphabet: Set[str] = set()

    def train(self, trace_sequences: List[List[str]]) -> None:
        """
        Trains the model by extracting transitions from a set of state sequences.

        Args:
            trace_sequences: A list of sequences, where each sequence is a list of symbolic states.
        """
        for sequence in trace_sequences:
            self.update_sequence(sequence)

    def update_sequence(self, sequence: List[str]) -> None:
        """
        Increments transition counts based on a single sequence of states.
        """
        for i in range(len(sequence) - 1):
            self.update_transition(sequence[i], sequence[i+1])

    def update_transition(self, source: str, target: str) -> None:
        """
        Updates the model with a single observed transition.
        """
        if source not in self._counts:
            self._counts[source] = {}
            self._state_totals[source] = 0
            
        self._counts[source][target] = self._counts[source].get(target, 0) + 1
        self._state_totals[source] += 1
        
        self._alphabet.add(source)
        self._alphabet.add(target)

    def get_probability(self, source: str, target: str) -> float:
        """
        Estimates the probability P(target | source).
        
        Returns:
            The transition probability (0.0 to 1.0).
        """
        if source not in self._counts or target not in self._counts[source]:
            return 0.0
        
        return self._counts[source][target] / self._state_totals[source]

    def get_transition_distribution(self, source: str) -> Dict[str, float]:
        """
        Returns the probability distribution for all possible next states from the source.
        """
        if source not in self._counts:
            return {}
            
        total = self._state_totals[source]
        return {
            target: count / total 
            for target, count in self._counts[source].items()
        }

    def explain_transition(self, source: str, target: str) -> str:
        """
        Provides a human-readable explanation of the transition probability.
        """
        prob = self.get_probability(source, target)
        count = self._counts.get(source, {}).get(target, 0)
        total = self._state_totals.get(source, 0)
        
        return f"Transition {source} -> {target} occurred {count} times out of {total} transitions from {source} (Prob: {prob:.4f})"

    def serialize(self) -> MarkovModelSnapshot:
        """
        Converts the internal state into a serializable Pydantic model.
        """
        matrix = {
            source: self.get_transition_distribution(source)
            for source in self._counts
        }
        
        return MarkovModelSnapshot(
            transition_matrix=matrix,
            state_counts=self._state_totals,
            alphabet=list(self._alphabet)
        )

    def load_snapshot(self, snapshot: MarkovModelSnapshot) -> None:
        """
        Restores the model from a snapshot.
        """
        self._state_totals = snapshot.state_counts.copy()
        self._alphabet = set(snapshot.alphabet)
        
        # Reconstruct counts from probabilities and totals
        self._counts = {}
        for source, dist in snapshot.transition_matrix.items():
            self._counts[source] = {}
            total = self._state_totals.get(source, 0)
            for target, prob in dist.items():
                # Recover count from probability: count = prob * total
                self._counts[source][target] = round(prob * total)
