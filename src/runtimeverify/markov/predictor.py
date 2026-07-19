import math
from typing import List, Tuple
from runtimeverify.markov.matrix import ProbabilityMatrix

class MarkovPredictor:
    """
    Inference helper over an estimated ProbabilityMatrix.
    Calculates sequence joint probabilities, logs probabilities, and predicts next states.
    """
    
    def __init__(self, matrix: ProbabilityMatrix):
        self.matrix = matrix

    def transition_probability(self, prev_state: str, curr_state: str) -> float:
        """Retrieves P(curr_state | prev_state) from the matrix."""
        return self.matrix.get_probability(prev_state, curr_state)

    def sequence_probability(self, sequence: List[str]) -> float:
        """
        Calculates the cumulative joint probability of a sequence.
        Formula:
            P(S) = P(s_1) * prod_{i=2}^N P(s_i | s_{i-1})
            Note: We assume a uniform initial state distribution P(s_1) = 1.0.
        """
        if not sequence:
            return 0.0
        if len(sequence) == 1:
            return 1.0 if sequence[0].upper() in self.matrix.states else 0.0
            
        prob = 1.0
        for i in range(len(sequence) - 1):
            prob *= self.transition_probability(sequence[i], sequence[i+1])
        return prob

    def sequence_log_probability(self, sequence: List[str]) -> float:
        """
        Calculates the joint log-probability of a sequence (base e) to prevent numerical underflow.
        Formula:
            ln P(S) = sum_{i=2}^N ln P(s_i | s_{i-1})
        """
        if not sequence:
            return -float("inf")
        if len(sequence) == 1:
            return 0.0 if sequence[0].upper() in self.matrix.states else -float("inf")
            
        log_prob = 0.0
        for i in range(len(sequence) - 1):
            p = self.transition_probability(sequence[i], sequence[i+1])
            if p <= 0.0:
                return -float("inf")
            log_prob += math.log(p)
        return log_prob

    def predict_next(self, current_state: str, top_k: int = 3) -> List[Tuple[str, float]]:
        """
        Predicts the top-K most likely target states originating from the current state.
        Returns a sorted list of (state_name, probability) tuples.
        """
        curr = current_state.upper()
        if curr not in self.matrix.states:
            return []
            
        targets = self.matrix.probabilities.get(curr, {})
        sorted_targets = sorted(targets.items(), key=lambda item: item[1], reverse=True)
        
        return [(state, prob) for state, prob in sorted_targets if prob > 0.0][:top_k]
