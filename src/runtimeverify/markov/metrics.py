import math
from runtimeverify.markov.matrix import ProbabilityMatrix


class MarkovMetrics:
    """Computes mathematical evaluation metrics (sparsity, entropy) over a ProbabilityMatrix."""

    @staticmethod
    def calculate_sparsity(matrix: ProbabilityMatrix) -> float:
        """
        Calculates the sparsity of the transition matrix.
        Sparsity is the proportion of zero-probability transitions out of all possible transitions (|S|^2).
        Returns a float between 0.0 (dense) and 1.0 (empty).
        """
        num_states = len(matrix.states)
        if num_states == 0:
            return 1.0

        zero_count = 0
        for state_from in matrix.states:
            for state_to in matrix.states:
                if matrix.get_probability(state_from, state_to) == 0.0:
                    zero_count += 1

        return zero_count / (num_states * num_states)

    @staticmethod
    def calculate_state_entropy(matrix: ProbabilityMatrix, state: str) -> float:
        """
        Calculates Shannon entropy for the transition distribution originating from a single state.

        Formula:
            H(s) = -sum( P(t|s) * log2(P(t|s)) )
        """
        state_key = state.upper()
        if state_key not in matrix.states:
            return 0.0

        entropy = 0.0
        probabilities = matrix.probabilities.get(state_key, {})

        for prob in probabilities.values():
            if prob > 0.0:
                entropy -= prob * math.log2(prob)

        return entropy

    @staticmethod
    def calculate_average_entropy(matrix: ProbabilityMatrix) -> float:
        """Computes the simple average of Shannon entropies across all states in the vocabulary."""
        if not matrix.states:
            return 0.0

        total_entropy = sum(MarkovMetrics.calculate_state_entropy(matrix, state) for state in matrix.states)
        return total_entropy / len(matrix.states)
