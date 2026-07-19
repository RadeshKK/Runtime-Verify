from abc import ABC, abstractmethod
from typing import Dict, Set

class AlternativeModel(ABC):
    """
    Abstract Base Class for the alternative hypothesis distribution Q(s_t | s_{t-1}).
    Represents the expected behavior profile under anomalous or malicious conditions.
    """
    
    @abstractmethod
    def get_probability(self, prev_state: str, curr_state: str) -> float:
        """Returns the probability Q(curr_state | prev_state) under this alternative model."""
        pass


class UniformAlternativeModel(AlternativeModel):
    """Q is modeled as a uniform distribution over the state alphabet vocabulary."""
    def __init__(self, vocabulary_size: int):
        self.vocabulary_size = vocabulary_size

    def get_probability(self, prev_state: str, curr_state: str) -> float:
        return 1.0 / self.vocabulary_size if self.vocabulary_size > 0 else 0.0


class AdversarialAlternativeModel(AlternativeModel):
    """
    Q is modeled to prioritize high-risk states (e.g. command execution, data deletion).
    Simulates an attacker attempting to exploit the agent.
    """
    def __init__(self, vocabulary_size: int, high_risk_states: Set[str], high_risk_prob: float = 0.5):
        self.vocabulary_size = vocabulary_size
        self.high_risk_states = {s.upper() for s in high_risk_states}
        self.high_risk_prob = high_risk_prob

    def get_probability(self, prev_state: str, curr_state: str) -> float:
        curr = curr_state.upper()
        if curr in self.high_risk_states:
            return self.high_risk_prob / len(self.high_risk_states)
        
        # Distribute remaining probability over non-high-risk states
        remaining_prob = 1.0 - self.high_risk_prob
        remaining_states_count = self.vocabulary_size - len(self.high_risk_states)
        if remaining_states_count <= 0:
            return 1.0 / self.vocabulary_size
        return remaining_prob / remaining_states_count


class EmpiricalAlternativeModel(AlternativeModel):
    """Q is modeled using an explicit custom transition matrix or previously observed matrix counts."""
    def __init__(self, transition_matrix: Dict[str, Dict[str, float]], vocabulary_size: int):
        self.matrix = {k.upper(): {tk.upper(): tv for tk, tv in v.items()} for k, v in transition_matrix.items()}
        self.vocabulary_size = vocabulary_size

    def get_probability(self, prev_state: str, curr_state: str) -> float:
        prev = prev_state.upper()
        curr = curr_state.upper()
        if prev in self.matrix and curr in self.matrix[prev]:
            return self.matrix[prev][curr]
        return 1.0 / self.vocabulary_size if self.vocabulary_size > 0 else 0.0
