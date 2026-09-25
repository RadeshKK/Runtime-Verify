from abc import ABC, abstractmethod
from typing import Dict, List, Union
from runtimeverify.state.base import StateInterface
from runtimeverify.state.categories import StateCategory
from runtimeverify.state.hierarchy import StateHierarchy


class AlternativeModel(ABC):
    """
    Abstract Base Class for the alternative hypothesis distribution Q(s_t | s_{t-1}).
    Represents the expected behavior profile under anomalous or malicious conditions.
    """

    @abstractmethod
    def get_probability(self, prev_state: str, curr_state: StateInterface) -> float:
        """Returns the probability Q(curr_state | prev_state) under this alternative model."""
        pass

    @abstractmethod
    def sample(self, prev_state: str) -> str:
        """Samples a state from the distribution Q(. | prev_state)."""
        pass


class UniformAlternativeModel(AlternativeModel):
    """Q is modeled as a uniform distribution over the state alphabet vocabulary."""

    def __init__(self, vocabulary_size: int):
        self.vocabulary_size = vocabulary_size

    def get_probability(self, prev_state: str, curr_state: StateInterface) -> float:
        return 1.0 / self.vocabulary_size if self.vocabulary_size > 0 else 0.0

    def sample(self, prev_state: str) -> str:
        # Simplified sampling: return a generic state if we don't have the vocabulary
        return "UNKNOWN_SAMPLED_STATE"


class AdversarialAlternativeModel(AlternativeModel):
    """
    Q is modeled to prioritize high-risk states (e.g. command execution, data deletion).
    Simulates an attacker attempting to exploit the agent.
    """

    def __init__(
        self,
        vocabulary_size: int,
        high_risk_identifiers: List[Union[str, StateHierarchy, StateCategory]],
        high_risk_prob: float = 0.5,
    ):
        self.vocabulary_size = vocabulary_size
        self.high_risk_identifiers = high_risk_identifiers
        self.high_risk_prob = high_risk_prob

    def get_probability(self, prev_state: str, curr_state: StateInterface) -> float:
        is_high_risk = False
        for identifier in self.high_risk_identifiers:
            if isinstance(identifier, str) and curr_state.name == identifier:
                is_high_risk = True
                break
            elif isinstance(identifier, StateHierarchy) and curr_state.hierarchy.is_descendant_of(identifier):
                is_high_risk = True
                break
            elif isinstance(identifier, StateCategory) and curr_state.category == identifier:
                is_high_risk = True
                break

        if is_high_risk:
            return self.high_risk_prob / max(1, len(self.high_risk_identifiers))

        remaining_prob = 1.0 - self.high_risk_prob
        remaining_states_count = self.vocabulary_size - len(self.high_risk_identifiers)
        if remaining_states_count <= 0:
            return 1.0 / self.vocabulary_size
        return remaining_prob / remaining_states_count

    def sample(self, prev_state: str) -> str:
        return "SAMPLED_HIGH_RISK_STATE"


class EmpiricalAlternativeModel(AlternativeModel):
    """Q is modeled using an explicit custom transition matrix or previously observed matrix counts."""

    def __init__(self, transition_matrix: Dict[str, Dict[str, float]], vocabulary_size: int):
        self.matrix = {k.upper(): {tk.upper(): tv for tk, tv in v.items()} for k, v in transition_matrix.items()}
        self.vocabulary_size = vocabulary_size

    def get_probability(self, prev_state: str, curr_state: StateInterface) -> float:
        prev = prev_state.upper()
        curr = curr_state.name.upper()
        if prev in self.matrix and curr in self.matrix[prev]:
            return self.matrix[prev][curr]
        return 1.0 / self.vocabulary_size if self.vocabulary_size > 0 else 0.0

    def sample(self, prev_state: str) -> str:
        prev = prev_state.upper()
        if prev in self.matrix:
            options = list(self.matrix[prev].keys())
            weights = list(self.matrix[prev].values())
            import random

            return random.choices(options, weights=weights)[0]
        return "UNKNOWN_SAMPLED_STATE"
