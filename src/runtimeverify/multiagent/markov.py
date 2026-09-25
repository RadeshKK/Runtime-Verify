"""
Multi-Agent Markov Behavioral Modeling for RuntimeVerify (Phase 17).
Extends first-order Markov transition matrices to multi-agent role workflows,
tracking joint role-action state transitions and cross-agent delegation sequences.
"""

from typing import List
from runtimeverify.events.base import Event
from runtimeverify.markov.model import MarkovModel


class MultiAgentMarkovModel:
    """
    First-order Markov model modeling multi-agent behavioral sequences and cross-agent handoffs.
    Transitions represent joint role-action states (e.g. 'PLANNER:PLAN' -> 'CODER:WRITE' -> 'TESTER:EXECUTE').
    """

    def __init__(self, smoothing: float = 1e-5, model_version: str = "1.0"):
        self.model = MarkovModel(smoothing=smoothing, model_version=model_version)
        self.smoothing = smoothing
        self.model_version = model_version

    @classmethod
    def state_from_event(cls, event: Event) -> str:
        """
        Synthesizes a standardized canonical state identifier from a multi-agent event.
        - For cross-agent events (delegation/handoff/communication): 'SRC_ROLE->TGT_ROLE:ACTION'
        - For intra-agent execution: 'ROLE:ACTION'
        """
        src_role = (event.agent_role or event.agent_type or "worker").upper()
        tgt_role = (event.target_agent_role or "").upper()
        action = (event.action or event.event_type or "unknown").upper()

        if tgt_role:
            return f"{src_role}->{tgt_role}:{action}"
        return f"{src_role}:{action}"

    def fit_sequences(self, sequences: List[List[str]]) -> None:
        """Fits Markov transition weights on historical multi-agent state sequences."""
        self.model.train(sequences)

    def fit_traces(self, traces: List[List[Event]]) -> None:
        """Converts traces of Events to string state sequences and fits the model."""
        state_sequences = [[self.state_from_event(event) for event in trace] for trace in traces]
        self.fit_sequences(state_sequences)

    def transition_probability(self, prev_state: str, curr_state: str) -> float:
        """Evaluates empirical transition probability P(curr_state | prev_state)."""
        return self.model.transition_probability(prev_state, curr_state)

    def observe(self, prev_state: str, curr_state: str) -> float:
        """Online update of transition observations."""
        return self.model.observe(prev_state, curr_state)
