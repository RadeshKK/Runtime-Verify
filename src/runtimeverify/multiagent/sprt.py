"""
Multi-Agent Sequential Probability Ratio Test (SPRT) Engine for RuntimeVerify (Phase 17).
Accumulates cross-agent likelihood ratios over session workflows to detect subtle multi-step
delegation and behavioral drifts across autonomous agent swarms without false alarms.
"""

import math
import time
from typing import Any, Dict, Optional
from runtimeverify.events.base import Event
from runtimeverify.multiagent.markov import MultiAgentMarkovModel
from runtimeverify.sprt.hypothesis import Hypothesis
from runtimeverify.sprt.thresholds import WaldThresholds


class MultiAgentSPRTDecision:
    """Represents a sequential verification decision for a multi-agent session trace."""

    def __init__(
        self,
        session_id: str,
        status: str,  # ACCEPT_H0, ACCEPT_H1, PENDING
        log_likelihood_ratio: float,
        step_count: int,
        lower_threshold: float,
        upper_threshold: float,
        last_transition: Optional[str] = None,
        transition_probability: float = 1.0,
    ):
        self.session_id = session_id
        self.status = status
        self.log_likelihood_ratio = log_likelihood_ratio
        self.step_count = step_count
        self.lower_threshold = lower_threshold
        self.upper_threshold = upper_threshold
        self.last_transition = last_transition
        self.transition_probability = transition_probability

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "status": self.status,
            "log_likelihood_ratio": round(self.log_likelihood_ratio, 4),
            "step_count": self.step_count,
            "lower_threshold": round(self.lower_threshold, 4),
            "upper_threshold": round(self.upper_threshold, 4),
            "last_transition": self.last_transition,
            "transition_probability": round(self.transition_probability, 6),
        }


class MultiAgentSPRTEngine:
    """
    Wald's Sequential Probability Ratio Test accumulator for multi-agent workflows.
    Monitors cross-agent transitions within a shared session, accumulating evidence
    to statistically differentiate legitimate collaborative work from compromised drift.
    """

    def __init__(
        self,
        markov_model: MultiAgentMarkovModel,
        hypothesis: Optional[Hypothesis] = None,
        session_ttl: float = 3600.0,
    ):
        self.model = markov_model
        self.hypothesis = hypothesis or Hypothesis(vocabulary_size=10, alpha=0.01, beta=0.01)
        self.thresholds = WaldThresholds(self.hypothesis)
        self.session_ttl = session_ttl

        # Session states
        self._session_llr: Dict[str, float] = {}
        self._session_steps: Dict[str, int] = {}
        self._session_prev_state: Dict[str, str] = {}
        self._session_last_access: Dict[str, float] = {}

    def observe_event(self, event: Event) -> MultiAgentSPRTDecision:
        """
        Observes a single multi-agent event and updates the sequential probability ratio test.
        """
        session_id = event.session_id
        curr_time = time.time()
        curr_state = MultiAgentMarkovModel.state_from_event(event)

        # Session cleanup if expired
        last_acc = self._session_last_access.get(session_id, curr_time)
        if (curr_time - last_acc) > self.session_ttl:
            self.reset_session(session_id)

        self._session_last_access[session_id] = curr_time

        prev_state = self._session_prev_state.get(session_id)
        self._session_prev_state[session_id] = curr_state

        if prev_state is None:
            # First event in session: baseline initialization
            self._session_llr[session_id] = 0.0
            self._session_steps[session_id] = 1
            return MultiAgentSPRTDecision(
                session_id=session_id,
                status="PENDING",
                log_likelihood_ratio=0.0,
                step_count=1,
                lower_threshold=self.thresholds.lower_boundary,
                upper_threshold=self.thresholds.upper_boundary,
                last_transition=f"START -> {curr_state}",
                transition_probability=1.0,
            )

        # Compute empirical transition probability
        prob = self.model.transition_probability(prev_state, curr_state)

        # Compute log-likelihood increment:
        p0 = 0.05
        p1 = 0.35

        # Anomaly indicator: if transition probability is below median expectation (e.g. < 0.15)
        is_anomalous = 1 if prob < 0.15 else 0

        if is_anomalous:
            llr_increment = math.log(p1 / p0)
        else:
            llr_increment = math.log((1 - p1) / (1 - p0))

        cum_llr = self._session_llr.get(session_id, 0.0) + llr_increment
        self._session_llr[session_id] = cum_llr

        steps = self._session_steps.get(session_id, 0) + 1
        self._session_steps[session_id] = steps

        # Decision threshold comparison
        if cum_llr >= self.thresholds.upper_boundary:
            status = "ACCEPT_H1"  # Drift/Anomaly confirmed
        elif cum_llr <= self.thresholds.lower_boundary:
            status = "ACCEPT_H0"  # Conforms to normal baseline
            # Reset after acceptance of H0 to allow continuous sequential monitoring
            self._session_llr[session_id] = 0.0
        else:
            status = "PENDING"

        return MultiAgentSPRTDecision(
            session_id=session_id,
            status=status,
            log_likelihood_ratio=cum_llr,
            step_count=steps,
            lower_threshold=self.thresholds.lower_boundary,
            upper_threshold=self.thresholds.upper_boundary,
            last_transition=f"{prev_state} -> {curr_state}",
            transition_probability=prob,
        )

    def reset_session(self, session_id: str) -> None:
        """Resets the accumulated SPRT statistics for a session."""
        self._session_llr.pop(session_id, None)
        self._session_steps.pop(session_id, None)
        self._session_prev_state.pop(session_id, None)
        self._session_last_access.pop(session_id, None)
