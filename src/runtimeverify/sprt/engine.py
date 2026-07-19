import math
import time
from typing import Dict, List, Any, Literal
from runtimeverify.state.base import StateInterface
from runtimeverify.markov.model import MarkovModel
from runtimeverify.detector.base import BaseDetector, DetectorMetadata
from runtimeverify.detector.results import DetectorResult, DetectorExplanation
from runtimeverify.sprt.hypothesis import Hypothesis
from runtimeverify.sprt.thresholds import WaldThresholds
from runtimeverify.sprt.decision import SPRTDecision

class SPRTEngine(BaseDetector):
    """
    Stateful streaming SPRT accumulator engine.
    Implements the BaseDetector interface, enabling it to plug directly into the Runtime Pipeline.
    Consumes transition probabilities from MarkovModel and aggregates log-likelihood ratios.
    """

    def __init__(self, markov_model: MarkovModel, hypothesis: Hypothesis, name: str = "SPRTDetector", session_ttl: float = 3600.0):
        self.model = markov_model
        self.hypothesis = hypothesis
        self.thresholds = WaldThresholds(hypothesis)
        self._name = name
        self.session_ttl = session_ttl

        # Stateful accumulators per session ID
        self._session_llr: Dict[str, float] = {}
        self._session_counts: Dict[str, int] = {}
        self._session_prev_state: Dict[str, str] = {}
        self._session_last_access: Dict[str, float] = {}

    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name=self._name,
            version="1.0",
            supported_categories=[],
            requires_training=True
        )

    def fit(self, sequences: List[List[StateInterface]]) -> None:
        """Fits the underlying Markov Model on historical training sequences."""
        # Convert state sequences to string sequences for Markov Model training
        string_seqs = [[state.name for state in seq] for seq in sequences]
        self.model.train(string_seqs)

    def observe(self, state: StateInterface) -> DetectorResult:
        """
        BaseDetector observe contract.
        Executes streaming SPRT check and maps it to a standard DetectorResult.
        """
        # Run streaming SPRT check
        decision = self.observe_sprt(state)

        # Map SPRTDecision.status to BaseDetector decision literal
        decision_map = {
            "ACCEPT_H0": "NORMAL",
            "ACCEPT_H1": "ANOMALY",
            "PENDING": "PENDING"
        }

        # Resolve explainability details
        if decision.status == "ACCEPT_H1":
            summary = (
                f"Anomalous behavior sequence detected. Cumulative log-likelihood ratio "
                f"{decision.log_likelihood_ratio:.4f} crossed upper Wald threshold {decision.upper_threshold:.4f}."
            )
        elif decision.status == "ACCEPT_H0":
            summary = f"Normal execution confirmed. Cumulative LLR crossed lower Wald threshold {decision.lower_threshold:.4f}."
        else:
            summary = f"Observation accumulated. Current LLR: {decision.log_likelihood_ratio:.4f}."

        explanation = DetectorExplanation(
            detector_name=self._name,
            summary=summary,
            evidence=decision.evidence
        )

        # Resolve confidence (1 - alpha for anomalies, 1 - beta for normal)
        confidence = 1.0 - self.hypothesis.alpha if decision.status == "ACCEPT_H1" else 1.0 - self.hypothesis.beta
        if decision.status == "PENDING":
            confidence = 0.5

        return DetectorResult(
            deviation_score=decision.log_likelihood_ratio,
            confidence=confidence,
            decision=decision_map.get(decision.status, "PENDING"),
            explanation=explanation,
            raw_metrics={
                "observation_count": decision.observation_count,
                "lower_threshold": decision.lower_threshold,
                "upper_threshold": decision.upper_threshold,
            }
        )

    def _cleanup_sessions(self) -> None:
        """Removes sessions that have not been accessed within the TTL."""
        now = time.time()
        expired_sessions = [
            sid for sid, last_access in self._session_last_access.items()
            if now - last_access > self.session_ttl
        ]
        for sid in expired_sessions:
            self.reset_session(sid)

    def observe_sprt(self, state: StateInterface) -> SPRTDecision:
        """
        Calculates likelihood increment, accumulates log-likelihood ratio,
        and evaluates Wald thresholds for the session.
        """
        self._cleanup_sessions()

        session_id = state.context.session_id
        current_name = state.name

        llr = self._session_llr.get(session_id, 0.0)
        count = self._session_counts.get(session_id, 0)
        prev_name = self._session_prev_state.get(session_id, None)

        self._session_last_access[session_id] = time.time()

        increment = 0.0
        evidence: Dict[str, Any] = {}

        if prev_name is not None:
            # 1. Fetch probabilities
            p_val = self.model.transition_probability(prev_name, current_name)
            q_val = self.hypothesis.get_q_probability(prev_name, state)

            # 2. Cumulative log-likelihood ratio increment
            # We assume model smoothing guarantees p_val > 0 and q_val > 0
            increment = math.log(q_val / p_val)

            # Prevent infinite jumps (log-infinity capping)
            if increment > self.hypothesis.llr_cap:
                increment = self.hypothesis.llr_cap
            elif increment < -self.hypothesis.llr_cap:
                increment = -self.hypothesis.llr_cap

            llr += increment
            count += 1
            evidence = {
                "prev_state": prev_name,
                "curr_state": current_name,
                "p_probability": p_val,
                "q_probability": q_val,
                "increment": increment
            }
        else:
            evidence = {
                "curr_state": current_name,
                "increment": 0.0
            }

        # 4. Save state traces
        self._session_prev_state[session_id] = current_name
        self._session_counts[session_id] = count

        # 5. Check Wald thresholds
        status: Literal["ACCEPT_H0", "ACCEPT_H1", "PENDING"] = "PENDING"
        if llr >= self.thresholds.upper_boundary:
            status = "ACCEPT_H1"
            # Lock the LLR at or above threshold to maintain alert state
            self._session_llr[session_id] = llr
        elif llr <= self.thresholds.lower_boundary:
            status = "ACCEPT_H0"
            # Reset LLR to restart the sequential testing sequence
            self._session_llr[session_id] = 0.0
        else:
            self._session_llr[session_id] = llr

        return SPRTDecision(
            status=status,
            log_likelihood_ratio=llr,
            lower_threshold=self.thresholds.lower_boundary,
            upper_threshold=self.thresholds.upper_boundary,
            observation_count=count,
            evidence=evidence
        )

    def reset(self) -> None:
        """Resets all session state tracking variables."""
        self._session_llr.clear()
        self._session_counts.clear()
        self._session_prev_state.clear()
        self._session_last_access.clear()

    def reset_session(self, session_id: str) -> None:
        """Resets tracking variables for a specific session."""
        self._session_llr.pop(session_id, None)
        self._session_counts.pop(session_id, None)
        self._session_prev_state.pop(session_id, None)
        self._session_last_access.pop(session_id, None)

    def save(self, path: str) -> None:
        """Saves the underlying Markov model to path."""
        self.model.save(path)

    def load(self, path: str) -> None:
        """Loads the underlying Markov model from path."""
        self.model.load(path)

    def explain(self, result: DetectorResult) -> DetectorExplanation:
        """Returns the explanation structure stored in the result."""
        return result.explanation
