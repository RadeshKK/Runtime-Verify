import random
from typing import Dict, List
from runtimeverify.state.base import StateInterface
from runtimeverify.detector.base import BaseDetector, DetectorMetadata
from runtimeverify.detector.results import DetectorResult, DetectorExplanation
from runtimeverify.markov.model import MarkovModel

class RandomDetector(BaseDetector):
    """Sanity check baseline: makes random anomaly decisions based on a configured probability."""
    def __init__(self, anomaly_rate: float = 0.05, name: str = "RandomBaseline"):
        self.anomaly_rate = anomaly_rate
        self._name = name

    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(name=self._name, version="1.0", requires_training=False)

    def fit(self, sequences: List[List[StateInterface]]) -> None:
        pass

    def observe(self, state: StateInterface) -> DetectorResult:
        is_anomaly = random.random() < self.anomaly_rate
        decision = "ANOMALY" if is_anomaly else "NORMAL"
        
        explanation = DetectorExplanation(
            detector_name=self._name,
            summary=f"Random decision resolved: {decision}.",
            evidence={"random_roll": is_anomaly}
        )

        return DetectorResult(
            deviation_score=1.0 if is_anomaly else 0.0,
            confidence=0.5,
            decision=decision,
            explanation=explanation,
            raw_metrics={"anomaly_rate": self.anomaly_rate}
        )

    def reset(self) -> None:
        pass

    def save(self, path: str) -> None:
        pass

    def load(self, path: str) -> None:
        pass

    def explain(self, result: DetectorResult) -> DetectorExplanation:
        return result.explanation


class ThresholdDetector(BaseDetector):
    """
    Simple rule-based baseline: flags an anomaly if the state's 
    metadata risk level exceeds a configured threshold (e.g. critical).
    """
    def __init__(self, risk_threshold: str = "critical", name: str = "ThresholdBaseline"):
        self.risk_threshold = risk_threshold.lower()
        self._name = name
        
        # Risk priority order
        self._priorities = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(name=self._name, version="1.0", requires_training=False)

    def fit(self, sequences: List[List[StateInterface]]) -> None:
        pass

    def observe(self, state: StateInterface) -> DetectorResult:
        state_risk = state.metadata.risk_level.lower()
        
        state_priority = self._priorities.get(state_risk, 0)
        threshold_priority = self._priorities.get(self.risk_threshold, 3)
        
        is_anomaly = state_priority >= threshold_priority
        decision = "ANOMALY" if is_anomaly else "NORMAL"

        explanation = DetectorExplanation(
            detector_name=self._name,
            summary=f"State risk level '{state_risk}' checked against threshold '{self.risk_threshold}'.",
            evidence={"state_risk": state_risk, "threshold": self.risk_threshold}
        )

        return DetectorResult(
            deviation_score=float(state_priority),
            confidence=1.0,
            decision=decision,
            explanation=explanation,
            raw_metrics={"risk_level": state_risk}
        )

    def reset(self) -> None:
        pass

    def save(self, path: str) -> None:
        pass

    def load(self, path: str) -> None:
        pass

    def explain(self, result: DetectorResult) -> DetectorExplanation:
        return result.explanation


class FrequencyDetector(BaseDetector):
    """
    Transition frequency baseline: monitors state transition probabilities from a Markov model.
    Flags an anomaly if the estimated transition probability is below a static probability threshold.
    """
    def __init__(self, markov_model: MarkovModel, min_prob_threshold: float = 0.05, name: str = "FrequencyBaseline"):
        self.model = markov_model
        self.threshold = min_prob_threshold
        self._name = name
        self._session_prev_state: Dict[str, str] = {}

    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(name=self._name, version="1.0", requires_training=True)

    def fit(self, sequences: List[List[StateInterface]]) -> None:
        # Convert state sequences to string sequences for Markov Model training
        string_seqs = [[state.name for state in seq] for seq in sequences]
        self.model.train(string_seqs)

    def observe(self, state: StateInterface) -> DetectorResult:
        session_id = state.context.session_id
        curr_name = state.name
        prev_name = self._session_prev_state.get(session_id)
        
        # Save current state as previous for next step
        self._session_prev_state[session_id] = curr_name
        
        # PENDING on the first state in sequence
        if prev_name is None:
            return DetectorResult(
                deviation_score=0.0,
                confidence=0.5,
                decision="PENDING",
                explanation=DetectorExplanation(
                    detector_name=self._name,
                    summary="First state in sequence, transition pending.",
                    evidence={}
                )
            )

        # Retrieve transition probability
        p_val = self.model.transition_probability(prev_name, curr_name)
        
        is_anomaly = p_val < self.threshold
        decision = "ANOMALY" if is_anomaly else "NORMAL"

        explanation = DetectorExplanation(
            detector_name=self._name,
            summary=f"Transition probability P({curr_name}|{prev_name}) = {p_val:.4f} compared to limit {self.threshold:.4f}.",
            evidence={"prev_state": prev_name, "curr_state": curr_name, "probability": p_val}
        )

        return DetectorResult(
            deviation_score=1.0 - p_val,
            confidence=1.0,
            decision=decision,
            explanation=explanation,
            raw_metrics={"probability": p_val}
        )

    def reset(self) -> None:
        self._session_prev_state.clear()
        
    def reset_session(self, session_id: str) -> None:
        self._session_prev_state.pop(session_id, None)

    def save(self, path: str) -> None:
        self.model.save(path)

    def load(self, path: str) -> None:
        self.model.load(path)

    def explain(self, result: DetectorResult) -> DetectorExplanation:
        return result.explanation
