from typing import Dict, TYPE_CHECKING
from runtimeverify.detector.results import DetectorResult

if TYPE_CHECKING:
    from runtimeverify.runtime.context import Decision


class PolicyEngine:
    """
    Core policy evaluation engine.
    Compares detector statistical deviations against threshold invariants.
    """

    def __init__(self, threshold: float = 10.0):
        self.threshold = threshold

    def evaluate(self, session_id: str, agent_id: str, detector_results: Dict[str, DetectorResult]) -> "Decision":
        """
        Evaluates active policies on detector results and yields a structured Decision.
        """
        from runtimeverify.runtime.context import Decision

        status = "ALLOW"
        triggered = []
        max_deviation = 0.0
        evidence = {}

        for name, res in detector_results.items():
            if res.deviation_score > max_deviation:
                max_deviation = res.deviation_score

            # Simple threshold check
            if res.deviation_score >= self.threshold or res.decision == "ANOMALY":
                status = "BLOCK"
                triggered.append(f"threshold_exceeded:{name}")
                evidence[name] = res.explanation.summary

        return Decision(
            session_id=session_id,
            agent_id=agent_id,
            status=status,
            confidence=1.0,
            evidence=evidence,
            detector_results={k: v.model_dump() for k, v in detector_results.items()},
            triggered_policies=triggered,
        )
