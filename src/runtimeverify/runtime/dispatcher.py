import logging
from typing import Dict, List, Optional
from runtimeverify.state.execution import ExecutionState
from runtimeverify.detector.base import BaseDetector
from runtimeverify.detector.results import DetectorResult, DetectorExplanation

class Dispatcher:
    """
    State dispatcher coordinating concurrent statistical detector checks.
    Isolates faults so that individual detector failures do not halt runtime execution.
    """
    
    def __init__(self, detectors: Optional[List[BaseDetector]] = None):
        self._detectors: List[BaseDetector] = detectors or []
        self._logger = logging.getLogger("runtimeverify.runtime.dispatcher")

    def register_detector(self, detector: BaseDetector) -> None:
        """Adds a detector to the active evaluation list."""
        self._detectors.append(detector)

    def dispatch(self, state: ExecutionState) -> Dict[str, DetectorResult]:
        """
        Dispatches the ExecutionState to all active detectors concurrently.
        Catches exceptions to isolate failures and yields default/degraded results.
        """
        results: Dict[str, DetectorResult] = {}
        
        for detector in self._detectors:
            metadata = detector.metadata()
            name = metadata.name
            
            # Skip if detector doesn't support this category
            if metadata.supported_categories and state.category.value not in metadata.supported_categories:
                continue

            try:
                # Online streaming inference
                results[name] = detector.observe(state)
            except Exception as e:
                self._logger.error(
                    f"Fault isolated: detector '{name}' threw an exception during observe(): {e}", 
                    exc_info=True
                )
                # Graceful degradation fallback payload
                fallback_explanation = DetectorExplanation(
                    detector_name=name,
                    summary=f"Detector execution failed: {e}",
                    evidence={"error_class": e.__class__.__name__, "message": str(e)},
                )
                results[name] = DetectorResult(
                    deviation_score=0.0,
                    confidence=0.0,
                    decision="PENDING",
                    explanation=fallback_explanation,
                    raw_metrics={"failed": True, "error": str(e)}
                )
                
        return results

    def reset_detectors(self) -> None:
        """Invokes reset on all registered detectors to clear session counters."""
        for detector in self._detectors:
            try:
                detector.reset()
            except Exception as e:
                self._logger.error(f"Failed to reset detector '{detector.metadata().name}': {e}")
