from typing import Dict, List
from runtimeverify.detector.base import BaseDetector


class DetectorRegistry:
    """Registry managing available statistical detectors."""

    def __init__(self):
        self._detectors: Dict[str, BaseDetector] = {}

    def register(self, name: str, detector: BaseDetector) -> None:
        self._detectors[name.lower()] = detector

    def get(self, name: str) -> BaseDetector:
        key = name.lower()
        if key not in self._detectors:
            raise KeyError(f"Detector '{name}' is not registered.")
        return self._detectors[key]

    def list_detectors(self) -> List[str]:
        return list(self._detectors.keys())

    def clear(self) -> None:
        self._detectors.clear()
