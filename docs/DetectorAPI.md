# Detector Engine API

The `detector` module analyzes state transitions and detects violations of target properties.

## Core Detector Interface

Any detector implementation must inherit from the base `BaseDetector` class and implement the following interface:

```python
class BaseDetector(ABC):
    
    @abstractmethod
    def reset(self) -> None:
        """Reset the detector state to its initial configuration."""
        pass

    @abstractmethod
    def feed(self, encoded_state: Dict[str, Any]) -> DetectionResult:
        """
        Process the latest state vector or event.
        Returns a DetectionResult object indicating any property violations.
        """
        pass
```

## DetectionResult Structure

```python
class DetectionResult:
    violation_detected: bool
    property_id: str
    severity: str  # "INFO", "WARNING", "CRITICAL"
    context: Dict[str, Any]
```

## Built-in Detectors

1. **FinitesStateMachineDetector**: Validates paths against allowed/forbidden state transitions.
2. **LTLDetector**: Checks properties defined in Linear Temporal Logic (e.g., "Event A must eventually be followed by Event B before Event C").
3. **ThresholdDetector**: Simple statistical limits on event counts or state variables over time windows.
