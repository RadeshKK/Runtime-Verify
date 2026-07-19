from abc import ABC, abstractmethod
from typing import Dict, Any
from runtimeverify.events.base import Event
from runtimeverify.state.execution import ExecutionState

class BaseEncoder(ABC):
    """Abstract interface defining the encoder contract."""
    
    @abstractmethod
    def encode(self, event: Event) -> ExecutionState:
        """
        Transforms a telemetry Event into an immutable ExecutionState.
        
        Args:
            event: The observed raw Event instance.
            
        Returns:
            An ExecutionState representing the semantic meaning of the event.
        """
        pass

class TelemetryNormalizer(ABC):
    """Abstract interface for standardizing telemetry events into standard maps."""
    
    @abstractmethod
    def normalize(self, event: Event) -> Dict[str, Any]:
        """Normalizes framework-specific attributes into a standardized schema."""
        pass

class ResourceClassifier(ABC):
    """Abstract interface for classifying resource types, access risks, and requirements."""
    
    @abstractmethod
    def classify(self, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
        """Categorizes resource types and actions."""
        pass

class ContextEnricher(ABC):
    """Abstract interface for incorporating trace history and context into event properties."""
    
    @abstractmethod
    def enrich(self, classified_event: Dict[str, Any], history: list) -> Dict[str, Any]:
        """Enriches the event classification with history and surrounding context."""
        pass

class RuleEngine(ABC):
    """Abstract interface for determining final semantic state names from enriched events."""
    
    @abstractmethod
    def evaluate(self, enriched_event: Dict[str, Any]) -> str:
        """Determines the semantic state name using rules."""
        pass
