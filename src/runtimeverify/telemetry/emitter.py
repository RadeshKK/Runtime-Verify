from abc import ABC, abstractmethod
from runtimeverify.events.base import Event
from runtimeverify.telemetry.bus import EventBus

class TelemetryEmitter(ABC):
    """Abstract interface defining the event emitter contract."""
    
    @abstractmethod
    def emit(self, event: Event) -> None:
        """
        Emits a structured event to downstream consumers.
        
        Args:
            event: The Event instance to transmit.
        """
        pass

class EventBusEmitter(TelemetryEmitter):
    """Concrete emitter that publishes events onto an in-process EventBus."""
    
    def __init__(self, event_bus: EventBus):
        self._bus = event_bus

    def emit(self, event: Event) -> None:
        self._bus.publish(event)

class NoOpEmitter(TelemetryEmitter):
    """Emitter implementation that discards all events."""
    
    def emit(self, event: Event) -> None:
        pass
