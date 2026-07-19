from typing import Optional
from runtimeverify.telemetry.bus import EventBus
from runtimeverify.telemetry.emitter import TelemetryEmitter, EventBusEmitter
from runtimeverify.telemetry.collector import TelemetryCollector, DefaultTelemetryCollector

class TelemetryManager:
    """
    Coordinator class for the Telemetry SDK. Holds the active EventBus, Emitter, 
    and Collector, and acts as the runtime configuration point.
    """
    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        emitter: Optional[TelemetryEmitter] = None,
        collector: Optional[TelemetryCollector] = None,
    ):
        self.bus = event_bus or EventBus()
        self.emitter = emitter or EventBusEmitter(self.bus)
        self.collector = collector or DefaultTelemetryCollector(self.emitter)

# Global TelemetryManager singleton reference
_GLOBAL_MANAGER: Optional[TelemetryManager] = None

def get_global_manager() -> TelemetryManager:
    """Retrieves the global TelemetryManager singleton. Initializes one if missing."""
    global _GLOBAL_MANAGER
    if _GLOBAL_MANAGER is None:
        _GLOBAL_MANAGER = TelemetryManager()
    return _GLOBAL_MANAGER

def set_global_manager(manager: TelemetryManager) -> None:
    """Sets/overrides the global TelemetryManager instance."""
    global _GLOBAL_MANAGER
    _GLOBAL_MANAGER = manager
