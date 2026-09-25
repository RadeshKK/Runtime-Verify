from typing import Callable, Dict, Set, Protocol, runtime_checkable, Optional
from runtimeverify.events.base import Event


@runtime_checkable
class EventListener(Protocol):
    """Protocol for event bus listeners."""

    def __call__(self, event: Event) -> None: ...


class EventBus:
    """
    In-process, thread-safe Event Bus that decouples event generators (collectors)
    from downstream consumers (detectors, metric systems, dashboards).
    """

    def __init__(self):
        self._listeners: Dict[str, Set[Callable[[Event], None]]] = {}
        self._global_listeners: Set[Callable[[Event], None]] = set()

    def subscribe(self, listener: Callable[[Event], None], event_type: Optional[str] = None) -> None:
        """
        Subscribes a listener callback to events.

        Args:
            listener: Callback function taking an Event.
            event_type: If provided, only events matching this type are sent.
                         If None, the listener receives all events.
        """
        if event_type is None:
            self._global_listeners.add(listener)
        else:
            if event_type not in self._listeners:
                self._listeners[event_type] = set()
            self._listeners[event_type].add(listener)

    def unsubscribe(self, listener: Callable[[Event], None], event_type: Optional[str] = None) -> None:
        """Unsubscribes a listener callback from the event bus."""
        if event_type is None:
            self._global_listeners.discard(listener)
        else:
            if event_type in self._listeners:
                self._listeners[event_type].discard(listener)

    def publish(self, event: Event) -> None:
        """
        Publishes an event to all registered listeners.

        Args:
            event: The Event instance to publish.
        """
        # Publish to global listeners
        for listener in list(self._global_listeners):
            try:
                listener(event)
            except Exception:
                # In production, log error to prevent subscriber failure from stopping execution.
                pass

        # Publish to type-specific listeners
        if event.type in self._listeners:
            for listener in list(self._listeners[event.type]):
                try:
                    listener(event)
                except Exception:
                    pass
