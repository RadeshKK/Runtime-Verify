import json
from typing import Dict, Type
from runtimeverify.events import (
    Event,
    ToolEvent,
    LLMEvent,
    MemoryEvent,
    FilesystemEvent,
    NetworkEvent,
)

class EventSerializer:
    """
    Utility class to serialize Event models to JSON and deserialize 
    JSON strings back into their respective specific Event subclasses.
    """
    
    _TYPE_MAP: Dict[str, Type[Event]] = {
        "generic": Event,
        "span": Event,
        "tool": ToolEvent,
        "llm": LLMEvent,
        "memory": MemoryEvent,
        "filesystem": FilesystemEvent,
        "network": NetworkEvent,
    }

    @classmethod
    def serialize(cls, event: Event) -> str:
        """Serializes an Event instance to a JSON string."""
        return event.model_dump_json()

    @classmethod
    def deserialize(cls, json_str: str) -> Event:
        """
        Deserializes a JSON string into the matching specialized Event subclass 
        by inspecting the 'type' attribute.
        """
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON string format: {e}")
            
        event_type = data.get("type", "generic")
        target_class = cls._TYPE_MAP.get(event_type, Event)
        return target_class.model_validate(data)
