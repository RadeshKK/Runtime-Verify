from typing import Dict, Any
from runtimeverify.events import (
    Event,
    ToolEvent,
    LLMEvent,
    MemoryEvent,
    FilesystemEvent,
    NetworkEvent,
    CanonicalEvent,
)
from runtimeverify.encoder.base import TelemetryNormalizer


class DefaultTelemetryNormalizer(TelemetryNormalizer):
    """
    Standard normalizer that takes typed Events and projects them
    into a standardized mapping of action, resource target, and properties.
    """

    def normalize(self, event: Event) -> Dict[str, Any]:
        normalized: Dict[str, Any] = {
            "event_id": event.id,
            "session_id": event.session_id,
            "agent_id": event.agent_id,
            "timestamp": event.timestamp,
            "type": event.type,
            "resource": getattr(event, "target", None),
            "action": getattr(event, "action", "unknown") or "unknown",
            "metadata": event.metadata.copy(),
        }

        if isinstance(event, CanonicalEvent):
            if event.target:
                normalized["resource"] = event.target
            if event.action:
                normalized["action"] = event.action
            if event.payload:
                normalized["metadata"].update(event.payload)
        elif isinstance(event, ToolEvent):
            normalized["action"] = f"tool_{event.status}"
            normalized["resource"] = event.tool_name
            normalized["metadata"].update(
                {
                    "arguments": event.arguments,
                    "output": event.output,
                    "duration_ms": event.duration_ms,
                }
            )
        elif isinstance(event, FilesystemEvent):
            normalized["action"] = event.action
            normalized["resource"] = event.path
            normalized["metadata"].update(
                {
                    "content_hash": event.content_hash,
                    "bytes_transferred": event.bytes_transferred,
                }
            )
        elif isinstance(event, NetworkEvent):
            normalized["action"] = event.action
            normalized["resource"] = event.url
            normalized["metadata"].update(
                {
                    "method": event.method,
                    "status_code": event.status_code,
                    "duration_ms": event.duration_ms,
                }
            )
        elif isinstance(event, LLMEvent):
            normalized["action"] = "generate"
            normalized["resource"] = event.model
            normalized["metadata"].update(
                {
                    "prompt_tokens": event.prompt_tokens,
                    "completion_tokens": event.completion_tokens,
                    "total_tokens": event.total_tokens,
                }
            )
        elif isinstance(event, MemoryEvent):
            normalized["action"] = event.action
            normalized["resource"] = event.key
            normalized["metadata"].update(
                {
                    "store_name": event.store_name,
                }
            )

        return normalized
