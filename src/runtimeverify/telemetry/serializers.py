import json
from typing import Dict, Type
from runtimeverify.events import (
    Event,
    ToolEvent,
    LLMEvent,
    MemoryEvent,
    FilesystemEvent,
    NetworkEvent,
    CanonicalEvent,
    LLMRequestEvent,
    LLMResponseEvent,
    ToolCallEvent,
    ToolResultEvent,
    FilesystemReadEvent,
    FilesystemWriteEvent,
    FilesystemDeleteEvent,
    ShellCommandEvent,
    NetworkRequestEvent,
    GitOperationEvent,
    CredentialAccessEvent,
    ProcessCreationEvent,
    AgentCommunicationEvent,
    HumanApprovalEvent,
    PolicyDecisionEvent,
)


class EventSerializer:
    """
    Utility class to serialize Event models to JSON and deserialize
    JSON strings back into their respective specific Event subclasses.
    """

    _TYPE_MAP: Dict[str, Type[Event]] = {
        # Legacy event types
        "generic": Event,
        "span": Event,
        "tool": ToolEvent,
        "llm": LLMEvent,
        "memory": MemoryEvent,
        "filesystem": FilesystemEvent,
        "network": NetworkEvent,
        # Canonical event types
        "canonical": CanonicalEvent,
        "llm.request": LLMRequestEvent,
        "llm.response": LLMResponseEvent,
        "tool.call": ToolCallEvent,
        "tool.result": ToolResultEvent,
        "filesystem.read": FilesystemReadEvent,
        "filesystem.write": FilesystemWriteEvent,
        "filesystem.delete": FilesystemDeleteEvent,
        "shell.command": ShellCommandEvent,
        "network.request": NetworkRequestEvent,
        "git.operation": GitOperationEvent,
        "credential.access": CredentialAccessEvent,
        "process.creation": ProcessCreationEvent,
        "agent.communication": AgentCommunicationEvent,
        "human.approval": HumanApprovalEvent,
        "policy.decision": PolicyDecisionEvent,
    }

    @classmethod
    def serialize(cls, event: Event) -> str:
        """Serializes an Event instance to a JSON string."""
        return event.model_dump_json(by_alias=False)

    @classmethod
    def deserialize(cls, json_str: str) -> Event:
        """
        Deserializes a JSON string into the matching specialized Event subclass
        by inspecting the 'event_type' or 'type' attribute.
        """
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON string format: {e}")

        event_type = data.get("event_type") or data.get("type", "generic")
        target_class = cls._TYPE_MAP.get(event_type, Event)
        return target_class.model_validate(data)
