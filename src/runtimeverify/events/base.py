from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
import json
from pydantic import BaseModel, Field, ConfigDict, field_validator
from runtimeverify.events.context import EventContext


class Event(BaseModel):
    """
    Base Event model representing any observed action or trace point in the agent lifecycle.
    This model is immutable (frozen) to ensure the integrity of runtime telemetry.

    Supports the canonical fields:
      - schema_version
      - id / event_id: Unique UUID4 string
      - timestamp: UTC localized datetime
      - session_id: Mandatory session/trace identifier
      - trace_id: Distributed correlation trace identifier
      - span_id: Span identifier
      - parent_event_id: Causal parent event identifier
      - agent_id: Emitting agent identifier
      - agent_type: Archetype of the agent
      - type / event_type: Canonical event type
      - action: Canonical action verb
      - target: Target resource or entity
      - source: Event originator
      - environment: Execution tier
      - context: Structured EventContext
      - metadata: Extensible key-value metadata
    """

    model_config = ConfigDict(
        frozen=True,
        populate_by_name=True,
        extra="allow",
        json_schema_extra={
            "examples": [
                {
                    "schema_version": "1.0",
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "event_id": "550e8400-e29b-41d4-a716-446655440000",
                    "timestamp": "2026-07-19T19:05:42Z",
                    "session_id": "session_123",
                    "agent_id": "math_expert",
                    "agent_type": "worker",
                    "type": "generic",
                    "event_type": "generic",
                    "action": "execute",
                    "target": "calculator",
                    "source": "agent",
                    "environment": "production",
                    "context": {"current_directory": "/workspace"},
                    "metadata": {"version": "1.0"},
                }
            ]
        },
    )

    schema_version: str = Field(default="1.0", description="Canonical event schema version")
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        alias="event_id",
        description="Unique identifier for the event (UUID4 default)",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of event occurrence in UTC"
    )
    session_id: str = Field(..., min_length=1, description="Unique identifier for the agent session or trace boundary")
    trace_id: Optional[str] = Field(default=None, description="Distributed correlation trace identifier")
    span_id: Optional[str] = Field(default=None, description="Span identifier within the trace")
    parent_event_id: Optional[str] = Field(default=None, description="Identifier of the causal parent event")
    agent_id: str = Field(..., min_length=1, description="Identifier for the agent or component emitting this event")
    agent_type: Optional[str] = Field(default=None, description="Role or classification archetype of the agent")
    # Multi-agent representation (Phase 17)
    parent_agent: Optional[str] = Field(
        default=None, alias="parent_agent_id", description="Parent delegating agent identifier"
    )
    agent_role: Optional[str] = Field(default=None, description="Operational role archetype of the agent")
    target_agent: Optional[str] = Field(
        default=None, alias="target_agent_id", description="Recipient or target agent identifier"
    )
    target_agent_role: Optional[str] = Field(default=None, description="Operational role of the target agent")
    delegation_depth: int = Field(default=0, ge=0, description="Hierarchical delegation nesting depth")
    call_chain: List[str] = Field(
        default_factory=list, description="Lineage sequence of agent IDs leading to this event"
    )
    type: str = Field("generic", alias="event_type", description="Discriminator/type name of the event")
    action: Optional[str] = Field(default=None, description="Specific action executed")
    target: Optional[str] = Field(default=None, description="Target resource or entity involved")
    source: str = Field(default="agent", description="Subsystem or actor originating the event")
    environment: str = Field(default="production", description="Runtime execution tier")
    context: EventContext = Field(
        default_factory=EventContext, description="Structured environment and execution context"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary user-defined context metadata")

    @field_validator("timestamp")
    @classmethod
    def ensure_utc_timestamp(cls, v: datetime) -> datetime:
        """Enforces that timestamps are timezone-aware UTC."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @property
    def event_id(self) -> str:
        """Canonical accessor for event_id."""
        return self.id

    @property
    def event_type(self) -> str:
        """Canonical accessor for event type."""
        return self.type

    @property
    def parent_agent_id(self) -> Optional[str]:
        """Canonical accessor for parent agent ID."""
        return self.parent_agent

    @property
    def target_agent_id(self) -> Optional[str]:
        """Canonical accessor for target agent ID."""
        return self.target_agent

    @property
    def role(self) -> Optional[str]:
        """Canonical accessor for agent role or type archetype."""
        return self.agent_role or self.agent_type

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the event model to a standard dictionary with both canonical and legacy field aliases."""
        data = self.model_dump()
        data["event_id"] = self.event_id
        data["event_type"] = self.event_type
        data["parent_agent_id"] = self.parent_agent_id
        data["target_agent_id"] = self.target_agent_id
        data["parent_agent"] = self.parent_agent
        data["target_agent"] = self.target_agent
        data["agent_role"] = self.role
        return data

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serializes the event model to a canonical JSON string."""
        return json.dumps(self.to_dict(), default=str, indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        """Deserializes a dictionary into an Event instance."""
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, json_str: str) -> "Event":
        """Deserializes a JSON string into an Event instance."""
        data = json.loads(json_str)
        return cls.model_validate(data)
