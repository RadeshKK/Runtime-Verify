from datetime import datetime, timezone
from typing import Dict, Any
import uuid
from pydantic import BaseModel, Field, ConfigDict

class Event(BaseModel):
    """
    Base Event model representing any observed action or trace point in the agent lifecycle.
    This model is immutable (frozen) to ensure integrity of runtime telemetry.
    """
    model_config = ConfigDict(
        frozen=True,
        json_schema_extra={
            "examples": [
                {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "timestamp": "2026-07-19T19:05:42Z",
                    "session_id": "session_123",
                    "agent_id": "math_expert",
                    "type": "generic",
                    "metadata": {"version": "1.0"}
                }
            ]
        }
    )

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique identifier for the event")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of event occurrence in UTC"
    )
    session_id: str = Field(..., description="Unique identifier for the agent session or trace trace_id")
    agent_id: str = Field(..., description="Identifier for the agent or component emitting this event")
    type: str = Field("generic", description="Discriminator/type name of the event")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary user-defined context metadata")
