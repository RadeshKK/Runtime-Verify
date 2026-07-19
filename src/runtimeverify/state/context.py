from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict

class StateContext(BaseModel):
    """
    Identifies the context of execution context in which the semantic state occurred.
    Differentiates identical tools executing in different situations (e.g. user folder vs system folder).
    """
    model_config = ConfigDict(frozen=True)
    
    resource_id: Optional[str] = Field(None, description="The resource ID involved, e.g. a filename, database table name, or network IP")
    resource_type: Optional[str] = Field(None, description="The type classification of the resource (e.g., config, script, sensitive_file)")
    agent_id: str = Field(..., description="The ID of the agent associated with this state")
    session_id: str = Field(..., description="The ID of the trace/session associated with this state")
    previous_state_id: Optional[str] = Field(None, description="Reference ID to the preceding ExecutionState in the trace")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), 
        description="Timestamp indicating when the state was instantiated"
    )
