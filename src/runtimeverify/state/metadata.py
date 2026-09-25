from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class StateMetadata(BaseModel):
    """
    Immutable metadata associated with an ExecutionState.
    Captures operational metrics, risk assessments, and required access permissions.
    """

    model_config = ConfigDict(frozen=True)

    permission_level: Optional[str] = Field(
        None, description="The permission level needed for execution (e.g. read, write, root)"
    )
    risk_level: str = Field("low", description="Safety/Risk evaluation rating: low, medium, high, critical")
    extra: Dict[str, Any] = Field(default_factory=dict, description="Custom metadata attributes")
