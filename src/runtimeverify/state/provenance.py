from typing import Any, Optional, Dict
from pydantic import BaseModel, Field, ConfigDict


class StateProvenance(BaseModel):
    """
    Provenance tracking information for an ExecutionState.
    Captures why and how a state was determined, aiding in false positive debug loops.
    """

    model_config = ConfigDict(frozen=True)

    generated_by: str = Field(
        ...,
        description="The generator/rule/model name that produced this state (e.g., 'Rule:filesystem.system_secret')",
    )
    confidence: float = Field(
        default=1.0, description="The confidence score of the classifier/rule matching (0.0 to 1.0)"
    )
    evidence: Optional[Any] = Field(
        None, description="The specific telemetry event content or trigger that acted as evidence"
    )
    extra: Dict[str, Any] = Field(default_factory=dict, description="Additional debug or tracking info")
