from typing import Dict, Any, List
from pydantic import BaseModel, Field


class MappingContext(BaseModel):
    """
    Represents the operational context during encoding, tracking
    historical states and active variables in the session.
    """

    history: List[str] = Field(default_factory=list, description="Sequence of previous state names in this session")
    variables: Dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary variables cached for context propagation"
    )
