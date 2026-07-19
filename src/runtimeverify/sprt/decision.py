from typing import Literal, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class SPRTDecision(BaseModel):
    """Immutable output object representing the decision state at step t."""
    model_config = ConfigDict(frozen=True)

    status: Literal["ACCEPT_H0", "ACCEPT_H1", "PENDING"] = Field(..., description="The resolved hypothesis state")
    log_likelihood_ratio: float = Field(..., description="Cumulative LLR value (Lambda_t)")
    lower_threshold: float = Field(..., description="Wald boundary A")
    upper_threshold: float = Field(..., description="Wald boundary B")
    observation_count: int = Field(..., description="Number of observed transitions in current session")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic state transitions triggering the LLR update")
