from typing import Dict, Any, Literal
from pydantic import BaseModel, Field, ConfigDict

class DetectorExplanation(BaseModel):
    """Structured explainability payload detail for auditing alerts."""
    model_config = ConfigDict(frozen=True)

    detector_name: str = Field(..., description="Name of the detector that generated this alert")
    summary: str = Field(..., description="Human-readable explanation of why this decision was reached")
    evidence: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Observed data points, rare transitions, or parameters acting as evidence"
    )
    reference_distribution: Dict[str, Any] = Field(
        default_factory=dict, 
        description="The normal/baseline distribution comparison (e.g. expected transition probabilities)"
    )


class DetectorResult(BaseModel):
    """Standardized output wrapper returned by all detectors on every state observation."""
    model_config = ConfigDict(frozen=True)

    deviation_score: float = Field(
        ..., 
        description="Numerical metric indicating the degree of deviation"
    )
    confidence: float = Field(
        default=1.0, 
        ge=0.0, 
        le=1.0, 
        description="Statistical confidence score or power (from 0.0 to 1.0)"
    )
    decision: Literal["NORMAL", "SUSPICIOUS", "ANOMALY", "PENDING"] = Field(
        ..., 
        description="Categorical decision classification resolved by the detector"
    )
    explanation: DetectorExplanation = Field(
        ..., 
        description="Detailed explainability payload backing the decision"
    )
    raw_metrics: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Detector-specific raw statistics for debugging or metrics collection"
    )
