"""
Data models and typed schemas for semantic decision engines in RuntimeVerify.
Defines risk classifications, decision signals, engine configurations, and output payloads.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskClassification(str, Enum):
    """
    Standardized semantic risk levels produced by decision engines.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        """Numeric rank for severity comparison (higher = higher risk)."""
        ranks = {
            RiskClassification.LOW: 1,
            RiskClassification.MEDIUM: 2,
            RiskClassification.HIGH: 3,
            RiskClassification.CRITICAL: 4,
            RiskClassification.UNKNOWN: 0,
        }
        return ranks.get(self, 0)


class DecisionSignalType(str, Enum):
    """
    Actionable semantic decision signals emitted by an engine.
    """

    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    NEUTRAL = "NEUTRAL"


class DecisionSignal(BaseModel):
    """
    Immutable structured evaluation result returned by a DecisionEngine.
    Provides explainable semantic risk assessment without directly overriding hard policies.
    """

    model_config = ConfigDict(frozen=True)

    engine_name: str = Field(..., description="Identifier of the producing engine (e.g. 'laya', 'null')")
    action_category: Optional[str] = Field(None, description="Identified semantic category of the action")
    risk_level: RiskClassification = Field(
        RiskClassification.UNKNOWN, description="Assessed semantic risk classification"
    )
    confidence: float = Field(
        0.0,
        description="Calibrated confidence score normalized between 0.0 and 1.0",
    )
    decision_signal: DecisionSignalType = Field(
        DecisionSignalType.NEUTRAL,
        description="Recommended decision signal (ALLOW, REVIEW, BLOCK, NEUTRAL)",
    )
    explanation: Optional[str] = Field(None, description="Human-readable explanation of why this signal was produced")
    raw_scores: Dict[str, Any] = Field(
        default_factory=dict, description="Raw outputs, scores, or distribution from the underlying model"
    )
    latency_ms: float = Field(0.0, ge=0.0, description="Inference latency in milliseconds")
    fallback: bool = Field(False, description="Whether this signal is a fallback resulting from error or timeout")
    error: Optional[str] = Field(None, description="Error message if a failure occurred during evaluation")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Engine-specific execution metadata (e.g. routed checkpoint)"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the semantic decision signal",
    )

    @field_validator("confidence", mode="before")
    @classmethod
    def validate_confidence(cls, v: Any) -> float:
        """Ensures confidence remains strictly bounded to [0.0, 1.0]."""
        try:
            val = float(v)
            return max(0.0, min(1.0, val))
        except (ValueError, TypeError):
            return 0.0


class SemanticEngineConfig(BaseModel):
    """
    Configuration options for semantic decision engines.
    """

    model_config = ConfigDict(frozen=True)

    enabled: bool = Field(False, description="Whether semantic evaluation is active in the interception pipeline")
    provider: str = Field("null", description="Provider identifier (e.g. 'laya', 'null', 'mock')")
    timeout_ms: float = Field(
        50.0, gt=0.0, description="Maximum execution timeout in milliseconds before triggering fallback"
    )
    model_name: Optional[str] = Field(
        "english", description="Model checkpoint name or router default (e.g. 'english', 'multilingual')"
    )
    device: Optional[str] = Field(None, description="Target execution device (e.g. 'cpu', 'cuda', 'mps', 'xpu')")
    preload: bool = Field(False, description="Whether to preload model checkpoints up front on startup")
    block_risk_threshold: RiskClassification = Field(
        RiskClassification.CRITICAL,
        description="Minimum risk level required to emit a BLOCK decision signal",
    )
    review_risk_threshold: RiskClassification = Field(
        RiskClassification.HIGH,
        description="Minimum risk level required to emit a REVIEW decision signal",
    )
    min_confidence_threshold: float = Field(
        0.60,
        ge=0.0,
        le=1.0,
        description="Minimum confidence required for a risk signal to trigger escalation",
    )
    escalate_on_critical: bool = Field(
        True, description="Whether CRITICAL risk signals escalate deterministic ALLOW to BLOCK"
    )
    escalate_on_high: bool = Field(True, description="Whether HIGH risk signals escalate deterministic ALLOW to REVIEW")
    extra_params: Dict[str, Any] = Field(default_factory=dict, description="Provider-specific configuration arguments")
