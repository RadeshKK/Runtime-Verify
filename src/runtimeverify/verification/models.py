"""
Data models and typed schemas for the Hybrid Runtime Verification Engine (Phase 6).
Provides structured Evidence, DecisionExplanation, VerificationResult, and configurable thresholds.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from runtimeverify.policy.models import PolicyDecision
from runtimeverify.semantic.models import DecisionSignal


class EvidenceType(str, Enum):
    """
    Categorical taxonomy of verification evidence sources.
    """

    DETERMINISTIC_POLICY = "DETERMINISTIC_POLICY"
    SEMANTIC_SIGNAL = "SEMANTIC_SIGNAL"
    BEHAVIORAL_TRANSITION = "BEHAVIORAL_TRANSITION"
    SPRT_DRIFT = "SPRT_DRIFT"
    ENVIRONMENT_CONTEXT = "ENVIRONMENT_CONTEXT"
    ANOMALY_DETECTION = "ANOMALY_DETECTION"


class Evidence(BaseModel):
    """
    Immutable evidentiary artifact produced by an underlying engine or evaluation subsystem.
    """

    model_config = ConfigDict(frozen=True)

    source: EvidenceType = Field(..., description="Engine or subsystem generating this evidence")
    source_name: str = Field(
        ..., description="Component identifier (e.g. 'policy_evaluator', 'laya', 'markov', 'sprt')"
    )
    severity: str = Field("INFO", description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    title: str = Field(..., description="Concise summary title of the evidence")
    description: str = Field(..., description="Detailed description of the observation")
    data: Dict[str, Any] = Field(default_factory=dict, description="Structured metrics, rule matches, or parameters")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DecisionExplanation(BaseModel):
    """
    Detailed explainability report answering the 5 mandatory audit questions:
    - WHAT happened
    - WHY it was suspicious
    - WHICH controls triggered
    - WHETHER the behavior deviated from baseline
    - WHAT action was taken
    """

    model_config = ConfigDict(frozen=True)

    what_happened: str = Field(..., description="Summary of the action or event observed")
    why_suspicious: Optional[str] = Field(
        None, description="Detailed explanation of why the action was flagged or blocked"
    )
    which_controls_triggered: List[str] = Field(
        default_factory=list, description="Identifiers of policies, models, or statistical tests that triggered"
    )
    behavioral_deviation: bool = Field(
        False, description="Whether the action deviated statistically from the Markov/SPRT baseline"
    )
    action_taken: str = Field(..., description="Action taken: EXECUTE, HOLD_FOR_APPROVAL, BLOCK")
    summary: str = Field(..., description="High-level human-readable verdict summary")


class VerificationResult(BaseModel):
    """
    Comprehensive structured outcome produced by the VerificationEngine.
    Integrates policy evaluation, semantic classification, and statistical verification.
    """

    model_config = ConfigDict(frozen=True)

    verification_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    decision: str = Field(..., description="Synthesized verdict: ALLOW, REVIEW, or BLOCK")
    risk_level: str = Field(..., description="Assessed overall risk rating: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Calibrated confidence score normalized to [0.0, 1.0]")
    reason: str = Field(..., description="Primary explanatory reason for the decision")
    explanation: DecisionExplanation = Field(..., description="Structured 5-question explainability breakdown")

    evidence: List[Evidence] = Field(default_factory=list, description="Aggregated list of all evidentiary records")
    policy_matches: List[Dict[str, Any]] = Field(
        default_factory=list, description="Details of matched deterministic policy rules"
    )
    behavioral_evidence: Optional[Dict[str, Any]] = Field(
        None, description="Markov transition and SPRT statistical evidence"
    )
    semantic_evidence: Optional[Dict[str, Any]] = Field(None, description="Semantic classification and intent scores")
    policy_decision: Optional[PolicyDecision] = Field(
        None, description="Underlying deterministic policy decision if evaluated"
    )
    semantic_signal: Optional[DecisionSignal] = Field(None, description="Underlying semantic signal if evaluated")

    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    environment: Optional[str] = None
    action_type: Optional[str] = None
    target: Optional[str] = None
    latency_ms: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VerificationEngineConfig(BaseModel):
    """
    Configurable parameters and explicit thresholds for the hybrid verification engine.
    Ensures complete transparency with no arbitrary magic constants.
    """

    model_config = ConfigDict(frozen=True)

    # Policy controls
    policy_block_enabled: bool = Field(True, description="Enforce deterministic policy BLOCK decisions")
    policy_review_enabled: bool = Field(True, description="Enforce deterministic policy REVIEW decisions")

    # Semantic thresholds
    semantic_min_confidence: float = Field(
        0.60, ge=0.0, le=1.0, description="Minimum confidence for semantic signal to trigger escalation"
    )
    semantic_critical_escalates_to: str = Field(
        "BLOCK", description="Target decision for semantic CRITICAL risk (BLOCK or REVIEW)"
    )
    semantic_high_escalates_to: str = Field(
        "REVIEW", description="Target decision for semantic HIGH risk (BLOCK or REVIEW)"
    )
    semantic_noul_review_threshold: float = Field(
        0.75, ge=0.0, le=1.0, description="Probability threshold on noul questions for review escalation"
    )

    # Behavioral (Markov) thresholds
    markov_anomaly_prob_threshold: float = Field(
        1e-4, gt=0.0, description="Transition probability below which a transition is flagged anomalous"
    )
    markov_anomaly_escalates_to: str = Field(
        "REVIEW", description="Target decision for single-transition Markov anomalies"
    )

    # SPRT thresholds
    sprt_drift_escalates_to: str = Field(
        "REVIEW", description="Target decision when SPRT accumulator rejects H0 (drift detected)"
    )
    sprt_alpha: float = Field(0.05, gt=0.0, lt=1.0, description="SPRT Type I error rate")
    sprt_beta: float = Field(0.05, gt=0.0, lt=1.0, description="SPRT Type II error rate")

    # Multi-signal correlation
    combined_risk_escalation: bool = Field(
        True, description="Escalate to REVIEW if both semantic and behavioral indicate elevated risk"
    )

    # Engine safety
    fail_closed: bool = Field(
        True, description="Fail closed (flag REVIEW or BLOCK) on unrecoverable subsystem failures in enforcement"
    )
