"""
Data models for the RuntimeVerify Attack / Agent Replay Engine.
Defines step-by-step verification results, layer telemetry, summary statistics,
and what-if policy comparison diffs.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ReplayStep(BaseModel):
    """
    Detailed telemetry and multi-layer verification verdict for an individual trace step.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    step_number: int = Field(..., description="1-indexed sequence order of this step in the trace")
    timestamp: Optional[datetime] = Field(None, description="Recorded timestamp of the original action")
    action_type: str = Field(..., description="Action category (shell, filesystem, network, process, git, etc.)")
    name: str = Field(..., description="Action verb/operation (e.g. read, write, execute, connect)")
    target: str = Field(..., description="Target resource (command, path, URL, branch)")
    params: Dict[str, Any] = Field(default_factory=dict, description="Raw action parameters")
    
    # Layer 1: Deterministic Policy
    policy_verdict: str = Field("ALLOW", description="ALLOW, REVIEW, or BLOCK from policy engine")
    policy_id: Optional[str] = Field(None, description="ID of triggered policy rule if any")
    policy_reason: Optional[str] = Field(None, description="Policy rule rationale")

    # Layer 2: Laya / Semantic Risk Classification
    semantic_verdict: str = Field("SAFE", description="SAFE, SUSPICIOUS, or CRITICAL from semantic classifier")
    semantic_category: Optional[str] = Field(None, description="Inferred semantic intent category")
    semantic_confidence: float = Field(1.0, description="Confidence score of semantic analysis [0.0 - 1.0]")
    semantic_explanation: Optional[str] = Field(None, description="Laya semantic risk reasoning")

    # Layer 3: Markov Behavioral Model & Sequential SPRT
    markov_state: Optional[str] = Field(None, description="Abstract behavioral state token (e.g. FILE_READ)")
    markov_probability: Optional[float] = Field(None, description="Estimated transition probability P(S_t | S_{t-1})")
    sprt_status: Optional[str] = Field(None, description="SPRT accumulator state: PENDING, ACCEPT_H0, or ACCEPT_H1")
    sprt_llr: Optional[float] = Field(None, description="Cumulative Wald log-likelihood ratio")
    sprt_observation_count: int = Field(0, description="Cumulative steps monitored by SPRT in this session")

    # Unified Synthesis Verdict
    final_verdict: str = Field(..., description="Synthesized decision: ALLOW, REVIEW, or BLOCK")
    risk_level: str = Field("LOW", description="Synthesized risk level: LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(1.0, description="Synthesized confidence score")
    reason: str = Field(..., description="Primary justification for the synthesized verdict")
    latency_ms: float = Field(0.0, description="Verification latency overhead in milliseconds")

    # What-If Policy Comparison (optional)
    comparison_verdict: Optional[str] = Field(None, description="Alternate policy verdict for what-if evaluation")
    comparison_reason: Optional[str] = Field(None, description="Alternate policy rationale")
    verdict_diverged: bool = Field(False, description="True if baseline and comparison policies reached different decisions")


class ReplaySummary(BaseModel):
    """
    Aggregated statistical summary of an entire replayed agent trace session.
    """

    total_steps: int = Field(0, description="Total number of steps evaluated")
    allowed_steps: int = Field(0, description="Count of steps evaluated as ALLOW")
    reviewed_steps: int = Field(0, description="Count of steps requiring human REVIEW")
    blocked_steps: int = Field(0, description="Count of steps actively BLOCKED")
    
    overall_verdict: str = Field("ALLOW", description="Overall session verdict (BLOCK if any blocked, else REVIEW if any reviewed, else ALLOW)")
    first_intervention_step: Optional[int] = Field(None, description="Step number of the first non-ALLOW verdict")
    first_intervention_layer: Optional[str] = Field(None, description="Security layer responsible for the first intervention (Policy, Laya, Markov, SPRT)")
    first_intervention_reason: Optional[str] = Field(None, description="Rationale behind the first intervention")

    policy_triggers_count: int = Field(0, description="Number of times deterministic policies triggered")
    semantic_flags_count: int = Field(0, description="Number of times Laya semantic classifier raised risk flags")
    sprt_anomalies_count: int = Field(0, description="Number of times Markov/SPRT flagged anomalous behavioral drift")

    policy_label: str = Field("default", description="Canonical policy label or version (e.g. v1, v2)")
    behavioral_drift: float = Field(0.0, description="Calculated behavioral anomaly drift score [0.0 - 1.0]")
    semantic_risk: float = Field(0.0, description="Peak semantic risk classification score [0.0 - 1.0]")

    avg_latency_ms: float = Field(0.0, description="Mean step verification latency in milliseconds")
    max_latency_ms: float = Field(0.0, description="Peak step verification latency in milliseconds")
    total_duration_ms: float = Field(0.0, description="Total elapsed wall-clock replay time in milliseconds")


class PolicyComparisonSummary(BaseModel):
    """
    Comparative analysis between a baseline policy and an alternate/candidate policy
    answering: 'What happens if I change the policy?' across versioned security experiments.
    """

    baseline_policy: str = Field(..., description="Name or path of the baseline policy")
    candidate_policy: str = Field(..., description="Name or path of the candidate policy")
    baseline_policy_label: str = Field("v1", description="Baseline policy label (e.g. v1)")
    candidate_policy_label: str = Field("v2", description="Candidate policy label (e.g. v2)")
    baseline_decision: str = Field("ALLOW", description="Overall baseline decision: ALLOW, REVIEW, or BLOCK")
    candidate_decision: str = Field("ALLOW", description="Overall candidate decision: ALLOW, REVIEW, or BLOCK")
    baseline_detection_step: Optional[int] = Field(None, description="First detection event index under baseline policy")
    candidate_detection_step: Optional[int] = Field(None, description="First detection event index under candidate policy")
    baseline_behavioral_drift: float = Field(0.0, description="Behavioral drift under baseline policy")
    candidate_behavioral_drift: float = Field(0.0, description="Behavioral drift under candidate policy")
    semantic_risk: float = Field(0.0, description="Peak semantic risk classification score")
    divergent_steps: int = Field(0, description="Number of steps where verdicts differed")
    baseline_blocks: int = Field(0, description="Steps blocked under baseline")
    candidate_blocks: int = Field(0, description="Steps blocked under candidate policy")
    first_intervention_baseline: Optional[int] = Field(None, description="First intervention step under baseline")
    first_intervention_candidate: Optional[int] = Field(None, description="First intervention step under candidate")
    delta_description: str = Field("", description="Human-readable impact statement summarizing the policy change")


class ReplayReport(BaseModel):
    """
    Complete audit report produced by the Agent Replay engine.
    """

    trace_source: str = Field(..., description="Path or origin of the replayed agent trace")
    session_id: str = Field("default-session", description="Target session identifier")
    agent_id: str = Field("default-agent", description="Target agent identifier")
    strategy: str = Field("hybrid", description="Verification strategy applied (hybrid, rules, semantic, markov, rules_markov)")
    policy_path: str = Field(..., description="Active baseline policy path")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="UTC execution timestamp")
    steps: List[ReplayStep] = Field(default_factory=list, description="Ordered step-by-step verification results")
    summary: ReplaySummary = Field(default_factory=ReplaySummary, description="Aggregated session metrics")
    comparison: Optional[PolicyComparisonSummary] = Field(None, description="What-if policy comparison if requested")
