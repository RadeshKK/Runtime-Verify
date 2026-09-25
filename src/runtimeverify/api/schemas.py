"""
Typed Pydantic Schemas for RuntimeVerify API (Phase 11).
Defines request parameters, response models, pagination envelopes,
and validation rules for all /api/v1 endpoints.
"""

from datetime import datetime, timezone
import math
from typing import Any, Dict, Generic, List, Optional, Sequence, TypeVar, Union
from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Pagination Schemas
# ---------------------------------------------------------------------------


class PaginatedResponse(BaseModel, Generic[T]):
    """Standardized envelope for paginated resource collections."""

    model_config = ConfigDict(frozen=True)

    items: List[T] = Field(..., description="List of items in the current page")
    total: int = Field(..., description="Total count of items matching filter criteria")
    page: int = Field(..., ge=1, description="Current page number (1-indexed)")
    page_size: int = Field(..., ge=1, description="Number of items requested per page")
    total_pages: int = Field(..., ge=0, description="Total number of pages available")
    has_more: bool = Field(..., description="Whether subsequent pages are available")


def paginate_items(items: Sequence[T], page: int, page_size: int) -> PaginatedResponse[T]:
    """Slices an in-memory collection and constructs a PaginatedResponse."""
    safe_page = max(1, page)
    safe_page_size = max(1, page_size)
    total = len(items)
    total_pages = math.ceil(total / safe_page_size) if total > 0 else 0

    start_idx = (safe_page - 1) * safe_page_size
    end_idx = start_idx + safe_page_size
    page_slice = list(items[start_idx:end_idx])
    has_more = end_idx < total

    return PaginatedResponse(
        items=page_slice,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
        total_pages=total_pages,
        has_more=has_more,
    )


# ---------------------------------------------------------------------------
# Health & Status Schemas
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    """Overall system health and engine status."""

    status: str = Field("healthy", description="System health status: healthy, degraded, or unhealthy")
    version: str = Field("1.0.0", description="RuntimeVerify engine version")
    uptime_seconds: float = Field(..., description="Elapsed server uptime in seconds")
    components: Dict[str, str] = Field(default_factory=dict, description="Operational status of internal subsystems")


class ReadinessResponse(BaseModel):
    """Kubernetes readiness probe response."""

    ready: bool = Field(..., description="Whether the instance is ready to receive traffic")
    checks: Dict[str, bool] = Field(
        default_factory=dict, description="Status of individual readiness dependency checks"
    )
    message: str = Field("All subsystems operational", description="Human-readable readiness status")


class LivenessResponse(BaseModel):
    """Kubernetes liveness probe response."""

    alive: bool = Field(True, description="Process responsiveness indicator")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Event Schemas
# ---------------------------------------------------------------------------


class EventIngestRequest(BaseModel):
    """Incoming telemetry or agent action event for ingestion and verification."""

    id: Optional[str] = Field(None, description="Optional custom event identifier (UUID generated if omitted)")
    session_id: str = Field(..., description="Session correlation identifier")
    agent_id: str = Field(..., description="Unique autonomous agent identifier")
    type: str = Field("generic", description="Event category: generic, tool, filesystem, network, llm, shell")
    action: Optional[str] = Field(None, description="Action verb: read, write, execute, connect, chat")
    target: Optional[str] = Field(None, description="Resource target: file path, URL, command line, or tool name")
    status: str = Field("success", description="Execution status: success, error, running")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary event arguments or tool parameters")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Contextual tags, environment, or execution metadata"
    )
    trace_id: Optional[str] = Field(None, description="Distributed tracing identifier")


class EventResponse(BaseModel):
    """Stored or ingested event record representation."""

    id: str
    session_id: str
    agent_id: str
    type: str
    action: Optional[str] = None
    target: Optional[str] = None
    status: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str


# ---------------------------------------------------------------------------
# Decision & Verification Schemas
# ---------------------------------------------------------------------------


class DecisionEvaluateRequest(BaseModel):
    """Request payload for dry-run verification without mutating persistent trace state."""

    action_type: str = Field("shell", description="Action domain: shell, filesystem, network, git, process, tool")
    target: str = Field(..., description="Action target: command string, file path, URL, git ref")
    agent_id: str = Field("agent-api", description="Agent identifier to evaluate against")
    session_id: str = Field("session-eval", description="Session identifier for behavioral tracking")
    params: Dict[str, Any] = Field(default_factory=dict, description="Action arguments or environment variables")
    environment: Optional[str] = Field(
        "development", description="Execution environment: development, staging, production"
    )
    dry_run: bool = Field(True, description="When true, does not persist behavioral state or emit alerts")


class DecisionResponse(BaseModel):
    """Synthesized multi-tier verification verdict."""

    verification_id: str
    decision: str = Field(..., description="Synthesized verdict: ALLOW, REVIEW, or BLOCK")
    risk_level: str = Field(..., description="Risk assessment: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Calibrated confidence score [0.0, 1.0]")
    reason: str = Field(..., description="Explanatory justification for the decision")
    action_type: Optional[str] = None
    target: Optional[str] = None
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    evidence: Union[List[Dict[str, Any]], Dict[str, Any]] = Field(
        default_factory=list, description="Evidentiary records"
    )
    policy_matches: List[Dict[str, Any]] = Field(default_factory=list, description="Matched deterministic policy rules")
    latency_ms: float = Field(0.0, description="Pipeline verification latency in milliseconds")
    timestamp: str


# ---------------------------------------------------------------------------
# Agent Overview & Session Schemas
# ---------------------------------------------------------------------------


class AgentSummaryResponse(BaseModel):
    """Aggregated activity and health profile for a known AI agent."""

    agent_id: str
    total_sessions: int = 0
    total_events: int = 0
    total_anomalies: int = 0
    status: str = "active"
    last_active: Optional[str] = None


class AgentSessionDetailResponse(BaseModel):
    """Detailed activity history and decisions for an agent session."""

    agent_id: str
    session_id: str
    event_count: int = 0
    anomalies_count: int = 0
    events: List[Dict[str, Any]] = Field(default_factory=list)
    decisions: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str
    updated_at: str


# ---------------------------------------------------------------------------
# Policy Management Schemas
# ---------------------------------------------------------------------------


class PolicyRuleSummary(BaseModel):
    """Summary of an active deterministic policy rule."""

    id: str
    description: Optional[str] = None
    decision: str
    severity: str
    match_criteria: Dict[str, Any] = Field(default_factory=dict)


class PolicyValidateRequest(BaseModel):
    """Policy definition payload for syntax, structural, and semantic validation."""

    content: str = Field(..., description="Raw YAML or JSON policy specification")
    format: str = Field("yaml", description="Specification syntax format: yaml or json")


class PolicyValidateResponse(BaseModel):
    """Policy validation outcome breakdown."""

    valid: bool
    policy_count: int = 0
    version: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    policies: List[PolicyRuleSummary] = Field(default_factory=list)


class PolicyTestRequest(BaseModel):
    """Test a candidate policy against a sample event."""

    policy_content: Optional[str] = Field(
        None, description="Optional candidate policy YAML to test against (uses active if omitted)"
    )
    event_type: str = Field("FILE_READ", description="Canonical event type")
    action: str = Field("READ", description="Event action")
    target: str = Field("/etc/passwd", description="Target path, command, or URL")
    agent_id: Optional[str] = Field(None, description="Agent identity")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PolicyTestResponse(BaseModel):
    """Policy dry-run matching outcome."""

    matched: bool
    decision: str = Field(..., description="Resulting verdict: ALLOW, REVIEW, BLOCK, or NO_MATCH")
    policy_id: Optional[str] = None
    severity: Optional[str] = None
    reason: Optional[str] = None
    matched_rule: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Audit Schemas
# ---------------------------------------------------------------------------


class AuditPruneRequest(BaseModel):
    """Parameters for retention-based audit log pruning."""

    max_age_days: Optional[int] = Field(None, ge=1, description="Prune records older than this number of days")
    max_records: Optional[int] = Field(None, ge=1, description="Prune records exceeding this maximum record count")


class AuditPruneResponse(BaseModel):
    """Audit pruning result."""

    pruned_records: int
    remaining_records: int
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AuditRecordResponse(BaseModel):
    """Audit record data model."""

    record_id: str
    record_type: str
    severity: str
    summary: str
    timestamp: str
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    trace_id: Optional[str] = None
    event_id: Optional[str] = None
    action_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    redacted: bool = False
