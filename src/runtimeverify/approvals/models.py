"""
Data models and typed schemas for Human Approval Workflows (Phase 7).
Defines ApprovalRequest, ApprovalDecision, ApprovalStatus, and ApprovalAuditEntry.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class ApprovalStatus(str, Enum):
    """Lifecycle state of an approval request."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class ApprovalDecisionType(str, Enum):
    """Decision outcomes made by human approvers."""

    APPROVE = "APPROVE"
    DENY = "DENY"


class ApprovalTimeoutBehavior(str, Enum):
    """Action taken when an approval request reaches its expiration deadline."""

    DENY = "DENY"  # Fail-closed: block execution
    FAIL_CLOSED = "FAIL_CLOSED"  # Explicit alias for DENY
    APPROVE = "APPROVE"  # Fail-open (only for non-critical baselines if explicitly configured)


class ApprovalDecision(BaseModel):
    """
    Cryptographically auditable record of a human approver's verdict.
    """

    model_config = ConfigDict(frozen=True)

    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique ID for this decision")
    request_id: str = Field(..., description="ID of the ApprovalRequest being decided")
    decision: ApprovalDecisionType = Field(..., description="APPROVE or DENY verdict")
    decided_by: str = Field("operator", description="Identifier of the human operator or authorization authority")
    reason: Optional[str] = Field(None, description="Human explanation justifying the decision")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="UTC decision time")
    signature: Optional[str] = Field(None, description="Optional cryptographic signature or authentication token")
    approval_token: Optional[str] = Field(
        None, description="One-time authorization challenge token for replay validation"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context or telemetry metadata")


class ApprovalRequest(BaseModel):
    """
    Structured request for human authorization when an action triggers a REVIEW policy.
    Contains all context, evidentiary findings, and time-to-live expiration bounds.
    """

    model_config = ConfigDict(validate_assignment=True)

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique approval request ID")
    event_id: Optional[str] = Field(None, description="Correlated canonical event ID")
    action_id: Optional[str] = Field(None, description="Correlated interceptor action ID")
    agent_id: Optional[str] = Field(None, description="ID of the autonomous agent initiating the action")
    session_id: Optional[str] = Field(None, description="Session or conversation ID")

    action: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured representation of the proposed action (type, target, parameters)",
    )
    risk: str = Field("HIGH", description="Assessed risk level: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN")
    reason: str = Field(..., description="Primary reason the action was held for human review")
    evidence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Evidentiary records from policies, semantic classifiers, and behavioral models",
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC creation timestamp",
    )
    expiration: datetime = Field(
        ...,
        description="UTC expiration deadline after which the request becomes invalid",
    )
    timeout_seconds: float = Field(60.0, ge=0.1, description="Timeout window duration in seconds")
    timeout_behavior: ApprovalTimeoutBehavior = Field(
        ApprovalTimeoutBehavior.DENY,
        description="Default action taken upon reaching expiration",
    )

    status: ApprovalStatus = Field(ApprovalStatus.PENDING, description="Current lifecycle state")
    decision: Optional[ApprovalDecision] = Field(None, description="Recorded decision once resolved")
    approval_token: Optional[str] = Field(
        default_factory=lambda: uuid.uuid4().hex + uuid.uuid4().hex,
        description="Single-use cryptographic challenge token for replay protection",
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Extensible contextual metadata")

    def is_expired(self, current_time: Optional[datetime] = None) -> bool:
        """Checks if the request deadline has elapsed."""
        now = current_time or datetime.now(timezone.utc)
        # Ensure timezone-aware comparison
        if self.expiration.tzinfo is None:
            exp = self.expiration.replace(tzinfo=timezone.utc)
        else:
            exp = self.expiration
        return now >= exp

    def is_pending(self) -> bool:
        """Returns True if the request is still awaiting a human decision and not expired."""
        return self.status == ApprovalStatus.PENDING and not self.is_expired()


class ApprovalAuditEntry(BaseModel):
    """
    Immutable audit trail record capturing every state transition, decision, or rejection.
    """

    model_config = ConfigDict(frozen=True)

    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str
    event_type: str = Field(..., description="REQUEST_CREATED, DECISION_RECORDED, EXPIRED, REPLAY_REJECTED, etc.")
    actor: str = Field(..., description="User, agent, or component causing this event")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = Field(default_factory=dict)
