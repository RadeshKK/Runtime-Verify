"""
Multi-Agent Runtime Verification Models for RuntimeVerify (Phase 17).
Defines schemas, roles, privilege tiers, anomalies, and decisions for multi-agent systems.
"""

from datetime import datetime, timezone
from enum import Enum
import fnmatch
import hashlib
import hmac
from typing import Any, Dict, List, Optional, Set
import uuid
from pydantic import BaseModel, ConfigDict, Field


class AgentRole(str, Enum):
    """
    Standardized operational roles for agents in multi-agent topologies.
    """

    ORCHESTRATOR = "orchestrator"
    PLANNER = "planner"
    RESEARCHER = "researcher"
    CODER = "coder"
    TESTER = "tester"
    EXECUTOR = "executor"
    REVIEWER = "reviewer"
    CRITIC = "critic"
    WORKER = "worker"
    USER_PROXY = "user_proxy"
    CUSTOM = "custom"


class RolePrivilegeLevel:
    """
    Default hierarchical privilege tiers for agent roles.
    Higher values denote greater access to system-altering capabilities.
    """

    DEFAULT_LEVELS: Dict[str, int] = {
        "user_proxy": 5,
        "researcher": 10,
        "planner": 10,
        "critic": 10,
        "reviewer": 15,
        "coder": 20,
        "tester": 20,
        "worker": 20,
        "executor": 30,
        "orchestrator": 40,
    }

    @classmethod
    def get_level(cls, role: str, custom_levels: Optional[Dict[str, int]] = None) -> int:
        role_lower = str(role).lower()
        if custom_levels and role_lower in custom_levels:
            return custom_levels[role_lower]
        return cls.DEFAULT_LEVELS.get(role_lower, 10)


class TopologyType(str, Enum):
    """
    Architectural topology archetype governing cross-agent interactions.
    """

    PIPELINE = "pipeline"  # Sequential chain (e.g. planner -> coder -> tester -> executor)
    HIERARCHICAL = "hierarchical"  # Hub-and-spoke / orchestrator with workers
    MESH = "mesh"  # Peer-to-peer among authorized roles
    CUSTOM = "custom"  # Arbitrary directed graph with edge rules


class TopologyEdge(BaseModel):
    """
    Authorized directional communication or delegation edge between agent roles.
    """

    model_config = ConfigDict(frozen=True)

    source_role: str = Field(..., description="Originating agent role")
    target_role: str = Field(..., description="Permitted recipient agent role")
    allowed_actions: Set[str] = Field(
        default_factory=lambda: {"message", "delegate", "handoff"},
        description="Permitted interaction types across this edge",
    )
    max_delegation_depth: int = Field(default=5, ge=1, description="Maximum delegation call depth allowed")
    require_approval: bool = Field(
        default=False, description="Whether interactions along this edge require human review"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom edge metadata")


class MultiAgentAnomalyType(str, Enum):
    """
    Taxonomy of multi-agent behavioral and topological anomalies.
    """

    UNEXPECTED_DELEGATION = "unexpected_delegation"
    UNEXPECTED_COMMUNICATION = "unexpected_communication"
    ABNORMAL_HANDOFF = "abnormal_handoff"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CROSS_AGENT_ANOMALY = "cross_agent_anomaly"
    CYCLIC_DELEGATION = "cyclic_delegation"
    EXCESSIVE_DELEGATION_DEPTH = "excessive_delegation_depth"


class MultiAgentAnomaly(BaseModel):
    """
    Structured evidentiary record of a detected multi-agent anomaly.
    """

    model_config = ConfigDict(frozen=True)

    anomaly_type: MultiAgentAnomalyType = Field(..., description="Classification category")
    source_agent: str = Field(..., description="Originating agent ID")
    source_role: str = Field(..., description="Originating agent role")
    target_agent: Optional[str] = Field(None, description="Target agent ID")
    target_role: Optional[str] = Field(None, description="Target agent role")
    action: str = Field(..., description="Interaction action verb")
    severity: str = Field("HIGH", description="Assessed severity (LOW, MEDIUM, HIGH, CRITICAL)")
    reason: str = Field(..., description="Human-readable explanation of why this interaction is anomalous")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Telemetry evidence supporting detection")


class MultiAgentDecision(BaseModel):
    """
    Comprehensive verification result for a multi-agent interaction.
    """

    model_config = ConfigDict(frozen=True)

    decision: str = Field("ALLOW", description="ALLOW, REVIEW, or BLOCK")
    risk_level: str = Field("LOW", description="LOW, MEDIUM, HIGH, or CRITICAL")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Verification confidence score")
    anomalies: List[MultiAgentAnomaly] = Field(default_factory=list, description="List of detected anomalies")
    reason: str = Field(
        "Multi-agent interaction conforms to authorized topology baseline", description="Summary rationale"
    )
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Evidentiary records")
    topology_matched: bool = Field(True, description="Whether interaction conforms to declared topology graph")


class DelegationTicket(BaseModel):
    """
    Cryptographically signed delegation authorization ticket establishing verifiable
    provenance and bounded authority between collaborating agents in a swarm.
    """

    model_config = ConfigDict(frozen=True)

    ticket_id: str = Field(
        default_factory=lambda: f"tkt_{uuid.uuid4().hex[:12]}",
        description="Unique identifier for this delegation ticket",
    )
    parent_agent: str = Field(..., description="Agent delegating authority")
    child_agent: str = Field(..., description="Agent receiving delegated authority")
    session_id: str = Field(..., description="Trace session ID this ticket is valid for")
    scope: List[str] = Field(
        default_factory=lambda: ["*"],
        description="List of permitted actions, tool names, or wildcards allowed under this ticket",
    )
    max_depth: int = Field(default=2, ge=1, description="Maximum sub-delegation depth allowed")
    issued_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC issuance timestamp",
    )
    expires_at: datetime = Field(
        ...,
        description="UTC expiration timestamp after which this ticket is invalid",
    )
    signature: str = Field("", description="HMAC-SHA256 signature binding ticket fields to parent agent key")

    def compute_signature_payload(self) -> str:
        """Deterministic canonical representation of ticket contents for signing."""
        iso_issued = self.issued_at.isoformat()
        iso_expires = self.expires_at.isoformat()
        sorted_scope = ",".join(sorted(self.scope))
        return f"{self.ticket_id}|{self.parent_agent}|{self.child_agent}|{self.session_id}|{sorted_scope}|{self.max_depth}|{iso_issued}|{iso_expires}"

    def sign(self, secret_key: str) -> "DelegationTicket":
        """Returns a new DelegationTicket with a cryptographically valid HMAC-SHA256 signature."""
        payload = self.compute_signature_payload()
        sig = hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        data = self.model_dump()
        data["signature"] = sig
        return DelegationTicket(**data)

    def verify_signature(self, secret_key: str) -> bool:
        """Verifies that the ticket signature matches the payload and secret key."""
        if not self.signature:
            return False
        payload = self.compute_signature_payload()
        expected = hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)

    def is_expired(self, current_time: Optional[datetime] = None) -> bool:
        """Checks if the delegation ticket has expired."""
        now = current_time or datetime.now(timezone.utc)
        return now > self.expires_at

    def allows_action(self, action_name: str) -> bool:
        """Checks if the requested action is permitted within the ticket scope."""
        if "*" in self.scope:
            return True
        for pattern in self.scope:
            if pattern == action_name or fnmatch.fnmatch(action_name, pattern):
                return True
        return False
