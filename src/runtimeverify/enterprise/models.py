"""
Core Enterprise Domain Models for RuntimeVerify (Phase 18).
Defines Tenant, Organization, Project, Environment, AgentEntity,
PolicySet, SessionEntity, AuditOwnership, ApprovalPolicy, and Integration schemas.
"""

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Conceptual Environments
# ---------------------------------------------------------------------------


class Environment(str, Enum):
    """
    Conceptual operational environments for enterprise policy enforcement.
    Transitions follow: DEVELOPMENT -> STAGING -> PRODUCTION.
    """

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

    @property
    def is_production(self) -> bool:
        return self == Environment.PRODUCTION

    @property
    def is_staging(self) -> bool:
        return self == Environment.STAGING

    @property
    def is_development(self) -> bool:
        return self == Environment.DEVELOPMENT

    @property
    def requires_dual_control(self) -> bool:
        """Production environments enforce dual-control human approvals for high-risk actions."""
        return self == Environment.PRODUCTION

    @property
    def allows_permissive_override(self) -> bool:
        """Development environments allow dry-run and permissive logging overrides."""
        return self == Environment.DEVELOPMENT


# ---------------------------------------------------------------------------
# Enterprise Organizational Hierarchy
# ---------------------------------------------------------------------------


class TenantStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PROVISIONING = "provisioning"
    DECOMMISSIONED = "decommissioned"


class TenantTier(str, Enum):
    COMMUNITY = "community"
    ENTERPRISE = "enterprise"
    ENTERPRISE_PLUS = "enterprise_plus"


class Tenant(BaseModel):
    """
    Top-level organizational and billing boundary.
    Represents the hard data isolation boundary in enterprise deployments.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: f"tenant-{uuid.uuid4().hex[:12]}")
    name: str = Field(..., min_length=2, max_length=120, description="Display name of enterprise tenant")
    slug: str = Field(..., min_length=2, max_length=64, description="URL-safe identifier slug")
    status: TenantStatus = Field(default=TenantStatus.ACTIVE)
    tier: TenantTier = Field(default=TenantTier.ENTERPRISE)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9-]+$", v):
            raise ValueError("Slug must contain only lowercase alphanumeric characters and hyphens")
        return v


class Organization(BaseModel):
    """
    Business unit or department within an enterprise Tenant.
    E.g. Engineering, Autonomous Services, SecOps, Finance.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: f"org-{uuid.uuid4().hex[:12]}")
    tenant_id: str = Field(..., description="Parent tenant boundary")
    name: str = Field(..., min_length=2, max_length=120)
    slug: str = Field(..., min_length=2, max_length=64)
    parent_org_id: Optional[str] = Field(None, description="Optional parent org for nested business units")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9-]+$", v):
            raise ValueError("Slug must contain only lowercase alphanumeric characters and hyphens")
        return v


class Project(BaseModel):
    """
    Specific workload, product, or agentic application initiative within an Organization.
    E.g. 'autonomous-coder', 'checkout-agent', 'infra-remediator'.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: f"proj-{uuid.uuid4().hex[:12]}")
    tenant_id: str = Field(..., description="Parent tenant boundary")
    organization_id: str = Field(..., description="Parent organization boundary")
    name: str = Field(..., min_length=2, max_length=120)
    slug: str = Field(..., min_length=2, max_length=64)
    description: Optional[str] = Field(None, max_length=500)
    environments_enabled: List[Environment] = Field(
        default_factory=lambda: [Environment.DEVELOPMENT, Environment.STAGING, Environment.PRODUCTION]
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9-]+$", v):
            raise ValueError("Slug must contain only lowercase alphanumeric characters and hyphens")
        return v


# ---------------------------------------------------------------------------
# Agent and Runtime Session Entities
# ---------------------------------------------------------------------------


class AgentEntity(BaseModel):
    """
    Managed autonomous agent identity registered within a Project and Environment.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="Unique agent identifier (e.g. 'coding-agent-01')")
    tenant_id: str = Field(...)
    organization_id: str = Field(...)
    project_id: str = Field(...)
    environment: Environment = Field(default=Environment.DEVELOPMENT)
    name: str = Field(..., min_length=1, max_length=120)
    role: str = Field(..., description="Agent role (e.g. planner, coder, tester, executor)")
    status: str = Field("active", description="active, suspended, retired")
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SessionEntity(BaseModel):
    """
    Runtime execution trajectory of an agent within enterprise scope boundaries.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="Unique session run identifier")
    tenant_id: str = Field(...)
    organization_id: str = Field(...)
    project_id: str = Field(...)
    environment: Environment = Field(...)
    agent_id: str = Field(...)
    status: str = Field("active", description="active, completed, terminated_security")
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: Optional[datetime] = None
    event_count: int = Field(default=0)
    anomaly_detected: bool = Field(default=False)
    risk_level: str = Field("LOW", description="Assessed session risk level: LOW, MEDIUM, HIGH, CRITICAL")
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# PolicySet and Hierarchical Governance
# ---------------------------------------------------------------------------


class EnforcementMode(str, Enum):
    ENFORCE = "enforce"  # Strict blocking / approval triggers
    MONITOR = "monitor"  # Audit / telemetry only, no blocking
    DISABLED = "disabled"  # Inactive


class PolicySetScope(str, Enum):
    TENANT = "tenant"  # Global enterprise guardrails (highest priority, cannot be overridden)
    ORGANIZATION = "organization"  # Departmental security policies
    PROJECT = "project"  # Application-specific policies


class PolicySet(BaseModel):
    """
    Hierarchical bundle of declarative security rules bound to Tenant, Org, Project, and Environment.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: f"polset-{uuid.uuid4().hex[:12]}")
    tenant_id: str = Field(..., description="Owning tenant")
    organization_id: Optional[str] = Field(None, description="Optional owning org; None for tenant-wide")
    project_id: Optional[str] = Field(None, description="Optional owning project; None for org/tenant-wide")
    environment: Optional[Environment] = Field(None, description="Optional environment constraint; None applies to all")
    name: str = Field(..., min_length=2, max_length=120)
    version: str = Field("1.0.0", description="Semantic version string")
    scope: PolicySetScope = Field(default=PolicySetScope.PROJECT)
    enforcement_mode: EnforcementMode = Field(default=EnforcementMode.ENFORCE)
    immutable: bool = Field(False, description="Immutable policy sets (e.g. tenant guardrails) cannot be overridden")
    policies: List[Dict[str, Any]] = Field(default_factory=list, description="Raw rule definitions or policy payloads")
    created_by: str = Field("system", description="Author identity")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Audit Ownership and Cryptographic Verification
# ---------------------------------------------------------------------------


class ActorType(str, Enum):
    USER = "user"
    AGENT = "agent"
    SERVICE = "service"
    SYSTEM = "system"


class AuditOwnership(BaseModel):
    """
    Immutable lineage record proving enterprise entity ownership and cryptographic chain integrity.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: f"audit-{uuid.uuid4().hex[:16]}")
    tenant_id: str = Field(...)
    organization_id: str = Field(...)
    project_id: str = Field(...)
    environment: Environment = Field(...)
    session_id: Optional[str] = None
    event_id: str = Field(..., description="Referenced canonical telemetry event ID")
    decision_id: Optional[str] = Field(None, description="Referenced verification decision ID")
    actor_id: str = Field(..., description="Identity of principal causing the event")
    actor_type: ActorType = Field(default=ActorType.AGENT)
    action: str = Field(...)
    verdict: str = Field(..., description="ALLOW, REVIEW, BLOCK")
    hash: str = Field(..., description="SHA-256 cryptographic digest of record content")
    prev_hash: Optional[str] = Field(
        None, description="Cryptographic link to previous audit entry in tamper-evident chain"
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Approval Policy and Dual-Control Models
# ---------------------------------------------------------------------------


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ApprovalPolicy(BaseModel):
    """
    Human-in-the-loop escalation rules specifying sign-off thresholds, dual-control, and timeout behavior.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: f"apprpol-{uuid.uuid4().hex[:12]}")
    tenant_id: str = Field(...)
    organization_id: Optional[str] = None
    project_id: Optional[str] = None
    environment: Environment = Field(default=Environment.PRODUCTION)
    name: str = Field(...)
    min_approvers: int = Field(
        default=1, ge=1, le=5, description="Number of distinct approvers required (e.g. 2 for dual control)"
    )
    allowed_roles: List[str] = Field(default_factory=lambda: ["security_engineer", "org_admin"])
    auto_timeout_seconds: int = Field(default=300, ge=30, le=86400)
    timeout_action: str = Field("BLOCK", description="Action upon expiry: BLOCK or REJECT")


class EnterpriseApprovalRequest(BaseModel):
    """
    Enterprise-governed approval record with dual-control multi-approver tracking.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: f"appr-{uuid.uuid4().hex[:16]}")
    tenant_id: str = Field(...)
    organization_id: str = Field(...)
    project_id: str = Field(...)
    environment: Environment = Field(...)
    session_id: str = Field(...)
    agent_id: str = Field(...)
    action_type: str = Field(...)
    action_target: str = Field(...)
    risk_level: str = Field("HIGH")
    status: ApprovalStatus = Field(default=ApprovalStatus.PENDING)
    required_approvals: int = Field(default=1)
    approved_by: List[str] = Field(default_factory=list, description="List of user IDs who approved")
    rejected_by: Optional[str] = None
    reason: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(...)


# ---------------------------------------------------------------------------
# Integration Connectors
# ---------------------------------------------------------------------------


class IntegrationType(str, Enum):
    OIDC_KEYCLOAK = "oidc_keycloak"
    OIDC_GENERIC = "oidc_generic"
    SLACK_WEBHOOK = "slack_webhook"
    SIEM_SPLUNK = "siem_splunk"
    SIEM_DATADOG = "siem_datadog"
    GENERIC_WEBHOOK = "generic_webhook"
    PAGERDUTY = "pagerduty"


class Integration(BaseModel):
    """
    Third-party integration connector configuration bound to tenant/org/project.
    Secret credentials are never exposed through API responses.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: f"integ-{uuid.uuid4().hex[:12]}")
    tenant_id: str = Field(...)
    organization_id: Optional[str] = None
    project_id: Optional[str] = None
    type: IntegrationType = Field(...)
    name: str = Field(..., min_length=2, max_length=120)
    endpoint_url: Optional[str] = None
    enabled: bool = Field(default=True)
    # Sanitized configuration parameters (secrets are referenced or hashed, never stored raw)
    config: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
