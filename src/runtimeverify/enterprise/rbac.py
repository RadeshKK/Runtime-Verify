"""
Role-Based Access Control (RBAC) Architecture for Enterprise RuntimeVerify (Phase 18).
Defines enterprise roles, fine-grained permissions, subject models, resource contexts,
and an authorization evaluation engine with strict tenant isolation and segregation of duties.
"""

from enum import Enum
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field

from runtimeverify.enterprise.models import ActorType, Environment


# ---------------------------------------------------------------------------
# Enterprise Roles and Permissions Taxonomy
# ---------------------------------------------------------------------------


class EnterpriseRole(str, Enum):
    """
    Standard enterprise security roles with hierarchical responsibility.
    """

    SUPER_ADMIN = "super_admin"  # Tenant root / platform operator
    ORG_ADMIN = "org_admin"  # Business unit / organization administrator
    SECURITY_ENGINEER = "security_engineer"  # SecOps, policy authoring, approval authority
    COMPLIANCE_AUDITOR = "compliance_auditor"  # Compliance, read-only audit log verification
    DEVELOPER = "developer"  # Engineer building & testing agents in dev/staging
    AGENT_SERVICE = "agent_service"  # Machine identity for autonomous agent processes


class EnterprisePermission(str, Enum):
    """
    Fine-grained permission identifiers for enterprise governance.
    """

    # Tenant Management
    TENANT_READ = "tenant:read"
    TENANT_WRITE = "tenant:write"
    TENANT_ADMIN = "tenant:admin"

    # Organization Management
    ORG_READ = "org:read"
    ORG_WRITE = "org:write"
    ORG_ADMIN = "org:admin"

    # Project Management
    PROJECT_READ = "project:read"
    PROJECT_WRITE = "project:write"
    PROJECT_DELETE = "project:delete"

    # Policy Governance
    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"
    POLICY_PUBLISH = "policy:publish"
    POLICY_DELETE = "policy:delete"

    # Telemetry and Events
    EVENT_INGEST = "event:ingest"
    EVENT_READ = "event:read"

    # Decision Engine
    DECISION_EVALUATE = "decision:evaluate"
    DECISION_READ = "decision:read"

    # Approval Workflows
    APPROVAL_REQUEST = "approval:request"
    APPROVAL_REVIEW = "approval:review"
    APPROVAL_APPROVE = "approval:approve"
    APPROVAL_DENY = "approval:deny"

    # Audit and Compliance
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"
    AUDIT_VERIFY = "audit:verify"

    # Agent Lifecycle
    AGENT_REGISTER = "agent:register"
    AGENT_READ = "agent:read"
    AGENT_REVOKE = "agent:revoke"

    # Integrations
    INTEGRATION_READ = "integration:read"
    INTEGRATION_WRITE = "integration:write"

    # Universal wildcard
    ALL = "*"


# Baseline default role to permissions mapping
ENTERPRISE_ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    EnterpriseRole.SUPER_ADMIN.value: {EnterprisePermission.ALL.value},
    EnterpriseRole.ORG_ADMIN.value: {
        EnterprisePermission.ORG_READ.value,
        EnterprisePermission.ORG_WRITE.value,
        EnterprisePermission.PROJECT_READ.value,
        EnterprisePermission.PROJECT_WRITE.value,
        EnterprisePermission.POLICY_READ.value,
        EnterprisePermission.POLICY_WRITE.value,
        EnterprisePermission.POLICY_PUBLISH.value,
        EnterprisePermission.EVENT_READ.value,
        EnterprisePermission.DECISION_READ.value,
        EnterprisePermission.APPROVAL_REVIEW.value,
        EnterprisePermission.APPROVAL_APPROVE.value,
        EnterprisePermission.APPROVAL_DENY.value,
        EnterprisePermission.AUDIT_READ.value,
        EnterprisePermission.AGENT_REGISTER.value,
        EnterprisePermission.AGENT_READ.value,
        EnterprisePermission.INTEGRATION_READ.value,
        EnterprisePermission.INTEGRATION_WRITE.value,
    },
    EnterpriseRole.SECURITY_ENGINEER.value: {
        EnterprisePermission.PROJECT_READ.value,
        EnterprisePermission.POLICY_READ.value,
        EnterprisePermission.POLICY_WRITE.value,
        EnterprisePermission.POLICY_PUBLISH.value,
        EnterprisePermission.EVENT_READ.value,
        EnterprisePermission.DECISION_EVALUATE.value,
        EnterprisePermission.DECISION_READ.value,
        EnterprisePermission.APPROVAL_REVIEW.value,
        EnterprisePermission.APPROVAL_APPROVE.value,
        EnterprisePermission.APPROVAL_DENY.value,
        EnterprisePermission.AUDIT_READ.value,
        EnterprisePermission.AUDIT_VERIFY.value,
        EnterprisePermission.AGENT_READ.value,
        EnterprisePermission.AGENT_REVOKE.value,
        EnterprisePermission.INTEGRATION_READ.value,
    },
    EnterpriseRole.COMPLIANCE_AUDITOR.value: {
        EnterprisePermission.PROJECT_READ.value,
        EnterprisePermission.POLICY_READ.value,
        EnterprisePermission.EVENT_READ.value,
        EnterprisePermission.DECISION_READ.value,
        EnterprisePermission.AUDIT_READ.value,
        EnterprisePermission.AUDIT_EXPORT.value,
        EnterprisePermission.AUDIT_VERIFY.value,
        EnterprisePermission.AGENT_READ.value,
    },
    EnterpriseRole.DEVELOPER.value: {
        EnterprisePermission.PROJECT_READ.value,
        EnterprisePermission.POLICY_READ.value,
        EnterprisePermission.EVENT_READ.value,
        EnterprisePermission.EVENT_INGEST.value,
        EnterprisePermission.DECISION_READ.value,
        EnterprisePermission.AGENT_REGISTER.value,
        EnterprisePermission.AGENT_READ.value,
    },
    EnterpriseRole.AGENT_SERVICE.value: {
        EnterprisePermission.EVENT_INGEST.value,
        EnterprisePermission.DECISION_EVALUATE.value,
        EnterprisePermission.APPROVAL_REQUEST.value,
    },
}


# ---------------------------------------------------------------------------
# Subject and Resource Models
# ---------------------------------------------------------------------------


class Subject(BaseModel):
    """
    Authenticated security principal attempting an operation.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="Unique subject ID (user email, sub claim, or agent UUID)")
    type: ActorType = Field(default=ActorType.USER)
    tenant_id: str = Field(..., description="Owning tenant isolation boundary")
    organization_id: Optional[str] = None
    project_id: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    custom_permissions: Set[str] = Field(default_factory=set)

    def resolve_permissions(self) -> Set[str]:
        """Calculates effective permissions combining role assignments and custom permissions."""
        perms: Set[str] = set(self.custom_permissions)
        for r in self.roles:
            r_normalized = r.lower()
            if r_normalized in ENTERPRISE_ROLE_PERMISSIONS:
                perms.update(ENTERPRISE_ROLE_PERMISSIONS[r_normalized])
        return perms

    def has_role(self, role: str) -> bool:
        target = role.lower()
        return any(r.lower() == target for r in self.roles)


class Resource(BaseModel):
    """
    Target enterprise entity upon which an action is requested.
    """

    model_config = ConfigDict(frozen=True)

    type: str = Field(..., description="Resource category (e.g. 'policy', 'audit', 'approval', 'agent')")
    id: Optional[str] = None
    tenant_id: str = Field(..., description="Tenant boundary of resource")
    organization_id: Optional[str] = None
    project_id: Optional[str] = None
    environment: Optional[Environment] = None
    owner_id: Optional[str] = Field(None, description="Original creator or requester of resource")


class AccessDecision(BaseModel):
    """
    Evaluated authorization decision.
    """

    model_config = ConfigDict(frozen=True)

    granted: bool
    action: str
    reason: str
    evaluated_permissions: Set[str] = Field(default_factory=set)


# ---------------------------------------------------------------------------
# Access Control Evaluation Engine
# ---------------------------------------------------------------------------


class AccessControlEvaluator:
    """
    Enterprise authorization engine enforcing multi-tenant isolation,
    environment protection boundaries, and segregation of duties (SOD).
    """

    @classmethod
    def evaluate(
        cls,
        subject: Subject,
        action: str,
        resource: Resource,
        target_env: Optional[Environment] = None,
    ) -> AccessDecision:
        """
        Evaluates whether the given subject is authorized to perform action on resource.
        """
        # 1. Hard Tenant Isolation Boundary
        # Only SUPER_ADMIN can transcend tenants, but standard operations require explicit tenant match
        if subject.tenant_id != resource.tenant_id:
            if not subject.has_role(EnterpriseRole.SUPER_ADMIN.value):
                return AccessDecision(
                    granted=False,
                    action=action,
                    reason=f"Tenant isolation violation: subject tenant '{subject.tenant_id}' does not match resource tenant '{resource.tenant_id}'.",
                )

        # 2. Production Environment Guardrails
        effective_env = target_env or resource.environment
        if effective_env == Environment.PRODUCTION:
            # Developers cannot modify policies in production or approve production escalations
            if subject.has_role(EnterpriseRole.DEVELOPER.value) and not (
                subject.has_role(EnterpriseRole.SECURITY_ENGINEER.value)
                or subject.has_role(EnterpriseRole.ORG_ADMIN.value)
                or subject.has_role(EnterpriseRole.SUPER_ADMIN.value)
            ):
                if action in {
                    EnterprisePermission.POLICY_WRITE.value,
                    EnterprisePermission.POLICY_PUBLISH.value,
                    EnterprisePermission.APPROVAL_APPROVE.value,
                }:
                    return AccessDecision(
                        granted=False,
                        action=action,
                        reason="Environment boundary enforcement: Developers cannot modify policies or approve actions in PRODUCTION.",
                    )

        # 3. Segregation of Duties (SOD): Cannot approve your own approval request
        if action == EnterprisePermission.APPROVAL_APPROVE.value:
            if resource.owner_id and resource.owner_id == subject.id:
                return AccessDecision(
                    granted=False,
                    action=action,
                    reason="Segregation of Duties (SOD) violation: Self-approval is strictly prohibited.",
                )

        # 4. Resolve Effective Permissions
        effective_perms = subject.resolve_permissions()
        if EnterprisePermission.ALL.value in effective_perms or action in effective_perms:
            return AccessDecision(
                granted=True,
                action=action,
                reason="Authorized by assigned enterprise role permissions.",
                evaluated_permissions=effective_perms,
            )

        return AccessDecision(
            granted=False,
            action=action,
            reason=f"Permission denied: subject lacks '{action}' permission.",
            evaluated_permissions=effective_perms,
        )
