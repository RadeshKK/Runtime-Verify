"""
Enterprise Architecture Subsystem for RuntimeVerify (Phase 18).
Provides organization-scale multi-tenant governance, hierarchical policy sets,
conceptual environments (dev/staging/prod), OIDC/Keycloak authentication abstractions,
dual-control approval workflows, and tamper-evident audit ownership in a modular monolith.
"""

from runtimeverify.enterprise.approval import (
    ApprovalResolution,
    EnterpriseApprovalManager,
)
from runtimeverify.enterprise.audit import EnterpriseAuditManager
from runtimeverify.enterprise.auth import (
    ApiKeyRecord,
    ClaimsExtractor,
    EnterpriseApiKeyManager,
    GenericOIDCClaimsExtractor,
    KeycloakClaimsExtractor,
    OIDCClaims,
    ServiceAssertionToken,
    ServiceToServiceAuth,
    TokenValidationError,
    TokenValidator,
)
from runtimeverify.enterprise.context import (
    EnterpriseContext,
    enterprise_scope,
    get_current_context,
    reset_current_context,
    set_current_context,
)
from runtimeverify.enterprise.isolation import (
    PartitionedStore,
    TenantIsolationEngine,
    TenantIsolationViolationError,
    TenantPartitionKey,
)
from runtimeverify.enterprise.models import (
    ActorType,
    AgentEntity,
    ApprovalPolicy,
    ApprovalStatus,
    AuditOwnership,
    EnforcementMode,
    EnterpriseApprovalRequest,
    Environment,
    Integration,
    IntegrationType,
    Organization,
    PolicySet,
    PolicySetScope,
    Project,
    SessionEntity,
    Tenant,
    TenantStatus,
    TenantTier,
)
from runtimeverify.enterprise.policyset import (
    PolicySetManager,
    PolicySetResolutionResult,
)
from runtimeverify.enterprise.rbac import (
    ENTERPRISE_ROLE_PERMISSIONS,
    AccessControlEvaluator,
    AccessDecision,
    EnterprisePermission,
    EnterpriseRole,
    Resource,
    Subject,
)

__all__ = [
    # Environments and Entities
    "Environment",
    "Tenant",
    "TenantStatus",
    "TenantTier",
    "Organization",
    "Project",
    "AgentEntity",
    "SessionEntity",
    "PolicySet",
    "PolicySetScope",
    "EnforcementMode",
    "AuditOwnership",
    "ActorType",
    "ApprovalPolicy",
    "ApprovalStatus",
    "EnterpriseApprovalRequest",
    "Integration",
    "IntegrationType",
    # Context
    "EnterpriseContext",
    "get_current_context",
    "set_current_context",
    "reset_current_context",
    "enterprise_scope",
    # RBAC
    "EnterpriseRole",
    "EnterprisePermission",
    "ENTERPRISE_ROLE_PERMISSIONS",
    "Subject",
    "Resource",
    "AccessDecision",
    "AccessControlEvaluator",
    # Auth
    "OIDCClaims",
    "ClaimsExtractor",
    "KeycloakClaimsExtractor",
    "GenericOIDCClaimsExtractor",
    "TokenValidator",
    "TokenValidationError",
    "ApiKeyRecord",
    "EnterpriseApiKeyManager",
    "ServiceToServiceAuth",
    "ServiceAssertionToken",
    # Isolation
    "TenantIsolationEngine",
    "TenantIsolationViolationError",
    "TenantPartitionKey",
    "PartitionedStore",
    # PolicySet
    "PolicySetManager",
    "PolicySetResolutionResult",
    # Audit
    "EnterpriseAuditManager",
    # Approvals
    "EnterpriseApprovalManager",
    "ApprovalResolution",
]
