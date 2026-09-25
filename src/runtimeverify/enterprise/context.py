"""
Ambient Enterprise Execution Context for Multi-Tenant RuntimeVerify (Phase 18).
Provides thread-safe and async-safe context propagation using contextvars.
"""

from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Generator, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field

from runtimeverify.enterprise.models import ActorType, Environment


class EnterpriseContext(BaseModel):
    """
    Principal organizational context for the executing thread or async task.
    Identifies tenant, organization, project, environment, actor, and permissions.
    """

    model_config = ConfigDict(frozen=True)

    tenant_id: str = Field(..., description="Active tenant isolation boundary")
    organization_id: Optional[str] = Field(None, description="Active organization context")
    project_id: Optional[str] = Field(None, description="Active project context")
    environment: Environment = Field(default=Environment.DEVELOPMENT, description="Active operational environment")
    actor_id: str = Field("anonymous", description="User ID, Agent ID, or Service ID")
    actor_type: ActorType = Field(default=ActorType.USER, description="Actor taxonomy")
    roles: List[str] = Field(default_factory=list, description="Roles held by the subject")
    permissions: Set[str] = Field(default_factory=set, description="Evaluated fine-grained permissions")
    correlation_id: Optional[str] = Field(None, description="Distributed tracing correlation ID")

    def matches_tenant(self, tenant_id: str) -> bool:
        """Verifies if this context strictly matches the target tenant."""
        return self.tenant_id == tenant_id

    def allows_environment(self, env: Environment) -> bool:
        """Verifies if this context is operating in or permitted for the target environment."""
        return self.environment == env

    def has_permission(self, permission: str) -> bool:
        """Checks if the subject in this context possesses the given permission or wildcard."""
        return "*" in self.permissions or permission in self.permissions

    def has_role(self, role: str) -> bool:
        """Checks if the subject possesses the given role (case-insensitive)."""
        target = role.lower()
        return any(r.lower() == target for r in self.roles)


# Context variable for async/thread-local enterprise context
_CURRENT_ENTERPRISE_CONTEXT: ContextVar[Optional[EnterpriseContext]] = ContextVar(
    "current_enterprise_context", default=None
)


def get_current_context() -> Optional[EnterpriseContext]:
    """Retrieves the current enterprise context, or None if uninitialized."""
    return _CURRENT_ENTERPRISE_CONTEXT.get()


def set_current_context(context: EnterpriseContext) -> Token:
    """Sets the ambient enterprise context for the current task/thread."""
    return _CURRENT_ENTERPRISE_CONTEXT.set(context)


def reset_current_context(token: Token) -> None:
    """Restores the previous enterprise context using the token returned by set_current_context."""
    _CURRENT_ENTERPRISE_CONTEXT.reset(token)


@contextmanager
def enterprise_scope(
    tenant_id: str,
    organization_id: Optional[str] = None,
    project_id: Optional[str] = None,
    environment: Environment = Environment.DEVELOPMENT,
    actor_id: str = "system",
    actor_type: ActorType = ActorType.SYSTEM,
    roles: Optional[List[str]] = None,
    permissions: Optional[Set[str]] = None,
    correlation_id: Optional[str] = None,
) -> Generator[EnterpriseContext, None, None]:
    """
    Context manager to execute a code block within a bounded EnterpriseContext.
    Automatically restores previous context on exit.
    """
    ctx = EnterpriseContext(
        tenant_id=tenant_id,
        organization_id=organization_id,
        project_id=project_id,
        environment=environment,
        actor_id=actor_id,
        actor_type=actor_type,
        roles=roles or [],
        permissions=permissions or set(),
        correlation_id=correlation_id,
    )
    token = set_current_context(ctx)
    try:
        yield ctx
    finally:
        reset_current_context(token)
