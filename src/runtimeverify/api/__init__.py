"""
RuntimeVerify API Package (Phase 11).
Exports the core FastAPI application, v1 router, auth providers, middleware, and schemas.
"""

from runtimeverify.api.app import app
from runtimeverify.api.auth import (
    AnonymousAuthProvider,
    ApiKeyAuthProvider,
    AuthContext,
    AuthProvider,
    CompositeAuthProvider,
    OIDCAuthProvider,
    Permission,
    Role,
    get_auth_provider,
    get_current_auth,
    require_authenticated,
    require_permission,
    require_role,
    set_auth_provider,
)
from runtimeverify.api.middleware import (
    CorrelationIdMiddleware,
    InMemoryRateLimiter,
    RateLimiter,
    RateLimitMiddleware,
    SecretRedactionMiddleware,
)
from runtimeverify.api.v1.router import api_v1_router

__all__ = [
    "app",
    "api_v1_router",
    "AuthProvider",
    "AuthContext",
    "AnonymousAuthProvider",
    "ApiKeyAuthProvider",
    "OIDCAuthProvider",
    "CompositeAuthProvider",
    "Permission",
    "Role",
    "get_auth_provider",
    "set_auth_provider",
    "get_current_auth",
    "require_authenticated",
    "require_permission",
    "require_role",
    "RateLimiter",
    "InMemoryRateLimiter",
    "RateLimitMiddleware",
    "CorrelationIdMiddleware",
    "SecretRedactionMiddleware",
]
