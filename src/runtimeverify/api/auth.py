"""
Authentication and Authorization Abstractions for RuntimeVerify API (Phase 11).
Provides decoupled, vendor-neutral auth primitives ready for enterprise
Keycloak/OIDC, API key, and RBAC integrations without fake authentication.
"""

from abc import ABC, abstractmethod
import base64
from enum import Enum
import json
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set
from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Permissions and Roles Taxonomy
# ---------------------------------------------------------------------------


class Permission(str, Enum):
    """Fine-grained permission identifiers for API resource authorization."""

    EVENTS_READ = "events:read"
    EVENTS_WRITE = "events:write"
    DECISIONS_READ = "decisions:read"
    DECISIONS_EVALUATE = "decisions:evaluate"
    AGENTS_READ = "agents:read"
    POLICIES_READ = "policies:read"
    POLICIES_WRITE = "policies:write"
    APPROVALS_READ = "approvals:read"
    APPROVALS_WRITE = "approvals:write"
    AUDIT_READ = "audit:read"
    AUDIT_ADMIN = "audit:admin"
    HEALTH_READ = "health:read"
    ALL = "*"


class Role(str, Enum):
    """Standard security roles mapped to permissions."""

    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    AGENT = "agent"
    VIEWER = "viewer"
    GUEST = "guest"


DEFAULT_ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    Role.ADMIN.value: {Permission.ALL.value},
    Role.OPERATOR.value: {
        Permission.EVENTS_READ.value,
        Permission.EVENTS_WRITE.value,
        Permission.DECISIONS_READ.value,
        Permission.DECISIONS_EVALUATE.value,
        Permission.AGENTS_READ.value,
        Permission.POLICIES_READ.value,
        Permission.APPROVALS_READ.value,
        Permission.APPROVALS_WRITE.value,
        Permission.AUDIT_READ.value,
        Permission.HEALTH_READ.value,
    },
    Role.AUDITOR.value: {
        Permission.EVENTS_READ.value,
        Permission.DECISIONS_READ.value,
        Permission.AGENTS_READ.value,
        Permission.POLICIES_READ.value,
        Permission.APPROVALS_READ.value,
        Permission.AUDIT_READ.value,
        Permission.HEALTH_READ.value,
    },
    Role.AGENT.value: {
        Permission.EVENTS_WRITE.value,
        Permission.DECISIONS_EVALUATE.value,
        Permission.HEALTH_READ.value,
    },
    Role.VIEWER.value: {
        Permission.EVENTS_READ.value,
        Permission.DECISIONS_READ.value,
        Permission.AGENTS_READ.value,
        Permission.POLICIES_READ.value,
        Permission.APPROVALS_READ.value,
        Permission.HEALTH_READ.value,
    },
    Role.GUEST.value: {
        Permission.HEALTH_READ.value,
        Permission.EVENTS_READ.value,
        Permission.EVENTS_WRITE.value,
        Permission.DECISIONS_READ.value,
        Permission.DECISIONS_EVALUATE.value,
        Permission.AGENTS_READ.value,
        Permission.POLICIES_READ.value,
        Permission.APPROVALS_READ.value,
        Permission.APPROVALS_WRITE.value,
        Permission.AUDIT_READ.value,
    },
}


# ---------------------------------------------------------------------------
# Auth Context Model
# ---------------------------------------------------------------------------


class AuthContext(BaseModel):
    """
    Principal security identity and evaluated permissions for a request.
    Carries verified user attributes, assigned roles, and granted permissions.
    """

    user_id: str = "anonymous"
    authenticated: bool = False
    roles: List[str] = Field(default_factory=list)
    permissions: Set[str] = Field(default_factory=set)
    client_id: Optional[str] = None
    email: Optional[str] = None
    issuer: Optional[str] = None
    claims: Dict[str, Any] = Field(default_factory=dict)
    tenant_id: Optional[str] = None
    organization_id: Optional[str] = None
    environment: Optional[str] = None

    def has_permission(self, permission: str) -> bool:
        """Determines if the principal has been granted a specific permission or wildcard."""
        if Permission.ALL.value in self.permissions or "*" in self.permissions:
            return True
        return permission in self.permissions

    def has_role(self, role: str) -> bool:
        """Determines if the principal holds the given role (case-insensitive)."""
        target = role.lower()
        return any(r.lower() == target for r in self.roles)

    def to_enterprise_context(
        self,
        default_tenant_id: str = "default-tenant",
    ) -> Any:
        """Converts AuthContext to an enterprise EnterpriseContext."""
        from runtimeverify.enterprise.context import EnterpriseContext
        from runtimeverify.enterprise.models import Environment as Env

        try:
            env = Env(self.environment) if self.environment else Env.DEVELOPMENT
        except ValueError:
            env = Env.DEVELOPMENT

        return EnterpriseContext(
            tenant_id=self.tenant_id or default_tenant_id,
            organization_id=self.organization_id,
            environment=env,
            actor_id=self.user_id,
            roles=self.roles,
            permissions=self.permissions,
        )


# ---------------------------------------------------------------------------
# AuthProvider Abstract Base Class
# ---------------------------------------------------------------------------


class AuthProvider(ABC):
    """
    Abstract authentication provider interface.
    Extracts security credentials from an incoming request and evaluates an AuthContext.
    """

    @abstractmethod
    async def authenticate(self, request: Request) -> AuthContext:
        """
        Authenticates the incoming request.
        Must return an AuthContext or raise HTTPException(status_code=401/403).
        """
        pass


# ---------------------------------------------------------------------------
# Concrete Auth Providers
# ---------------------------------------------------------------------------


class AnonymousAuthProvider(AuthProvider):
    """
    Default provider allowing unauthenticated or developer-mode requests.
    Assigns the 'guest' role with broad permissions for local execution.
    """

    def __init__(self, allow_all: bool = True):
        self.allow_all = allow_all

    async def authenticate(self, request: Request) -> AuthContext:
        perms = set()
        if self.allow_all:
            for p_set in DEFAULT_ROLE_PERMISSIONS.values():
                perms.update(p_set)
        else:
            perms = set(DEFAULT_ROLE_PERMISSIONS.get(Role.GUEST.value, set()))

        return AuthContext(
            user_id="anonymous",
            authenticated=False,
            roles=[Role.GUEST.value],
            permissions=perms,
        )


class ApiKeyAuthProvider(AuthProvider):
    """
    API Key authentication provider supporting header-based API keys.
    Inspects 'X-API-Key' or 'Authorization: ApiKey <key>' headers.
    """

    def __init__(
        self,
        api_keys: Optional[Dict[str, Dict[str, Any]]] = None,
        allow_anonymous: bool = False,
    ):
        # api_keys mapping: { "raw_key": {"user_id": ..., "roles": [...], "permissions": [...]} }
        self.api_keys = api_keys or {}
        self.allow_anonymous = allow_anonymous

    def register_key(
        self,
        api_key: str,
        user_id: str,
        roles: Optional[List[str]] = None,
        permissions: Optional[List[str]] = None,
        client_id: Optional[str] = None,
    ) -> None:
        """Registers a valid API key with identity and permissions."""
        role_list = roles or [Role.OPERATOR.value]
        perm_set: Set[str] = set(permissions or [])
        for r in role_list:
            perm_set.update(DEFAULT_ROLE_PERMISSIONS.get(r, set()))

        self.api_keys[api_key] = {
            "user_id": user_id,
            "roles": role_list,
            "permissions": list(perm_set),
            "client_id": client_id,
        }

    async def authenticate(self, request: Request) -> AuthContext:
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("ApiKey "):
                api_key = auth_header.split(" ", 1)[1].strip()

        if not api_key:
            if self.allow_anonymous:
                return await AnonymousAuthProvider(allow_all=False).authenticate(request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing API Key or Authorization header",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        if api_key not in self.api_keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API Key provided",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        record = self.api_keys[api_key]
        return AuthContext(
            user_id=record["user_id"],
            authenticated=True,
            roles=record.get("roles", []),
            permissions=set(record.get("permissions", [])),
            client_id=record.get("client_id"),
            tenant_id=record.get("tenant_id"),
            organization_id=record.get("organization_id"),
            environment=record.get("environment"),
        )


class OIDCAuthProvider(AuthProvider):
    """
    OpenID Connect (OIDC) JWT Bearer Authentication Provider.
    Engineered to integrate seamlessly with Keycloak, Okta, and enterprise OIDC identity providers.
    Decodes and verifies standard JWT claims, Keycloak realm_access/resource_access roles,
    and maps them to RuntimeVerify permissions.
    """

    def __init__(
        self,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        jwks_uri: Optional[str] = None,
        token_verifier: Optional[Callable[[str], Dict[str, Any]]] = None,
        allow_anonymous: bool = False,
    ):
        self.issuer = issuer
        self.audience = audience
        self.jwks_uri = jwks_uri
        self.token_verifier = token_verifier or self._default_jwt_decode
        self.allow_anonymous = allow_anonymous

    @staticmethod
    def _default_jwt_decode(token: str) -> Dict[str, Any]:
        """
        Parses standard JWT unverified payload for claim extraction.
        In production, users supply a token_verifier utilizing PyJWT with cryptographic JWKS keys.
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError("Malformed JWT structure: expected 3 dot-separated segments")
            payload_segment = parts[1]
            # Standard Base64 URL decoding with padding
            rem = len(payload_segment) % 4
            if rem > 0:
                payload_segment += "=" * (4 - rem)
            decoded_bytes = base64.urlsafe_b64decode(payload_segment)
            claims = json.loads(decoded_bytes.decode("utf-8"))
            return claims
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid JWT Bearer token: {e}",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

    async def authenticate(self, request: Request) -> AuthContext:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header or not auth_header.startswith("Bearer "):
            if self.allow_anonymous:
                return await AnonymousAuthProvider(allow_all=False).authenticate(request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Bearer Authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header.split(" ", 1)[1].strip()
        claims = self.token_verifier(token)

        # Validate standard token expiration if present
        exp = claims.get("exp")
        if exp is not None:
            if time.time() > float(exp):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="JWT Bearer token has expired",
                    headers={"WWW-Authenticate": 'Bearer error="token_expired"'},
                )

        # Validate issuer if configured
        if self.issuer and claims.get("iss") != self.issuer:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"JWT issuer mismatch: expected '{self.issuer}'",
                headers={"WWW-Authenticate": 'Bearer error="invalid_issuer"'},
            )

        # Validate audience if configured
        if self.audience:
            token_aud = claims.get("aud")
            aud_valid = False
            if isinstance(token_aud, list):
                aud_valid = self.audience in token_aud
            elif isinstance(token_aud, str):
                aud_valid = token_aud == self.audience
            if not aud_valid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"JWT audience mismatch: expected '{self.audience}'",
                    headers={"WWW-Authenticate": 'Bearer error="invalid_audience"'},
                )

        # Extract identity
        user_id = claims.get("sub") or claims.get("preferred_username") or "oidc-principal"
        client_id = claims.get("azp") or claims.get("client_id")
        email = claims.get("email")

        # Extract Keycloak roles from realm_access and resource_access
        extracted_roles: Set[str] = set()
        if "roles" in claims and isinstance(claims["roles"], list):
            extracted_roles.update(claims["roles"])

        realm_access = claims.get("realm_access")
        if isinstance(realm_access, dict):
            realm_roles = realm_access.get("roles", [])
            if isinstance(realm_roles, list):
                extracted_roles.update(realm_roles)

        if client_id and "resource_access" in claims:
            res_access = claims.get("resource_access", {})
            if isinstance(res_access, dict) and client_id in res_access:
                c_roles = res_access[client_id].get("roles", [])
                if isinstance(c_roles, list):
                    extracted_roles.update(c_roles)

        # Map roles to permissions
        permissions: Set[str] = set()
        # If user has explicit scopes (OAuth2)
        scope_str = claims.get("scope", "")
        if scope_str:
            for s in scope_str.split():
                permissions.add(s)

        for r in extracted_roles:
            permissions.update(DEFAULT_ROLE_PERMISSIONS.get(r, set()))

        # If no explicit role mapped, default to viewer role
        if not extracted_roles:
            extracted_roles.add(Role.VIEWER.value)
            permissions.update(DEFAULT_ROLE_PERMISSIONS[Role.VIEWER.value])

        tenant_id = (
            claims.get("tenant_id")
            or claims.get("tenant")
            or (
                claims.get("attributes", {}).get("tenant_id", [None])[0]
                if isinstance(claims.get("attributes"), dict)
                else None
            )
        )
        org_id = (
            claims.get("organization_id")
            or claims.get("org")
            or (
                claims.get("attributes", {}).get("organization_id", [None])[0]
                if isinstance(claims.get("attributes"), dict)
                else None
            )
        )

        return AuthContext(
            user_id=user_id,
            authenticated=True,
            roles=list(extracted_roles),
            permissions=permissions,
            client_id=client_id,
            email=email,
            issuer=claims.get("iss"),
            claims=claims,
            tenant_id=tenant_id,
            organization_id=org_id,
            environment=claims.get("environment"),
        )


class CompositeAuthProvider(AuthProvider):
    """
    Chains multiple AuthProviders in sequence.
    Evaluates Bearer/OIDC first, then API Key, falling back to Anonymous if permitted.
    """

    def __init__(self, providers: List[AuthProvider]):
        self.providers = providers

    async def authenticate(self, request: Request) -> AuthContext:
        last_error = None
        for provider in self.providers:
            try:
                ctx = await provider.authenticate(request)
                if ctx.authenticated:
                    return ctx
            except HTTPException as e:
                last_error = e
                continue

        # If any provider returned an unauthenticated context (e.g. Anonymous)
        for provider in self.providers:
            if isinstance(provider, AnonymousAuthProvider):
                return await provider.authenticate(request)

        if last_error:
            raise last_error

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: No valid credentials supplied",
        )


# ---------------------------------------------------------------------------
# Global Auth Registry & FastAPI Dependencies
# ---------------------------------------------------------------------------

_global_auth_provider: AuthProvider = AnonymousAuthProvider(allow_all=True)
_auth_provider_lock = threading.Lock()


def get_auth_provider() -> AuthProvider:
    """Returns the globally configured AuthProvider."""
    with _auth_provider_lock:
        return _global_auth_provider


def set_auth_provider(provider: AuthProvider) -> None:
    """Sets the globally configured AuthProvider."""
    global _global_auth_provider
    with _auth_provider_lock:
        _global_auth_provider = provider


async def get_current_auth(request: Request) -> AuthContext:
    """FastAPI dependency: resolves the authenticated principal for the current request."""
    provider = get_auth_provider()
    return await provider.authenticate(request)


def require_authenticated() -> Callable[..., Any]:
    """Dependency factory: requires the client to be authenticated."""

    async def dependency(ctx: AuthContext = Depends(get_current_auth)) -> AuthContext:
        if not ctx.authenticated:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required to access this resource",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return ctx

    return dependency


def require_permission(permission: str) -> Callable[..., Any]:
    """Dependency factory: enforces fine-grained permission authorization."""

    async def dependency(ctx: AuthContext = Depends(get_current_auth)) -> AuthContext:
        if not ctx.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Principal lacks required permission '{permission}'",
            )
        return ctx

    return dependency


def require_role(role: str) -> Callable[..., Any]:
    """Dependency factory: enforces RBAC role authorization."""

    async def dependency(ctx: AuthContext = Depends(get_current_auth)) -> AuthContext:
        if not ctx.has_role(role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Principal lacks required role '{role}'",
            )
        return ctx

    return dependency
