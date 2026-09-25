"""
Authentication Architecture for Enterprise RuntimeVerify (Phase 18).
Provides vendor-neutral OIDC/OAuth2 abstractions, Keycloak/Okta/Azure claim mappers,
cryptographically hashed enterprise API keys with environment scoping,
and service-to-service machine authentication without vendor lock-in.
"""

from abc import ABC, abstractmethod
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field

from runtimeverify.enterprise.models import ActorType, Environment
from runtimeverify.enterprise.rbac import Subject

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# OIDC Claims Model and Pluggable Claims Extractors
# ---------------------------------------------------------------------------


class OIDCClaims(BaseModel):
    """
    Standardized, vendor-neutral OpenID Connect claims payload.
    """

    model_config = ConfigDict(frozen=True)

    issuer: str = Field(..., description="Token issuer (iss)")
    subject: str = Field(..., description="Principal identifier (sub)")
    audience: List[str] = Field(default_factory=list, description="Target audience (aud)")
    expires_at: Optional[int] = Field(None, description="Expiration UNIX epoch (exp)")
    issued_at: Optional[int] = Field(None, description="Issued UNIX epoch (iat)")
    not_before: Optional[int] = Field(None, description="Not before UNIX epoch (nbf)")
    username: Optional[str] = None
    email: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    tenant_id: Optional[str] = None
    organization_id: Optional[str] = None
    raw_claims: Dict[str, Any] = Field(default_factory=dict)


class ClaimsExtractor(ABC):
    """
    Abstract interface for mapping vendor-specific JWT claim trees into standardized OIDCClaims.
    """

    @abstractmethod
    def extract_claims(self, payload: Dict[str, Any]) -> OIDCClaims:
        """Transforms vendor-specific claims dictionary into normalized OIDCClaims."""
        pass


class KeycloakClaimsExtractor(ClaimsExtractor):
    """
    Claims extractor compatible with Keycloak OIDC realms and clients.
    Extracts realm_access.roles, resource_access.{client_id}.roles, and custom attributes.
    """

    def __init__(self, client_id: Optional[str] = None, default_tenant_id: Optional[str] = None):
        self.client_id = client_id
        self.default_tenant_id = default_tenant_id

    def extract_claims(self, payload: Dict[str, Any]) -> OIDCClaims:
        roles: List[str] = []

        # 1. Realm roles
        realm_access = payload.get("realm_access", {})
        if isinstance(realm_access, dict):
            roles.extend(realm_access.get("roles", []))

        # 2. Client-specific resource roles
        if self.client_id:
            res_access = payload.get("resource_access", {}).get(self.client_id, {})
            if isinstance(res_access, dict):
                roles.extend(res_access.get("roles", []))

        # 3. Audience normalization
        aud = payload.get("aud", [])
        if isinstance(aud, str):
            aud_list = [aud]
        elif isinstance(aud, list):
            aud_list = [str(a) for a in aud]
        else:
            aud_list = []

        # 4. Tenant and Org mapping from user attributes
        tenant_id = (
            payload.get("tenant_id")
            or payload.get("tenant")
            or (
                payload.get("attributes", {}).get("tenant_id", [None])[0]
                if isinstance(payload.get("attributes"), dict)
                else None
            )
            or self.default_tenant_id
        )

        org_id = (
            payload.get("organization_id")
            or payload.get("org")
            or (
                payload.get("attributes", {}).get("organization_id", [None])[0]
                if isinstance(payload.get("attributes"), dict)
                else None
            )
        )

        return OIDCClaims(
            issuer=str(payload.get("iss", "keycloak")),
            subject=str(payload.get("sub", "")),
            audience=aud_list,
            expires_at=payload.get("exp"),
            issued_at=payload.get("iat"),
            not_before=payload.get("nbf"),
            username=payload.get("preferred_username"),
            email=payload.get("email"),
            roles=list(set(roles)),
            groups=payload.get("groups", []),
            tenant_id=tenant_id,
            organization_id=org_id,
            raw_claims=payload,
        )


class GenericOIDCClaimsExtractor(ClaimsExtractor):
    """
    Standard vendor-neutral OIDC claims extractor supporting standard roles/groups claims.
    Compatible with Okta, Auth0, and Azure AD.
    """

    def __init__(self, default_tenant_id: Optional[str] = None):
        self.default_tenant_id = default_tenant_id

    def extract_claims(self, payload: Dict[str, Any]) -> OIDCClaims:
        raw_roles = payload.get("roles") or payload.get("groups") or []
        if isinstance(raw_roles, str):
            roles = [r.strip() for r in raw_roles.split(",") if r.strip()]
        elif isinstance(raw_roles, list):
            roles = [str(r) for r in raw_roles]
        else:
            roles = []

        aud = payload.get("aud", [])
        aud_list = [aud] if isinstance(aud, str) else [str(a) for a in aud]

        return OIDCClaims(
            issuer=str(payload.get("iss", "oidc-provider")),
            subject=str(payload.get("sub", "")),
            audience=aud_list,
            expires_at=payload.get("exp"),
            issued_at=payload.get("iat"),
            not_before=payload.get("nbf"),
            username=payload.get("preferred_username") or payload.get("name"),
            email=payload.get("email"),
            roles=roles,
            groups=payload.get("groups", []),
            tenant_id=payload.get("tenant_id") or payload.get("tid") or self.default_tenant_id,
            organization_id=payload.get("organization_id"),
            raw_claims=payload,
        )


# ---------------------------------------------------------------------------
# JWT Token Validator
# ---------------------------------------------------------------------------


class TokenValidationError(Exception):
    """Raised when JWT validation fails."""

    pass


class TokenValidator:
    """
    Validates JWT tokens with signature, audience, issuer, and expiration checks.
    Decoupled from specific cryptography libraries; supports custom verifier hooks.
    """

    def __init__(
        self,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        claims_extractor: Optional[ClaimsExtractor] = None,
        crypto_verifier: Optional[Callable[[str], Dict[str, Any]]] = None,
        clock_skew_seconds: int = 30,
    ):
        self.issuer = issuer
        self.audience = audience
        self.claims_extractor = claims_extractor or GenericOIDCClaimsExtractor()
        self.crypto_verifier = crypto_verifier
        self.clock_skew_seconds = clock_skew_seconds

    def validate_token(self, token: str) -> OIDCClaims:
        """
        Validates token structure, cryptographic signature (if verifier set),
        standard temporal constraints, and returns normalized OIDCClaims.
        """
        if not token:
            raise TokenValidationError("Token string cannot be empty")

        payload: Dict[str, Any]
        if self.crypto_verifier:
            try:
                payload = self.crypto_verifier(token)
            except Exception as e:
                raise TokenValidationError(f"Cryptographic signature verification failed: {e}") from e
        else:
            payload = self._parse_jwt_payload_unverified(token)

        # Validate temporal constraints
        now = int(time.time())
        exp = payload.get("exp")
        if exp is not None and (now - self.clock_skew_seconds) > exp:
            raise TokenValidationError(f"Token has expired (exp: {exp}, now: {now})")

        nbf = payload.get("nbf")
        if nbf is not None and (now + self.clock_skew_seconds) < nbf:
            raise TokenValidationError(f"Token not valid yet (nbf: {nbf}, now: {now})")

        # Validate issuer
        if self.issuer and payload.get("iss") != self.issuer:
            raise TokenValidationError(f"Issuer mismatch: expected '{self.issuer}', got '{payload.get('iss')}'")

        # Validate audience
        if self.audience:
            token_aud = payload.get("aud")
            valid_aud = False
            if isinstance(token_aud, str) and token_aud == self.audience:
                valid_aud = True
            elif isinstance(token_aud, list) and self.audience in token_aud:
                valid_aud = True
            if not valid_aud:
                raise TokenValidationError(f"Audience mismatch: token audience does not contain '{self.audience}'")

        return self.claims_extractor.extract_claims(payload)

    @staticmethod
    def _parse_jwt_payload_unverified(token: str) -> Dict[str, Any]:
        """Base64URL decodes unverified JWT payload segment."""
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenValidationError("Invalid JWT format: expected 3 dot-separated segments")
        payload_segment = parts[1]
        rem = len(payload_segment) % 4
        if rem > 0:
            payload_segment += "=" * (4 - rem)
        try:
            decoded = base64.urlsafe_b64decode(payload_segment)
            return json.loads(decoded.decode("utf-8"))
        except Exception as e:
            raise TokenValidationError(f"Malformed JWT payload: {e}") from e


# ---------------------------------------------------------------------------
# Enterprise API Key Management
# ---------------------------------------------------------------------------


class ApiKeyRecord(BaseModel):
    """
    Persisted metadata for an enterprise API key.
    The raw secret is NEVER stored; only a cryptographic SHA-256 hash is retained.
    """

    model_config = ConfigDict(frozen=True)

    key_id: str = Field(..., description="Public identifier segment of API key")
    hashed_secret: str = Field(..., description="SHA-256 digest of secret component")
    tenant_id: str = Field(...)
    organization_id: Optional[str] = None
    project_id: Optional[str] = None
    environment: Environment = Field(...)
    name: str = Field(...)
    roles: List[str] = Field(default_factory=lambda: ["developer"])
    created_at: int = Field(default_factory=lambda: int(time.time()))
    expires_at: Optional[int] = None
    revoked: bool = Field(default=False)


class EnterpriseApiKeyManager:
    """
    Generates, hashes, stores, and validates environment-scoped enterprise API keys.
    Key format: `rv_<env_prefix>_<key_id>_<secret>`
    Example: `rv_live_k10a8f7c_93f821ba...` or `rv_test_k88b12e3_12ac94df...`
    """

    def __init__(self) -> None:
        # Key storage index: key_id -> ApiKeyRecord
        self._keys: Dict[str, ApiKeyRecord] = {}

    def generate_api_key(
        self,
        tenant_id: str,
        name: str,
        environment: Environment,
        organization_id: Optional[str] = None,
        project_id: Optional[str] = None,
        roles: Optional[List[str]] = None,
        ttl_seconds: Optional[int] = None,
    ) -> Tuple[str, ApiKeyRecord]:
        """
        Creates a new cryptographically secure API key.
        Returns (raw_key, record). The caller must present raw_key once to the user.
        """
        env_prefix = "live" if environment == Environment.PRODUCTION else "test"
        key_id = f"k{secrets.token_hex(4)}"
        secret = secrets.token_hex(24)
        raw_key = f"rv_{env_prefix}_{key_id}_{secret}"

        hashed_secret = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        expires_at = int(time.time() + ttl_seconds) if ttl_seconds else None

        record = ApiKeyRecord(
            key_id=key_id,
            hashed_secret=hashed_secret,
            tenant_id=tenant_id,
            organization_id=organization_id,
            project_id=project_id,
            environment=environment,
            name=name,
            roles=roles or ["developer"],
            expires_at=expires_at,
        )

        self._keys[key_id] = record
        return raw_key, record

    def verify_api_key(self, raw_key: str) -> Optional[ApiKeyRecord]:
        """
        Validates raw API key format, hash matching, expiration, and revocation status.
        """
        if not raw_key.startswith("rv_"):
            return None

        parts = raw_key.split("_", 3)
        if len(parts) != 4:
            return None

        _, env_prefix, key_id, secret = parts

        record = self._keys.get(key_id)
        if not record or record.revoked:
            return None

        # Environment prefix match
        if env_prefix == "live" and record.environment != Environment.PRODUCTION:
            return None
        if env_prefix == "test" and record.environment == Environment.PRODUCTION:
            return None

        # Expiration check
        if record.expires_at and int(time.time()) > record.expires_at:
            return None

        # Constant-time hash comparison
        computed_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(computed_hash, record.hashed_secret):
            return None

        return record

    def revoke_key(self, key_id: str) -> bool:
        """Revokes an existing API key by key_id."""
        record = self._keys.get(key_id)
        if not record:
            return False
        # Create updated revoked record (BaseModel frozen)
        updated = ApiKeyRecord(
            key_id=record.key_id,
            hashed_secret=record.hashed_secret,
            tenant_id=record.tenant_id,
            organization_id=record.organization_id,
            project_id=record.project_id,
            environment=record.environment,
            name=record.name,
            roles=record.roles,
            created_at=record.created_at,
            expires_at=record.expires_at,
            revoked=True,
        )
        self._keys[key_id] = updated
        return True


# ---------------------------------------------------------------------------
# Service-to-Service Machine Authentication
# ---------------------------------------------------------------------------


class ServiceAssertionToken(BaseModel):
    """
    Signed service assertion token used for mutual machine-to-machine authentication.
    """

    model_config = ConfigDict(frozen=True)

    service_name: str
    tenant_id: str
    issued_at: int
    expires_at: int
    signature: str


class ServiceToServiceAuth:
    """
    Manages mutual machine-to-machine assertion generation and verification
    using HMAC-SHA256 signatures and strict audience constraints.
    """

    def __init__(self, shared_secret: str, expected_service_audience: str = "runtimeverify-core"):
        self._secret = shared_secret.encode("utf-8")
        self.expected_audience = expected_service_audience

    def create_service_token(self, service_name: str, tenant_id: str, ttl_seconds: int = 300) -> str:
        """Issues an ephemeral signed service assertion token."""
        now = int(time.time())
        exp = now + ttl_seconds
        payload_data = f"{service_name}:{tenant_id}:{self.expected_audience}:{now}:{exp}"
        signature = hmac.new(self._secret, payload_data.encode("utf-8"), hashlib.sha256).hexdigest()
        token_dict = {
            "service_name": service_name,
            "tenant_id": tenant_id,
            "audience": self.expected_audience,
            "iat": now,
            "exp": exp,
            "sig": signature,
        }
        token_json = json.dumps(token_dict)
        return base64.urlsafe_b64encode(token_json.encode("utf-8")).decode("utf-8")

    def verify_service_token(self, token_str: str) -> Optional[Subject]:
        """Verifies service token authenticity and returns a machine Subject."""
        try:
            decoded_json = base64.urlsafe_b64decode(token_str.encode("utf-8")).decode("utf-8")
            data = json.loads(decoded_json)
        except Exception:
            return None

        service_name = data.get("service_name")
        tenant_id = data.get("tenant_id")
        audience = data.get("audience")
        iat = data.get("iat")
        exp = data.get("exp")
        sig = data.get("sig")

        if not all([service_name, tenant_id, audience, iat, exp, sig]):
            return None

        if audience != self.expected_audience:
            return None

        now = int(time.time())
        if now > exp:
            return None

        expected_payload = f"{service_name}:{tenant_id}:{audience}:{iat}:{exp}"
        expected_sig = hmac.new(self._secret, expected_payload.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(sig, expected_sig):
            return None

        return Subject(
            id=f"service:{service_name}",
            type=ActorType.SERVICE,
            tenant_id=tenant_id,
            roles=["agent_service"],
        )
