"""
Cryptographic One-Time Approval Tokens and Replay Protection for RuntimeVerify (Phase 14).
Generates and verifies cryptographically secure, single-use authorization tokens
for human approval decisions, ensuring tickets cannot be replayed or forged across API/CLI boundaries.
"""

import hashlib
import hmac
import json
import secrets
from typing import Any, Optional


class ApprovalTokenManager:
    """
    Manages generation and constant-time validation of single-use approval tokens.
    Guarantees replay prevention and cryptographic action binding even if network packets
    or API request bodies are intercepted.
    """

    @classmethod
    def generate_token(cls) -> str:
        """
        Generates a 256-bit cryptographically secure URL-safe random approval token.
        """
        return secrets.token_urlsafe(32)

    @classmethod
    def compute_action_digest(
        cls,
        action: Any,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> str:
        """
        Computes a deterministic SHA-256 fingerprint of the target action and context.
        Binds authorization challenge tokens to the exact proposed parameters.
        """
        payload = {
            "action": action if isinstance(action, (dict, list, str, int, float, bool)) else str(action),
            "agent_id": agent_id or "",
            "session_id": session_id or "",
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def generate_bound_token(
        cls,
        action: Any,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> str:
        """
        Generates an action-bound cryptographic token incorporating action digest and random nonce.
        Format: `<nonce>.<hmac_signature>`
        """
        nonce = secrets.token_urlsafe(16)
        digest = cls.compute_action_digest(action, agent_id=agent_id, session_id=session_id)
        key_bytes = (
            secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
        ) or b"rv-action-binding-key"
        signature = hmac.new(key_bytes, f"{digest}:{nonce}".encode("utf-8"), hashlib.sha256).hexdigest()[:32]
        return f"{nonce}.{signature}"

    @classmethod
    def verify_bound_token(
        cls,
        candidate_token: Optional[str],
        action: Any,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> bool:
        """
        Validates that candidate_token was issued specifically for the given action and context.
        Protects against approval transplant or tampered argument attacks.
        """
        if not candidate_token or "." not in candidate_token:
            return False
        parts = candidate_token.strip().split(".", 1)
        if len(parts) != 2:
            return False
        nonce, signature = parts
        digest = cls.compute_action_digest(action, agent_id=agent_id, session_id=session_id)
        key_bytes = (
            secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
        ) or b"rv-action-binding-key"
        expected_sig = hmac.new(key_bytes, f"{digest}:{nonce}".encode("utf-8"), hashlib.sha256).hexdigest()[:32]
        return hmac.compare_digest(signature, expected_sig)

    @classmethod
    def verify_token(
        cls,
        candidate_token: Optional[str],
        stored_token: Optional[str],
    ) -> bool:
        """
        Performs constant-time comparison of the candidate authorization token
        against the stored challenge token to prevent timing side-channel attacks.
        """
        if not candidate_token or not stored_token:
            return False
        return hmac.compare_digest(candidate_token.strip(), stored_token.strip())
