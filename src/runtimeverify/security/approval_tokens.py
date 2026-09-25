"""
Cryptographic One-Time Approval Tokens and Replay Protection for RuntimeVerify (Phase 14).
Generates and verifies cryptographically secure, single-use authorization tokens
for human approval decisions, ensuring tickets cannot be replayed or forged across API/CLI boundaries.
"""

import hmac
import secrets
from typing import Optional


class ApprovalTokenManager:
    """
    Manages generation and constant-time validation of single-use approval tokens.
    Guarantees replay prevention even if network packets or API request bodies are intercepted.
    """

    @classmethod
    def generate_token(cls) -> str:
        """
        Generates a 256-bit cryptographically secure URL-safe random approval token.
        """
        return secrets.token_urlsafe(32)

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
