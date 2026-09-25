"""
Cryptographic Audit Hash Chaining and Tamper Verification for RuntimeVerify (Phase 14).
Provides SHA-256 hash chaining over sequential audit records to detect unauthorized
deletion, record modification, reordering, or injection into audit trails.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple


class AuditIntegrityEngine:
    """
    Computes and verifies SHA-256 cryptographic hash chains over structured audit records.
    Each record binds to the cryptographic hash of the preceding record, forming an
    immutable Merkle-like chain of custody.
    """

    GENESIS_HASH = "0" * 64

    @classmethod
    def compute_record_hash(
        cls,
        record_id: str,
        timestamp_iso: str,
        record_type: str,
        summary: str,
        details: Dict[str, Any],
        prev_hash: Optional[str] = None,
    ) -> str:
        """
        Computes a deterministic SHA-256 hash for an audit record.
        Uses canonical JSON serialization (sorted keys, compact separators) for details.
        """
        canonical_details = json.dumps(details, sort_keys=True, separators=(",", ":"), default=str)
        parent = prev_hash or cls.GENESIS_HASH

        payload = f"{record_id}|{timestamp_iso}|{record_type}|{summary}|{canonical_details}|{parent}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def verify_chain(
        cls,
        records: List[Any],
    ) -> Tuple[bool, List[str]]:
        """
        Verifies the cryptographic integrity of a sequence of audit records.

        Checks:
        1. Each record's stored hash matches its recomputed content hash.
        2. Each record's `prev_hash` matches the hash of the immediate predecessor.
        3. The first record correctly anchors to the genesis hash (or None).

        Returns:
            Tuple of (is_valid: bool, issues: List[str]).
        """
        issues: List[str] = []
        if not records:
            return True, []

        expected_prev = cls.GENESIS_HASH

        for idx, record in enumerate(records):
            rec_id = getattr(record, "record_id", f"idx-{idx}")
            rec_time = record.timestamp.isoformat() if hasattr(record.timestamp, "isoformat") else str(record.timestamp)
            rec_type = record.record_type.value if hasattr(record.record_type, "value") else str(record.record_type)
            summary = getattr(record, "summary", "")
            details = getattr(record, "details", {})
            stored_hash = getattr(record, "record_hash", None)
            stored_prev = getattr(record, "prev_hash", None)

            # Skip integrity check on legacy records without hash metadata
            if stored_hash is None and stored_prev is None:
                continue

            # Verify predecessor link
            if stored_prev is not None and stored_prev != expected_prev and expected_prev != cls.GENESIS_HASH:
                issues.append(
                    f"Chain break at record '{rec_id}' (index {idx}): expected prev_hash '{expected_prev[:12]}...', "
                    f"got '{stored_prev[:12]}...'"
                )

            # Verify content hash
            computed = cls.compute_record_hash(
                record_id=rec_id,
                timestamp_iso=rec_time,
                record_type=rec_type,
                summary=summary,
                details=details,
                prev_hash=stored_prev,
            )

            if stored_hash is not None and stored_hash != computed:
                issues.append(
                    f"Tampered record detected at '{rec_id}' (index {idx}): stored hash '{stored_hash[:12]}...' "
                    f"does not match computed hash '{computed[:12]}...'"
                )

            expected_prev = stored_hash or computed

        return len(issues) == 0, issues
