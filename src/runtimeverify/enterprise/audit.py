"""
Enterprise Audit Ownership and Tamper-Evident Verification for RuntimeVerify (Phase 18).
Implements explicit enterprise ownership, SHA-256 cryptographic chain linking,
and verification against tampering.
"""

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import threading
from typing import Dict, List, Optional, Tuple

from runtimeverify.enterprise.models import (
    ActorType,
    AuditOwnership,
    Environment,
)


class EnterpriseAuditManager:
    """
    Manages immutable enterprise audit records with explicit tenant/org/project ownership
    and cryptographically verifiable SHA-256 hash chains per partition.
    """

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # partition_key (f"{tenant_id}:{environment.value}") -> list of AuditOwnership records in chronological order
        self._chains: Dict[str, List[AuditOwnership]] = defaultdict(list)
        # record_id -> AuditOwnership
        self._record_index: Dict[str, AuditOwnership] = {}

    def _get_partition_key(self, tenant_id: str, environment: Environment) -> str:
        return f"{tenant_id}:{environment.value}"

    def record_entry(
        self,
        tenant_id: str,
        organization_id: str,
        project_id: str,
        environment: Environment,
        actor_id: str,
        action: str,
        verdict: str,
        event_id: str,
        actor_type: ActorType = ActorType.AGENT,
        session_id: Optional[str] = None,
        decision_id: Optional[str] = None,
    ) -> AuditOwnership:
        """
        Appends a new cryptographically chained audit record to the tenant/environment partition.
        """
        with self._lock:
            partition_key = self._get_partition_key(tenant_id, environment)
            chain = self._chains[partition_key]

            prev_hash = chain[-1].hash if len(chain) > 0 else self.GENESIS_HASH
            timestamp = datetime.now(timezone.utc)

            # Compute entry hash
            payload = {
                "prev_hash": prev_hash,
                "tenant_id": tenant_id,
                "organization_id": organization_id,
                "project_id": project_id,
                "environment": environment.value,
                "actor_id": actor_id,
                "actor_type": actor_type.value,
                "action": action,
                "verdict": verdict,
                "event_id": event_id,
                "decision_id": decision_id,
                "session_id": session_id,
                "timestamp": timestamp.isoformat(),
            }
            serialized = json.dumps(payload, sort_keys=True)
            entry_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

            entry = AuditOwnership(
                tenant_id=tenant_id,
                organization_id=organization_id,
                project_id=project_id,
                environment=environment,
                session_id=session_id,
                event_id=event_id,
                decision_id=decision_id,
                actor_id=actor_id,
                actor_type=actor_type,
                action=action,
                verdict=verdict,
                hash=entry_hash,
                prev_hash=prev_hash,
                timestamp=timestamp,
            )

            chain.append(entry)
            self._record_index[entry.id] = entry
            return entry

    def verify_chain(self, tenant_id: str, environment: Environment) -> Tuple[bool, Optional[str]]:
        """
        Cryptographically verifies the audit hash chain for a tenant and environment partition.
        Returns (is_valid, error_reason).
        """
        with self._lock:
            partition_key = self._get_partition_key(tenant_id, environment)
            chain = self._chains.get(partition_key, [])

            if not chain:
                return True, None

            expected_prev_hash = self.GENESIS_HASH
            for i, entry in enumerate(chain):
                if entry.prev_hash != expected_prev_hash:
                    return (
                        False,
                        f"Audit chain broken at index {i} (id: {entry.id}): prev_hash mismatch. Expected {expected_prev_hash}, found {entry.prev_hash}.",
                    )

                # Recompute digest
                payload = {
                    "prev_hash": entry.prev_hash,
                    "tenant_id": entry.tenant_id,
                    "organization_id": entry.organization_id,
                    "project_id": entry.project_id,
                    "environment": entry.environment.value,
                    "actor_id": entry.actor_id,
                    "actor_type": entry.actor_type.value,
                    "action": entry.action,
                    "verdict": entry.verdict,
                    "event_id": entry.event_id,
                    "decision_id": entry.decision_id,
                    "session_id": entry.session_id,
                    "timestamp": entry.timestamp.isoformat(),
                }
                serialized = json.dumps(payload, sort_keys=True)
                computed_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

                if computed_hash != entry.hash:
                    return (
                        False,
                        f"Audit record tampering detected at index {i} (id: {entry.id}): digest mismatch. Stored {entry.hash}, computed {computed_hash}.",
                    )

                expected_prev_hash = entry.hash

            return True, None

    def query_records(
        self,
        tenant_id: str,
        environment: Optional[Environment] = None,
        session_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditOwnership]:
        """
        Queries audit records within strict tenant isolation boundary.
        """
        with self._lock:
            results: List[AuditOwnership] = []
            environments_to_check = [environment] if environment else list(Environment)

            for env in environments_to_check:
                pkey = self._get_partition_key(tenant_id, env)
                for entry in reversed(self._chains.get(pkey, [])):
                    if session_id and entry.session_id != session_id:
                        continue
                    if actor_id and entry.actor_id != actor_id:
                        continue
                    results.append(entry)
                    if len(results) >= limit:
                        return results

            return results
