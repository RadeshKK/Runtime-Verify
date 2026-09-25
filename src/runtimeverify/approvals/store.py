"""
Thread-safe approval registry and audit store for RuntimeVerify (Phase 7).
Ensures replay prevention, authorization validation, expiration enforcement, and full audit logging.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Set

from runtimeverify.approvals.exceptions import (
    ApprovalExpiredError,
    DuplicateApprovalError,
    UnauthorizedApproverError,
    UnknownApprovalRequestError,
)
from runtimeverify.approvals.models import (
    ApprovalAuditEntry,
    ApprovalDecision,
    ApprovalDecisionType,
    ApprovalRequest,
    ApprovalStatus,
)

logger = logging.getLogger(__name__)


class ApprovalStore:
    """
    In-memory and file-persisted registry for human approval workflows.
    Guarantees strict linear state transitions:
    PENDING -> APPROVED | DENIED | EXPIRED | CANCELLED
    """

    def __init__(self, persistence_path: Optional[str] = None):
        self._lock = threading.RLock()
        self._requests: Dict[str, ApprovalRequest] = {}
        self._audit_log: List[ApprovalAuditEntry] = []
        self._persistence_path = persistence_path
        self._load_if_exists()

    def _load_if_exists(self) -> None:
        if not self._persistence_path:
            return
        path = Path(self._persistence_path)
        if not path.exists():
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                requests = data.get("requests", {})
                for req_id, req_data in requests.items():
                    self._requests[req_id] = ApprovalRequest.model_validate(req_data)
                audits = data.get("audit_log", [])
                for a in audits:
                    self._audit_log.append(ApprovalAuditEntry.model_validate(a))
            logger.debug("Loaded %d approval requests from %s", len(self._requests), path)
        except Exception as e:
            logger.warning("Failed to load approval store from '%s': %s", path, e)

    def _persist(self) -> None:
        if not self._persistence_path:
            return
        try:
            path = Path(self._persistence_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "requests": {k: v.model_dump(mode="json") for k, v in self._requests.items()},
                "audit_log": [a.model_dump(mode="json") for a in self._audit_log],
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
        except Exception as e:
            logger.warning("Failed to persist approval store to '%s': %s", self._persistence_path, e)

    def save_request(self, request: ApprovalRequest) -> ApprovalRequest:
        """Stores a new approval request and registers creation audit."""
        with self._lock:
            self._requests[request.request_id] = request
            self.record_audit(
                request_id=request.request_id,
                event_type="REQUEST_CREATED",
                actor=request.agent_id or "system",
                details={
                    "risk": request.risk,
                    "reason": request.reason,
                    "expiration": request.expiration.isoformat(),
                    "action_type": request.action.get("action_type") if isinstance(request.action, dict) else "unknown",
                },
            )
            self._persist()
            return request

    create_request = save_request

    def get_request(self, request_id: str) -> ApprovalRequest:
        """Retrieves an approval request by ID, raising UnknownApprovalRequestError if absent."""
        with self._lock:
            # Sync from disk if persistence is enabled
            self._load_if_exists()
            self._auto_expire_unlocked(request_id)
            if request_id not in self._requests:
                raise UnknownApprovalRequestError(request_id)
            return self._requests[request_id]

    def peek_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Returns request without raising error if missing."""
        with self._lock:
            self._load_if_exists()
            self._auto_expire_unlocked(request_id)
            return self._requests.get(request_id)

    def list_requests(
        self,
        status: Optional[ApprovalStatus] = None,
        agent_id: Optional[str] = None,
    ) -> List[ApprovalRequest]:
        """Lists stored requests, applying expiration updates and optional filters."""
        with self._lock:
            self._load_if_exists()
            self.expire_stale_requests()
            results: List[ApprovalRequest] = []
            for req in self._requests.values():
                if status is not None and req.status != status:
                    continue
                if agent_id is not None and req.agent_id != agent_id:
                    continue
                results.append(req)
            return sorted(results, key=lambda r: r.created_at, reverse=True)

    def record_decision(
        self,
        request_id: str,
        decision: ApprovalDecision,
        authorized_approvers: Optional[Set[str]] = None,
        require_token: bool = False,
    ) -> ApprovalRequest:
        """
        Records an approver's verdict on an approval request.
        Enforces replay prevention, authorization bounds, and expiration checks.
        """
        with self._lock:
            self._load_if_exists()
            if request_id not in self._requests:
                raise UnknownApprovalRequestError(request_id)

            req = self._requests[request_id]

            # 1. Authorization check
            if authorized_approvers is not None and len(authorized_approvers) > 0:
                if decision.decided_by not in authorized_approvers:
                    self.record_audit(
                        request_id=request_id,
                        event_type="UNAUTHORIZED_DECISION_ATTEMPT",
                        actor=decision.decided_by,
                        details={"authorized_approvers": list(authorized_approvers)},
                    )
                    self._persist()
                    raise UnauthorizedApproverError(decision.decided_by, request_id)

            # 2. Expiration check
            if req.is_expired():
                req.status = ApprovalStatus.EXPIRED
                self.record_audit(
                    request_id=request_id,
                    event_type="EXPIRED",
                    actor="system:timeout",
                    details={"expiration": req.expiration.isoformat()},
                )
                self._persist()
                raise ApprovalExpiredError(request_id, req.expiration.isoformat())

            # 3. One-time approval token validation
            if decision.approval_token is not None or require_token:
                from runtimeverify.security.approval_tokens import ApprovalTokenManager

                if not ApprovalTokenManager.verify_token(decision.approval_token, req.approval_token):
                    self.record_audit(
                        request_id=request_id,
                        event_type="INVALID_APPROVAL_TOKEN",
                        actor=decision.decided_by,
                        details={"reason": "Invalid or expired single-use approval token provided"},
                    )
                    self._persist()
                    raise UnauthorizedApproverError(
                        f"Invalid or expired single-use approval token for ticket '{request_id}'", request_id
                    )

            # 4. Replay prevention check
            if req.status != ApprovalStatus.PENDING:
                self.record_audit(
                    request_id=request_id,
                    event_type="REPLAY_ATTEMPT_REJECTED",
                    actor=decision.decided_by,
                    details={
                        "attempted_verdict": decision.decision.value,
                        "current_status": req.status.value,
                    },
                )
                self._persist()
                raise DuplicateApprovalError(request_id, req.status.value)

            # 5. Apply transition and invalidate challenge token
            req.decision = decision
            req.approval_token = None  # Consume token permanently
            if decision.decision == ApprovalDecisionType.APPROVE:
                req.status = ApprovalStatus.APPROVED
            else:
                req.status = ApprovalStatus.DENIED

            self.record_audit(
                request_id=request_id,
                event_type="DECISION_RECORDED",
                actor=decision.decided_by,
                details={
                    "decision": decision.decision.value,
                    "reason": decision.reason,
                    "timestamp": decision.timestamp.isoformat(),
                },
            )
            self._persist()
            return req

    def expire_stale_requests(self, current_time: Optional[datetime] = None) -> List[ApprovalRequest]:
        """Scans and updates any pending requests whose expiration deadline has passed."""
        with self._lock:
            expired_now: List[ApprovalRequest] = []
            now = current_time or datetime.now(timezone.utc)
            for req in self._requests.values():
                if req.status == ApprovalStatus.PENDING and req.is_expired(now):
                    req.status = ApprovalStatus.EXPIRED
                    expired_now.append(req)
                    self.record_audit(
                        request_id=req.request_id,
                        event_type="EXPIRED",
                        actor="system:timeout",
                        details={"expiration": req.expiration.isoformat()},
                    )
            if expired_now:
                self._persist()
            return expired_now

    def _auto_expire_unlocked(self, request_id: str) -> None:
        req = self._requests.get(request_id)
        if req and req.status == ApprovalStatus.PENDING and req.is_expired():
            req.status = ApprovalStatus.EXPIRED
            self.record_audit(
                request_id=req.request_id,
                event_type="EXPIRED",
                actor="system:timeout",
                details={"expiration": req.expiration.isoformat()},
            )
            self._persist()

    def record_audit(
        self,
        request_id: str,
        event_type: str,
        actor: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> ApprovalAuditEntry:
        """Appends an immutable audit record."""
        entry = ApprovalAuditEntry(
            request_id=request_id,
            event_type=event_type,
            actor=actor,
            details=details or {},
        )
        self._audit_log.append(entry)
        return entry

    def get_audit_log(self, request_id: Optional[str] = None) -> List[ApprovalAuditEntry]:
        """Returns in-memory audit logs, optionally filtered by request_id."""
        with self._lock:
            self._load_if_exists()
            if request_id:
                return [a for a in self._audit_log if a.request_id == request_id]
            return list(self._audit_log)

    def clear(self) -> None:
        """Clears all records and removes persistence file if present."""
        with self._lock:
            self._requests.clear()
            self._audit_log.clear()
            if self._persistence_path and os.path.exists(self._persistence_path):
                try:
                    os.remove(self._persistence_path)
                except OSError:
                    pass


# Global singleton access
_default_store: Optional[ApprovalStore] = None
_default_store_lock = threading.Lock()


def get_default_approval_store(persistence_path: Optional[str] = None) -> ApprovalStore:
    """Returns or initializes the shared approval store instance."""
    global _default_store
    with _default_store_lock:
        if _default_store is None:
            default_path = persistence_path or ".runtimeverify/approvals.json"
            _default_store = ApprovalStore(persistence_path=default_path)
        return _default_store


def set_default_approval_store(store: ApprovalStore) -> None:
    """Explicitly injects the shared approval store instance."""
    global _default_store
    with _default_store_lock:
        _default_store = store
