"""
API-based Approval Provider for RuntimeVerify (Phase 7).
Enables programmatic, REST API, and webhook-driven human approval workflows.
"""

import logging
import time
from typing import Callable, Optional, Set

from runtimeverify.approvals.models import (
    ApprovalDecision,
    ApprovalDecisionType,
    ApprovalRequest,
    ApprovalStatus,
    ApprovalTimeoutBehavior,
)
from runtimeverify.approvals.provider import ApprovalProvider
from runtimeverify.approvals.store import ApprovalStore

logger = logging.getLogger(__name__)


class APIApprovalProvider(ApprovalProvider):
    """
    Approval provider for HTTP/REST environments and webhooks.
    Saves requests into the shared store and exposes polling / webhook hooks.
    """

    def __init__(
        self,
        store: Optional[ApprovalStore] = None,
        webhook_fn: Optional[Callable[[ApprovalRequest], None]] = None,
        poll_interval: float = 0.25,
        default_user: str = "api-operator",
        authorized_approvers: Optional[Set[str]] = None,
    ):
        super().__init__(store=store, authorized_approvers=authorized_approvers)
        self.webhook_fn = webhook_fn
        self.poll_interval = poll_interval
        self.default_user = default_user

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        """
        Enqueues an approval request, invokes optional webhook hook, and waits for API resolution.
        """
        self.store.save_request(request)

        if self.webhook_fn:
            try:
                self.webhook_fn(request)
            except Exception as e:
                logger.error("Failed to trigger webhook for approval request '%s': %s", request.request_id, e)

        # Await decision up to timeout
        return self._wait_for_resolution(request)

    def _wait_for_resolution(self, request: ApprovalRequest) -> ApprovalDecision:
        start_time = time.monotonic()
        timeout = request.timeout_seconds

        while (time.monotonic() - start_time) < timeout:
            updated_req = self.store.peek_request(request.request_id)
            if updated_req is None:
                break

            if updated_req.status == ApprovalStatus.APPROVED and updated_req.decision:
                return updated_req.decision

            if updated_req.status in (ApprovalStatus.DENIED, ApprovalStatus.CANCELLED) and updated_req.decision:
                return updated_req.decision

            if updated_req.is_expired():
                break

            time.sleep(self.poll_interval)

        # Timeout handling
        self.store.expire_stale_requests()
        logger.warning("Approval request '%s' timed out via API provider after %.1fs", request.request_id, timeout)

        if request.timeout_behavior == ApprovalTimeoutBehavior.APPROVE:
            decision = ApprovalDecision(
                request_id=request.request_id,
                decision=ApprovalDecisionType.APPROVE,
                decided_by="system:timeout",
                reason=f"Approval request timed out after {timeout:.1f}s (configured fail-open)",
            )
        else:
            decision = ApprovalDecision(
                request_id=request.request_id,
                decision=ApprovalDecisionType.DENY,
                decided_by="system:timeout",
                reason=f"Approval request timed out after {timeout:.1f}s without authorization (fail-closed)",
            )

        try:
            self.store.record_decision(request.request_id, decision)
        except Exception:
            pass
        return decision
