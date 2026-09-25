"""
CLI-based Approval Provider for RuntimeVerify (Phase 7).
Supports interactive terminal prompts as well as queued asynchronous polling for 'runtimeverify approvals approve' commands.
"""

import logging
import time
from typing import Optional, Set

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


class CLIApprovalProvider(ApprovalProvider):
    """
    Approval provider facilitating human reviews via the CLI.
    In interactive mode, prompts the console directly.
    In queued mode, enqueues the request and polls until approved via 'runtimeverify approvals approve'.
    """

    def __init__(
        self,
        store: Optional[ApprovalStore] = None,
        interactive: bool = False,
        poll_interval: float = 0.5,
        default_user: str = "cli-operator",
        authorized_approvers: Optional[Set[str]] = None,
    ):
        super().__init__(store=store, authorized_approvers=authorized_approvers)
        self.interactive = interactive
        self.poll_interval = poll_interval
        self.default_user = default_user

    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        """
        Processes an approval request.
        """
        # Save request to the shared store
        self.store.save_request(request)

        if self.interactive:
            return self._prompt_interactive(request)
        else:
            return self._poll_queued(request)

    def _prompt_interactive(self, request: ApprovalRequest) -> ApprovalDecision:
        """Prompts reviewer in the active terminal."""
        try:
            print(f"\n{'=' * 60}")
            print(f"⚠️  HUMAN APPROVAL REQUIRED (Request ID: {request.request_id})")
            print(f"Agent: {request.agent_id or 'unknown'} | Risk: {request.risk}")
            print(f"Reason: {request.reason}")
            action_desc = request.action.get("target") or str(request.action)
            print(f"Proposed Action: {action_desc}")
            print(f"Expires at: {request.expiration.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print(f"{'=' * 60}")

            resp = input("Authorize execution? [y/N]: ").strip().lower()
            decision_type = ApprovalDecisionType.APPROVE if resp in ("y", "yes") else ApprovalDecisionType.DENY
            reason = input("Optional reason / comments: ").strip() or (
                "Approved via interactive CLI prompt"
                if decision_type == ApprovalDecisionType.APPROVE
                else "Denied via interactive CLI prompt"
            )

            decision = ApprovalDecision(
                request_id=request.request_id,
                decision=decision_type,
                decided_by=self.default_user,
                reason=reason,
            )
            self.submit_decision(decision)
            return decision

        except (KeyboardInterrupt, EOFError):
            print("\n[!] Approval cancelled by user interrupt. Failing closed (DENY).")
            decision = ApprovalDecision(
                request_id=request.request_id,
                decision=ApprovalDecisionType.DENY,
                decided_by=self.default_user,
                reason="Interactive approval cancelled by user (fail-closed)",
            )
            self.submit_decision(decision)
            return decision

    def _poll_queued(self, request: ApprovalRequest) -> ApprovalDecision:
        """
        Waits for an external CLI command (e.g. 'runtimeverify approvals approve <id>') to decide the request.
        """
        start_time = time.monotonic()
        timeout = request.timeout_seconds

        logger.info(
            "Approval request '%s' enqueued. Waiting up to %.1fs for human review...",
            request.request_id,
            timeout,
        )

        while (time.monotonic() - start_time) < timeout:
            updated_req = self.store.peek_request(request.request_id)
            if updated_req is None:
                break

            if updated_req.status == ApprovalStatus.APPROVED and updated_req.decision:
                logger.info(
                    "Approval request '%s' was APPROVED by %s", request.request_id, updated_req.decision.decided_by
                )
                return updated_req.decision

            if updated_req.status in (ApprovalStatus.DENIED, ApprovalStatus.CANCELLED) and updated_req.decision:
                logger.warning(
                    "Approval request '%s' was DENIED by %s", request.request_id, updated_req.decision.decided_by
                )
                return updated_req.decision

            if updated_req.is_expired():
                break

            time.sleep(self.poll_interval)

        # Timeout reached: mark as expired and apply timeout behavior
        self.store.expire_stale_requests()
        logger.warning("Approval request '%s' timed out after %.1fs.", request.request_id, timeout)

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
                reason=f"Approval request timed out after {timeout:.1f}s without human authorization (fail-closed)",
            )

        try:
            self.store.record_decision(request.request_id, decision)
        except Exception:
            pass  # Already marked EXPIRED in store
        return decision
