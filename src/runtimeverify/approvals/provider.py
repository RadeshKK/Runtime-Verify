"""
Abstract base class and core contracts for Approval Providers (Phase 7).
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Set

from runtimeverify.approvals.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
)
from runtimeverify.approvals.store import ApprovalStore, get_default_approval_store


class ApprovalProvider(ABC):
    """
    Vendor-neutral abstraction for requesting, queueing, and dispatching human approval workflows.
    """

    def __init__(
        self,
        store: Optional[ApprovalStore] = None,
        authorized_approvers: Optional[Set[str]] = None,
    ):
        self.store = store or get_default_approval_store()
        self.authorized_approvers = authorized_approvers

    @abstractmethod
    def request_approval(self, request: ApprovalRequest) -> ApprovalDecision:
        """
        Submits an approval request to human reviewers and returns the final decision.
        Implementations may block (CLI prompt / long-poll) or integrate with asynchronous hooks.
        """
        pass

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Looks up an approval request by its ID."""
        return self.store.peek_request(request_id)

    def list_pending(self) -> List[ApprovalRequest]:
        """Returns all requests currently awaiting review."""
        return self.store.list_requests(status=ApprovalStatus.PENDING)

    def list_all(self, status: Optional[ApprovalStatus] = None) -> List[ApprovalRequest]:
        """Returns all approval requests matching the status filter."""
        return self.store.list_requests(status=status)

    def submit_decision(self, decision: ApprovalDecision) -> ApprovalRequest:
        """
        Submits an approver's verdict on a pending request.
        Validates authorization, enforces expiration, and prevents replay attacks.
        """
        return self.store.record_decision(
            request_id=decision.request_id,
            decision=decision,
            authorized_approvers=self.authorized_approvers,
        )
