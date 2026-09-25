"""
Human Approval Workflow package for RuntimeVerify (Phase 7).
Provides approval requests, decisions, providers (CLI, API), registries, and replay prevention.
"""

from runtimeverify.approvals.api_provider import APIApprovalProvider
from runtimeverify.approvals.cli_provider import CLIApprovalProvider
from runtimeverify.approvals.exceptions import (
    ApprovalDeniedError,
    ApprovalError,
    ApprovalExpiredError,
    ApprovalTimeoutError,
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
    ApprovalTimeoutBehavior,
)
from runtimeverify.approvals.provider import ApprovalProvider
from runtimeverify.approvals.store import (
    ApprovalStore,
    get_default_approval_store,
    set_default_approval_store,
)

__all__ = [
    "APIApprovalProvider",
    "ApprovalAuditEntry",
    "ApprovalDecision",
    "ApprovalDecisionType",
    "ApprovalDeniedError",
    "ApprovalError",
    "ApprovalExpiredError",
    "ApprovalProvider",
    "ApprovalRequest",
    "ApprovalStatus",
    "ApprovalStore",
    "ApprovalTimeoutBehavior",
    "ApprovalTimeoutError",
    "CLIApprovalProvider",
    "DuplicateApprovalError",
    "UnauthorizedApproverError",
    "UnknownApprovalRequestError",
    "get_default_approval_store",
    "set_default_approval_store",
]
