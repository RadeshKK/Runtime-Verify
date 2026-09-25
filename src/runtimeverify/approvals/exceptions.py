"""
Exceptions and structured error types for Human Approval Workflows.
"""


class ApprovalError(Exception):
    """Base exception for all approval-related failures."""

    pass


class UnknownApprovalRequestError(ApprovalError):
    """Raised when an approval request cannot be located by ID."""

    def __init__(self, request_id: str):
        self.request_id = request_id
        super().__init__(f"Approval request '{request_id}' not found.")


class DuplicateApprovalError(ApprovalError):
    """Raised to prevent replay attacks when a request has already been decided."""

    def __init__(self, request_id: str, current_status: str):
        self.request_id = request_id
        self.current_status = current_status
        super().__init__(
            f"Approval request '{request_id}' has already been decided (Status: {current_status}). "
            "Replay attack prevented: decisions cannot be altered or re-applied."
        )


class ApprovalExpiredError(ApprovalError):
    """Raised when an operation attempts to decide an expired approval request."""

    def __init__(self, request_id: str, expiration_time: str):
        self.request_id = request_id
        self.expiration_time = expiration_time
        super().__init__(
            f"Approval request '{request_id}' expired at {expiration_time}. "
            "Decisions cannot be accepted on expired requests."
        )


class UnauthorizedApproverError(ApprovalError):
    """Raised when an unauthorized user attempts to approve or deny an action."""

    def __init__(self, approver: str, request_id: str):
        self.approver = approver
        self.request_id = request_id
        super().__init__(
            f"User '{approver}' is not authorized to submit decisions for approval request '{request_id}'."
        )


class ApprovalTimeoutError(ApprovalError):
    """Raised when a blocking approval request times out without a human decision."""

    def __init__(self, request_id: str, timeout_seconds: float):
        self.request_id = request_id
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"Approval request '{request_id}' timed out after {timeout_seconds:.1f}s waiting for human review."
        )


class ApprovalDeniedError(ApprovalError):
    """Raised when human review or fail-closed policy explicitly denies the action."""

    def __init__(self, request_id: str, decider: str, reason: str):
        self.request_id = request_id
        self.decider = decider
        self.reason = reason
        super().__init__(
            f"Action blocked: human approval request '{request_id}' was DENIED by '{decider}'. Reason: {reason}"
        )
