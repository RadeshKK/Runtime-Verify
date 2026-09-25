from typing import Any, Dict, Optional


class InterceptionError(Exception):
    """Base exception for all action interception and runtime verification errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ExecutionBlockedError(InterceptionError):
    """
    Raised when an action is blocked by a policy or behavioral detection rule
    under enforcement mode.
    """

    def __init__(
        self,
        action_id: str,
        policy_id: str,
        reason: str,
        severity: str = "HIGH",
        matched_rule: Optional[Dict[str, Any]] = None,
        audit_record: Optional[Dict[str, Any]] = None,
    ):
        message = f"Action '{action_id}' BLOCKED by policy '{policy_id}' [{severity}]: {reason}"
        super().__init__(
            message,
            details={
                "action_id": action_id,
                "policy_id": policy_id,
                "severity": severity,
                "reason": reason,
                "matched_rule": matched_rule or {},
                "audit_record": audit_record or {},
            },
        )
        self.action_id = action_id
        self.policy_id = policy_id
        self.severity = severity
        self.reason = reason
        self.matched_rule = matched_rule or {}
        self.audit_record = audit_record or {}


class ExecutionReviewRequiredError(InterceptionError):
    """
    Raised when an action requires human review or escalation before execution
    can proceed under enforcement mode.
    """

    def __init__(
        self,
        action_id: str,
        policy_id: str,
        reason: str,
        approval_id: Optional[str] = None,
        matched_rule: Optional[Dict[str, Any]] = None,
    ):
        message = f"Action '{action_id}' requires HUMAN REVIEW under policy '{policy_id}': {reason}"
        super().__init__(
            message,
            details={
                "action_id": action_id,
                "policy_id": policy_id,
                "approval_id": approval_id,
                "reason": reason,
                "matched_rule": matched_rule or {},
            },
        )
        self.action_id = action_id
        self.policy_id = policy_id
        self.approval_id = approval_id
        self.reason = reason
        self.matched_rule = matched_rule or {}


class SecurityFailClosedError(InterceptionError):
    """
    Raised when a critical evaluation failure or error occurs and the engine
    fails closed to prevent unauthorized execution.
    """

    def __init__(self, action_id: str, error_message: str):
        message = f"Action '{action_id}' failed closed due to an internal security evaluation failure: {error_message}"
        super().__init__(message, details={"action_id": action_id, "error": error_message})
        self.action_id = action_id
        self.error_message = error_message


class ActionExecutionError(InterceptionError):
    """
    Raised when an approved action fails during execution by an ActionExecutor.
    """

    def __init__(self, action_id: str, executor_name: str, cause: Exception):
        message = f"Executor '{executor_name}' failed while executing action '{action_id}': {cause}"
        super().__init__(
            message,
            details={"action_id": action_id, "executor": executor_name, "error": str(cause)},
        )
        self.action_id = action_id
        self.executor_name = executor_name
        self.cause = cause
