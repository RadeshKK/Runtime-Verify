"""
Enterprise Approval Workflows and Dual-Control Human-in-the-Loop Governance (Phase 18).
Enforces configurable multi-approver thresholds (e.g. 2 approvers for production),
segregation of duties, role checks, and auto-timeout handling.
"""

from datetime import datetime, timezone
import threading
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from runtimeverify.enterprise.models import (
    ApprovalPolicy,
    ApprovalStatus,
    EnterpriseApprovalRequest,
    Environment,
)


class ApprovalResolution(BaseModel):
    """
    Outcome of an approval action (approve, reject, or status query).
    """

    model_config = ConfigDict(frozen=True)

    request_id: str
    status: ApprovalStatus
    approved_by: List[str] = Field(default_factory=list)
    remaining_approvals: int
    message: str


class EnterpriseApprovalManager:
    """
    Manages dual-control approval escalation queues with multi-tenant isolation,
    SOD self-approval prevention, and timeout enforcement.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # id -> EnterpriseApprovalRequest
        self._requests: Dict[str, EnterpriseApprovalRequest] = {}
        # tenant_id -> list of request IDs
        self._tenant_requests: Dict[str, List[str]] = {}
        # policy index: f"{tenant_id}:{env.value}" -> ApprovalPolicy
        self._policies: Dict[str, ApprovalPolicy] = {}

    def set_approval_policy(self, policy: ApprovalPolicy) -> None:
        """Configures or updates an approval policy for a tenant and environment."""
        with self._lock:
            key = f"{policy.tenant_id}:{policy.environment.value}"
            self._policies[key] = policy

    def get_approval_policy(self, tenant_id: str, environment: Environment) -> ApprovalPolicy:
        """Retrieves active approval policy or returns default."""
        with self._lock:
            key = f"{tenant_id}:{environment.value}"
            if key in self._policies:
                return self._policies[key]
            # Default dual-control policy for production; single approver for dev/staging
            min_approvers = 2 if environment == Environment.PRODUCTION else 1
            return ApprovalPolicy(
                tenant_id=tenant_id,
                environment=environment,
                name=f"default-{environment.value}-approval-policy",
                min_approvers=min_approvers,
                allowed_roles=["security_engineer", "org_admin", "super_admin"],
                auto_timeout_seconds=300,
            )

    def create_request(
        self,
        tenant_id: str,
        organization_id: str,
        project_id: str,
        environment: Environment,
        session_id: str,
        agent_id: str,
        action_type: str,
        action_target: str,
        risk_level: str = "HIGH",
    ) -> EnterpriseApprovalRequest:
        """
        Creates a new approval request governed by the applicable environment policy.
        """
        policy = self.get_approval_policy(tenant_id, environment)
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(now.timestamp() + policy.auto_timeout_seconds, tz=timezone.utc)

        with self._lock:
            req = EnterpriseApprovalRequest(
                tenant_id=tenant_id,
                organization_id=organization_id,
                project_id=project_id,
                environment=environment,
                session_id=session_id,
                agent_id=agent_id,
                action_type=action_type,
                action_target=action_target,
                risk_level=risk_level,
                required_approvals=policy.min_approvers,
                expires_at=expires_at,
            )

            self._requests[req.id] = req
            if tenant_id not in self._tenant_requests:
                self._tenant_requests[tenant_id] = []
            self._tenant_requests[tenant_id].append(req.id)
            return req

    def get_request(self, request_id: str) -> Optional[EnterpriseApprovalRequest]:
        """Retrieves an approval request and checks for timeout expiration."""
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                return None
            return self._evaluate_timeout(req)

    def _evaluate_timeout(self, req: EnterpriseApprovalRequest) -> EnterpriseApprovalRequest:
        """Checks if a pending request has exceeded its expiration window."""
        if req.status == ApprovalStatus.PENDING:
            now = datetime.now(timezone.utc)
            if now > req.expires_at:
                updated = EnterpriseApprovalRequest(
                    id=req.id,
                    tenant_id=req.tenant_id,
                    organization_id=req.organization_id,
                    project_id=req.project_id,
                    environment=req.environment,
                    session_id=req.session_id,
                    agent_id=req.agent_id,
                    action_type=req.action_type,
                    action_target=req.action_target,
                    risk_level=req.risk_level,
                    status=ApprovalStatus.EXPIRED,
                    required_approvals=req.required_approvals,
                    approved_by=req.approved_by,
                    rejected_by=req.rejected_by,
                    reason="Approval request timed out without required sign-offs.",
                    created_at=req.created_at,
                    expires_at=req.expires_at,
                )
                self._requests[req.id] = updated
                return updated
        return req

    def approve(
        self,
        request_id: str,
        approver_id: str,
        approver_roles: List[str],
    ) -> ApprovalResolution:
        """
        Records an approval from an authorized security principal.
        Enforces:
        - Allowed role checking
        - Segregation of duties (agent cannot self-approve)
        - Deduplication (same user cannot approve twice)
        - Dual-control threshold satisfaction
        """
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                raise ValueError(f"Approval request '{request_id}' not found.")

            req = self._evaluate_timeout(req)
            if req.status != ApprovalStatus.PENDING:
                raise ValueError(f"Cannot approve request in status '{req.status.value}'.")

            # Segregation of duties: requester cannot approve
            if approver_id == req.agent_id:
                raise PermissionError("Segregation of Duties (SOD): Requester cannot approve their own action.")

            # Role verification
            policy = self.get_approval_policy(req.tenant_id, req.environment)
            has_role = any(r.lower() in [pr.lower() for pr in policy.allowed_roles] for r in approver_roles)
            if not has_role and "super_admin" not in [r.lower() for r in approver_roles]:
                raise PermissionError(
                    f"Approver '{approver_id}' lacks required approval role for {req.environment.value}."
                )

            # Deduplication
            if approver_id in req.approved_by:
                raise ValueError(f"Approver '{approver_id}' has already approved this request.")

            new_approved_by = list(req.approved_by) + [approver_id]
            remaining = req.required_approvals - len(new_approved_by)

            new_status = ApprovalStatus.APPROVED if remaining <= 0 else ApprovalStatus.PENDING

            updated = EnterpriseApprovalRequest(
                id=req.id,
                tenant_id=req.tenant_id,
                organization_id=req.organization_id,
                project_id=req.project_id,
                environment=req.environment,
                session_id=req.session_id,
                agent_id=req.agent_id,
                action_type=req.action_type,
                action_target=req.action_target,
                risk_level=req.risk_level,
                status=new_status,
                required_approvals=req.required_approvals,
                approved_by=new_approved_by,
                rejected_by=req.rejected_by,
                reason=req.reason,
                created_at=req.created_at,
                expires_at=req.expires_at,
            )
            self._requests[req.id] = updated

            msg = (
                f"Approved by {approver_id}. Request is fully APPROVED."
                if new_status == ApprovalStatus.APPROVED
                else f"Approved by {approver_id}. {remaining} approval(s) still required."
            )

            return ApprovalResolution(
                request_id=req.id,
                status=new_status,
                approved_by=new_approved_by,
                remaining_approvals=max(0, remaining),
                message=msg,
            )

    def reject(
        self,
        request_id: str,
        rejector_id: str,
        reason: str = "Rejected by security operator",
    ) -> ApprovalResolution:
        """
        Immediately rejects a pending approval request.
        """
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                raise ValueError(f"Approval request '{request_id}' not found.")

            req = self._evaluate_timeout(req)
            if req.status != ApprovalStatus.PENDING:
                raise ValueError(f"Cannot reject request in status '{req.status.value}'.")

            updated = EnterpriseApprovalRequest(
                id=req.id,
                tenant_id=req.tenant_id,
                organization_id=req.organization_id,
                project_id=req.project_id,
                environment=req.environment,
                session_id=req.session_id,
                agent_id=req.agent_id,
                action_type=req.action_type,
                action_target=req.action_target,
                risk_level=req.risk_level,
                status=ApprovalStatus.REJECTED,
                required_approvals=req.required_approvals,
                approved_by=req.approved_by,
                rejected_by=rejector_id,
                reason=reason,
                created_at=req.created_at,
                expires_at=req.expires_at,
            )
            self._requests[req.id] = updated

            return ApprovalResolution(
                request_id=req.id,
                status=ApprovalStatus.REJECTED,
                approved_by=req.approved_by,
                remaining_approvals=0,
                message=f"Request REJECTED by {rejector_id}: {reason}",
            )

    def list_pending(
        self, tenant_id: str, environment: Optional[Environment] = None
    ) -> List[EnterpriseApprovalRequest]:
        """Lists active pending approval requests for a tenant."""
        with self._lock:
            req_ids = self._tenant_requests.get(tenant_id, [])
            pending: List[EnterpriseApprovalRequest] = []
            for rid in req_ids:
                req = self._requests.get(rid)
                if req:
                    req = self._evaluate_timeout(req)
                    if req.status == ApprovalStatus.PENDING:
                        if environment is None or req.environment == environment:
                            pending.append(req)
            return pending
