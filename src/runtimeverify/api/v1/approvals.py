"""
Approvals Router for RuntimeVerify API (Phase 11 & Phase 7).
Provides endpoints for listing pending approval requests, inspecting approval requests,
recording human APPROVE and DENY verdicts, and querying the approval audit log.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from runtimeverify.api.auth import AuthContext, Permission, require_permission
from runtimeverify.api.schemas import paginate_items
from runtimeverify.approvals import (
    ApprovalDecision,
    ApprovalDecisionType,
    ApprovalExpiredError,
    ApprovalStatus,
    DuplicateApprovalError,
    UnauthorizedApproverError,
    UnknownApprovalRequestError,
    get_default_approval_store,
)

router = APIRouter(tags=["Approvals"])


class ApprovalDecisionPayload(BaseModel):
    user: str = "api-operator"
    reason: Optional[str] = None


@router.get(
    "/approvals",
    summary="List Approval Requests",
    description="Lists approval requests with optional status filtering. Supports both array format and pagination.",
)
def list_approvals(
    status: Optional[str] = Query(None, description="Filter by status: PENDING, APPROVED, DENIED, EXPIRED"),
    page: Optional[int] = Query(None, ge=1, description="Optional page number for pagination"),
    page_size: Optional[int] = Query(None, ge=1, le=100, description="Items per page when paginating"),
    auth: AuthContext = Depends(require_permission(Permission.APPROVALS_READ.value)),
) -> Any:
    store = get_default_approval_store()
    status_filter = None
    if status and status.upper() != "ALL":
        try:
            status_filter = ApprovalStatus(status.upper())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status filter '{status}'")

    reqs = store.list_requests(status=status_filter)
    reqs_dump = [r.model_dump(mode="json") for r in reqs]

    if page is not None:
        return paginate_items(reqs_dump, page=page, page_size=page_size or 20)

    return reqs_dump


@router.get(
    "/approvals/{request_id}",
    summary="Get Approval Request by ID",
    description="Retrieves an approval request and its current status.",
)
def get_approval(
    request_id: str,
    auth: AuthContext = Depends(require_permission(Permission.APPROVALS_READ.value)),
) -> Dict[str, Any]:
    store = get_default_approval_store()
    try:
        req = store.get_request(request_id)
        return req.model_dump(mode="json")
    except UnknownApprovalRequestError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post(
    "/approvals/{request_id}/approve",
    summary="Approve Pending Action",
    description="Records a human APPROVE verdict for a pending approval request.",
)
def approve_request(
    request_id: str,
    payload: ApprovalDecisionPayload,
    auth: AuthContext = Depends(require_permission(Permission.APPROVALS_WRITE.value)),
) -> Dict[str, Any]:
    store = get_default_approval_store()
    decided_by = payload.user if payload.user != "api-operator" or not auth.authenticated else auth.user_id
    decision = ApprovalDecision(
        request_id=request_id,
        decision=ApprovalDecisionType.APPROVE,
        decided_by=decided_by,
        reason=payload.reason or f"Approved via API by {decided_by}",
    )
    try:
        updated = store.record_decision(request_id, decision)
        return updated.model_dump(mode="json")
    except UnknownApprovalRequestError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except DuplicateApprovalError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ApprovalExpiredError as e:
        raise HTTPException(status_code=410, detail=str(e))
    except UnauthorizedApproverError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.post(
    "/approvals/{request_id}/deny",
    summary="Deny Pending Action",
    description="Records a human DENY verdict for a pending approval request.",
)
def deny_request(
    request_id: str,
    payload: ApprovalDecisionPayload,
    auth: AuthContext = Depends(require_permission(Permission.APPROVALS_WRITE.value)),
) -> Dict[str, Any]:
    store = get_default_approval_store()
    decided_by = payload.user if payload.user != "api-operator" or not auth.authenticated else auth.user_id
    decision = ApprovalDecision(
        request_id=request_id,
        decision=ApprovalDecisionType.DENY,
        decided_by=decided_by,
        reason=payload.reason or f"Denied via API by {decided_by}",
    )
    try:
        updated = store.record_decision(request_id, decision)
        return updated.model_dump(mode="json")
    except UnknownApprovalRequestError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except DuplicateApprovalError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ApprovalExpiredError as e:
        raise HTTPException(status_code=410, detail=str(e))
    except UnauthorizedApproverError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.get(
    "/approvals/{request_id}/audit",
    summary="Get Approval Audit Trail",
    description="Retrieves the immutable audit log for a specific approval request.",
)
def get_approval_audit(
    request_id: str,
    auth: AuthContext = Depends(require_permission(Permission.APPROVALS_READ.value)),
) -> List[Dict[str, Any]]:
    store = get_default_approval_store()
    audits = store.get_audit_log(request_id=request_id)
    return [a.model_dump(mode="json") for a in audits]
