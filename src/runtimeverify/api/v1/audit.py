"""
Audit Router for RuntimeVerify API (Phase 11 & Phase 8).
Provides structured audit record query by multi-dimensional correlation IDs,
single record inspection, and retention-based pruning.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from runtimeverify.api.auth import AuthContext, Permission, require_permission
from runtimeverify.api.schemas import (
    AuditPruneRequest,
    AuditPruneResponse,
    AuditRecordResponse,
    PaginatedResponse,
    paginate_items,
)
from runtimeverify.audit.models import AuditRecordType, AuditSeverity
from runtimeverify.audit.service import get_default_audit_service

router = APIRouter(tags=["Audit"])


@router.get(
    "/audit",
    response_model=PaginatedResponse[AuditRecordResponse],
    summary="List Audit Records",
    description="Queries structured audit records with filtering by agent, session, record type, trace ID, and severity, with pagination.",
)
def list_audit_records(
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    session_id: Optional[str] = Query(None, description="Filter by session identifier"),
    record_type: Optional[str] = Query(None, description="Filter by record type (e.g. EVENT, POLICY_DECISION)"),
    trace_id: Optional[str] = Query(None, description="Filter by distributed trace identifier"),
    severity: Optional[str] = Query(None, description="Filter by severity (e.g. INFO, WARNING, HIGH, CRITICAL)"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page (max 100)"),
    auth: AuthContext = Depends(require_permission(Permission.AUDIT_READ.value)),
) -> PaginatedResponse[AuditRecordResponse]:
    audit_service = get_default_audit_service()
    if not audit_service.repository:
        return paginate_items([], page=page, page_size=page_size)

    rt = None
    if record_type:
        try:
            rt = AuditRecordType(record_type.upper())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid record_type '{record_type}'",
            )

    sev = None
    if severity:
        try:
            sev = AuditSeverity(severity.upper())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity '{severity}'",
            )

    records = audit_service.repository.query(
        trace_id=trace_id,
        session_id=session_id,
        agent_id=agent_id,
        record_type=rt,
        severity=sev,
    )

    responses: List[AuditRecordResponse] = [
        AuditRecordResponse(
            record_id=r.record_id,
            record_type=r.record_type.value,
            severity=r.severity.value,
            summary=r.summary,
            timestamp=r.timestamp.isoformat(),
            agent_id=r.agent_id,
            session_id=r.session_id,
            trace_id=r.trace_id,
            event_id=r.event_id,
            action_id=r.action_id,
            details=r.details,
            redacted=r.redacted,
        )
        for r in records
    ]

    return paginate_items(responses, page=page, page_size=page_size)


@router.get(
    "/audit/{record_id}",
    response_model=AuditRecordResponse,
    summary="Get Audit Record by ID",
    description="Retrieves a specific sanitized audit record by its unique identifier.",
)
def get_audit_record(
    record_id: str,
    auth: AuthContext = Depends(require_permission(Permission.AUDIT_READ.value)),
) -> AuditRecordResponse:
    audit_service = get_default_audit_service()
    if not audit_service.repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit repository is unavailable",
        )

    record = audit_service.repository.get(record_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit record with ID '{record_id}' was not found",
        )

    return AuditRecordResponse(
        record_id=record.record_id,
        record_type=record.record_type.value,
        severity=record.severity.value,
        summary=record.summary,
        timestamp=record.timestamp.isoformat(),
        agent_id=record.agent_id,
        session_id=record.session_id,
        trace_id=record.trace_id,
        event_id=record.event_id,
        action_id=record.action_id,
        details=record.details,
        redacted=record.redacted,
    )


@router.post(
    "/audit/prune",
    response_model=AuditPruneResponse,
    summary="Prune Stale Audit Records",
    description="Prunes audit records by age (days) or volume (max records). Requires administrative privileges.",
)
def prune_audit_records(
    payload: AuditPruneRequest,
    auth: AuthContext = Depends(require_permission(Permission.AUDIT_ADMIN.value)),
) -> AuditPruneResponse:
    audit_service = get_default_audit_service()
    if not audit_service.repository:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Audit repository is not initialized",
        )

    pruned = audit_service.repository.apply_retention(
        max_age_days=payload.max_age_days,
        max_records=payload.max_records,
    )
    remaining = audit_service.repository.count()

    return AuditPruneResponse(
        pruned_records=pruned,
        remaining_records=remaining,
    )
