"""
Events Router for RuntimeVerify API (Phase 11).
Handles event ingestion, multi-field filtering, query pagination, and single event retrieval.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status

from runtimeverify.api.auth import AuthContext, Permission, require_permission
from runtimeverify.api.schemas import (
    EventIngestRequest,
    EventResponse,
    PaginatedResponse,
    paginate_items,
)
from runtimeverify.audit.service import get_default_audit_service
from runtimeverify.events import Event, FilesystemEvent, NetworkEvent, ToolEvent, LLMEvent

router = APIRouter(tags=["Events"])


@router.post(
    "/events",
    response_model=Dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest and Verify Telemetry Event",
    description="Ingests a new canonical or framework telemetry event, processes it through the runtime verification engine, and logs an audit trail.",
)
def ingest_event(
    payload: EventIngestRequest,
    auth: AuthContext = Depends(require_permission(Permission.EVENTS_WRITE.value)),
) -> Dict[str, Any]:
    from runtimeverify.api.app import engine, session_db, decisions_cache

    if not engine:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Runtime verification engine is not initialized",
        )

    event_id = payload.id or str(uuid.uuid4())
    event_type = payload.type.lower()

    event_kwargs = {
        "id": event_id,
        "session_id": payload.session_id,
        "agent_id": payload.agent_id,
        "metadata": payload.metadata or {},
    }

    event: Event
    if event_type == "tool":
        event = ToolEvent(
            tool_name=payload.target or payload.payload.get("tool_name", "unknown_tool"),
            arguments=payload.payload.get("arguments", payload.payload),
            status=payload.status,
            **event_kwargs,
        )
    elif event_type == "filesystem":
        event = FilesystemEvent(
            action=payload.action or "read",
            path=payload.target or payload.payload.get("path", ""),
            status=payload.status,
            **event_kwargs,
        )
    elif event_type == "network":
        event = NetworkEvent(
            action=payload.action or "connect",
            url=payload.target or payload.payload.get("url", ""),
            method=payload.payload.get("method", "GET"),
            status_code=payload.payload.get("status_code"),
            **event_kwargs,
        )
    elif event_type == "llm":
        event = LLMEvent(
            model=payload.payload.get("model", "gpt-4"),
            prompt=payload.payload.get("prompt"),
            response=payload.payload.get("response"),
            **event_kwargs,
        )
    else:
        event = Event(type=event_type, **event_kwargs)

    try:
        decision = engine.observe(event)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Verification failure: {e}",
        )

    # Log to audit service
    audit_service = get_default_audit_service()
    audit_service.log_event(
        summary=f"Event '{event_type}' ingested for agent '{payload.agent_id}'",
        event_id=event_id,
        session_id=payload.session_id,
        agent_id=payload.agent_id,
        trace_id=payload.trace_id,
        details={"type": event_type, "target": payload.target, "status": payload.status},
    )

    decision_data = decision.model_dump()
    ev_dict = event.model_dump()
    if payload.payload:
        ev_dict["payload"] = payload.payload
    decision_data["event"] = ev_dict

    # Store in memory databases
    decisions_cache[event_id] = decision_data
    if payload.session_id not in session_db:
        session_db[payload.session_id] = []
    session_db[payload.session_id].append(
        {
            "event": ev_dict,
            "decision": decision.model_dump(),
        }
    )

    return {
        "status": "ingested",
        "event_id": event_id,
        "decision": decision_data,
    }


def _extract_payload(ev_data: Dict[str, Any]) -> Dict[str, Any]:
    if ev_data.get("payload"):
        return ev_data["payload"]
    if ev_data.get("arguments"):
        return ev_data["arguments"]
    if "prompt" in ev_data:
        return {
            "prompt": ev_data.get("prompt"),
            "response": ev_data.get("response"),
            "model": ev_data.get("model"),
        }
    return {}


@router.get(
    "/events",
    response_model=PaginatedResponse[EventResponse],
    summary="List Telemetry Events",
    description="Lists ingested telemetry events across sessions, supporting filtering by agent, session, type, and pagination.",
)
def list_events(
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    session_id: Optional[str] = Query(None, description="Filter by session identifier"),
    type: Optional[str] = Query(None, description="Filter by event type"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page (max 100)"),
    auth: AuthContext = Depends(require_permission(Permission.EVENTS_READ.value)),
) -> PaginatedResponse[EventResponse]:
    from runtimeverify.api.app import session_db

    all_events: List[EventResponse] = []
    for s_id, records in session_db.items():
        if session_id and s_id != session_id:
            continue
        for rec in records:
            ev_data = rec.get("event", {})
            if agent_id and ev_data.get("agent_id") != agent_id:
                continue
            if type and ev_data.get("type") != type:
                continue

            ts = ev_data.get("timestamp")
            if not ts:
                ts = datetime.now(timezone.utc).isoformat()
            elif isinstance(ts, datetime):
                ts = ts.isoformat()

            all_events.append(
                EventResponse(
                    id=str(ev_data.get("id") or ""),
                    session_id=str(ev_data.get("session_id") or s_id),
                    agent_id=str(ev_data.get("agent_id") or ""),
                    type=str(ev_data.get("type") or "generic"),
                    action=ev_data.get("action"),
                    target=ev_data.get("target")
                    or ev_data.get("path")
                    or ev_data.get("url")
                    or ev_data.get("tool_name"),
                    status=str(ev_data.get("status") or "success"),
                    payload=_extract_payload(ev_data),
                    metadata=ev_data.get("metadata") or {},
                    timestamp=str(ts),
                )
            )

    return paginate_items(all_events, page=page, page_size=page_size)


@router.get(
    "/events/{event_id}",
    response_model=EventResponse,
    summary="Get Telemetry Event by ID",
    description="Retrieves a specific ingested telemetry event by its unique identifier.",
)
def get_event(
    event_id: str,
    auth: AuthContext = Depends(require_permission(Permission.EVENTS_READ.value)),
) -> EventResponse:
    from runtimeverify.api.app import session_db, decisions_cache

    # Check decisions_cache first
    if event_id in decisions_cache:
        ev_data = decisions_cache[event_id].get("event", {})
        ts = ev_data.get("timestamp") or datetime.now(timezone.utc).isoformat()
        return EventResponse(
            id=str(ev_data.get("id") or event_id),
            session_id=str(ev_data.get("session_id") or ""),
            agent_id=str(ev_data.get("agent_id") or ""),
            type=str(ev_data.get("type") or "generic"),
            action=ev_data.get("action"),
            target=ev_data.get("target") or ev_data.get("path") or ev_data.get("url") or ev_data.get("tool_name"),
            status=str(ev_data.get("status") or "success"),
            payload=_extract_payload(ev_data),
            metadata=ev_data.get("metadata") or {},
            timestamp=str(ts),
        )

    # Scan session_db
    for s_id, records in session_db.items():
        for rec in records:
            ev_data = rec.get("event", {})
            if ev_data.get("id") == event_id:
                ts = ev_data.get("timestamp") or datetime.now(timezone.utc).isoformat()
                return EventResponse(
                    id=str(ev_data.get("id")),
                    session_id=str(ev_data.get("session_id") or s_id),
                    agent_id=str(ev_data.get("agent_id") or ""),
                    type=str(ev_data.get("type") or "generic"),
                    action=ev_data.get("action"),
                    target=ev_data.get("target")
                    or ev_data.get("path")
                    or ev_data.get("url")
                    or ev_data.get("tool_name"),
                    status=str(ev_data.get("status") or "success"),
                    payload=_extract_payload(ev_data),
                    metadata=ev_data.get("metadata") or {},
                    timestamp=str(ts),
                )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Event with ID '{event_id}' was not found",
    )
