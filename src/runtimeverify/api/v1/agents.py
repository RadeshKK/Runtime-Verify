"""
Agents Router for RuntimeVerify API (Phase 11).
Provides agent fleet discovery, aggregated anomaly metrics, and per-session deep inspection.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query, status

from runtimeverify.api.auth import AuthContext, Permission, require_permission
from runtimeverify.api.schemas import (
    AgentSessionDetailResponse,
    AgentSummaryResponse,
    PaginatedResponse,
    paginate_items,
)

router = APIRouter(tags=["Agents"])


def _aggregate_agents_data() -> Dict[str, Dict[str, Any]]:
    from runtimeverify.api.app import session_db, decisions_cache

    agents: Dict[str, Dict[str, Any]] = {}

    for session_id, records in session_db.items():
        for rec in records:
            ev = rec.get("event", {})
            agent_id = ev.get("agent_id") or "unknown-agent"
            if agent_id not in agents:
                agents[agent_id] = {
                    "agent_id": agent_id,
                    "sessions": set(),
                    "total_events": 0,
                    "total_anomalies": 0,
                    "last_active": None,
                }

            agents[agent_id]["sessions"].add(session_id)
            agents[agent_id]["total_events"] += 1

            dec = rec.get("decision", {})
            if dec.get("status") in ("BLOCK", "REVIEW"):
                agents[agent_id]["total_anomalies"] += 1

            ts = ev.get("timestamp")
            if ts:
                agents[agent_id]["last_active"] = str(ts)

    # Also scan decisions_cache for any events without session_db records
    for d in decisions_cache.values():
        ev = d.get("event", {})
        ag_id = d.get("agent_id") or ev.get("agent_id")
        if ag_id and ag_id not in agents:
            agents[ag_id] = {
                "agent_id": ag_id,
                "sessions": {d.get("session_id") or "default"} if d.get("session_id") else set(),
                "total_events": 1,
                "total_anomalies": 1 if d.get("status") in ("BLOCK", "REVIEW") else 0,
                "last_active": d.get("timestamp"),
            }

    return agents


@router.get(
    "/agents",
    response_model=PaginatedResponse[AgentSummaryResponse],
    summary="List Registered Agents",
    description="Lists all autonomous AI agents observed across sessions with aggregate verification metrics.",
)
def list_agents(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page (max 100)"),
    auth: AuthContext = Depends(require_permission(Permission.AGENTS_READ.value)),
) -> PaginatedResponse[AgentSummaryResponse]:
    agents_map = _aggregate_agents_data()
    summaries: List[AgentSummaryResponse] = []

    for agent_id, data in sorted(agents_map.items()):
        summaries.append(
            AgentSummaryResponse(
                agent_id=agent_id,
                total_sessions=len(data["sessions"]),
                total_events=data["total_events"],
                total_anomalies=data["total_anomalies"],
                status="active",
                last_active=data["last_active"],
            )
        )

    return paginate_items(summaries, page=page, page_size=page_size)


@router.get(
    "/agents/{agent_id}",
    response_model=AgentSummaryResponse,
    summary="Get Agent Profile",
    description="Retrieves aggregate activity and anomaly statistics for a specific agent.",
)
def get_agent(
    agent_id: str,
    auth: AuthContext = Depends(require_permission(Permission.AGENTS_READ.value)),
) -> AgentSummaryResponse:
    agents_map = _aggregate_agents_data()
    if agent_id not in agents_map:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' was not found",
        )

    data = agents_map[agent_id]
    return AgentSummaryResponse(
        agent_id=agent_id,
        total_sessions=len(data["sessions"]),
        total_events=data["total_events"],
        total_anomalies=data["total_anomalies"],
        status="active",
        last_active=data["last_active"],
    )


@router.get(
    "/agents/{agent_id}/sessions/{session_id}",
    response_model=AgentSessionDetailResponse,
    summary="Get Agent Session Detail",
    description="Retrieves the full event trace history and verification verdicts for an agent session.",
)
def get_agent_session(
    agent_id: str,
    session_id: str,
    auth: AuthContext = Depends(require_permission(Permission.AGENTS_READ.value)),
) -> AgentSessionDetailResponse:
    from runtimeverify.api.app import session_db

    if session_id not in session_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' was not found",
        )

    records = session_db[session_id]
    matching = [r for r in records if (r.get("event", {}).get("agent_id") == agent_id or agent_id == "*")]

    if not matching:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No records found for agent '{agent_id}' in session '{session_id}'",
        )

    events = [r.get("event", {}) for r in matching]
    decisions = [r.get("decision", {}) for r in matching]
    anomalies = sum(1 for d in decisions if d.get("status") in ("BLOCK", "REVIEW"))

    first_ts = events[0].get("timestamp") or datetime.now(timezone.utc).isoformat()
    last_ts = events[-1].get("timestamp") or datetime.now(timezone.utc).isoformat()

    return AgentSessionDetailResponse(
        agent_id=agent_id,
        session_id=session_id,
        event_count=len(events),
        anomalies_count=anomalies,
        events=events,
        decisions=decisions,
        created_at=str(first_ts),
        updated_at=str(last_ts),
    )
