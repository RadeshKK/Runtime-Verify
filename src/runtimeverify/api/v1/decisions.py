"""
Decisions Router for RuntimeVerify API (Phase 11).
Provides action verification, dry-run policy evaluation, decision querying, and pagination.
"""

from datetime import datetime, timedelta, timezone
import time
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from runtimeverify.api.auth import AuthContext, Permission, require_permission
from runtimeverify.api.schemas import (
    DecisionEvaluateRequest,
    DecisionResponse,
    PaginatedResponse,
    paginate_items,
)
from pathlib import Path
from runtimeverify.interception.models import Action, ActionType
from runtimeverify.runtime.context import ExecutionContext
from runtimeverify.policy.evaluator import PolicyEvaluator
from runtimeverify.policy.loader import load_policy_from_yaml
from runtimeverify.verification.engine import VerificationEngine
from runtimeverify.verification.models import VerificationEngineConfig

router = APIRouter(tags=["Decisions"])

# Cached default verification engine for fast API evaluations
_eval_engine: Optional[VerificationEngine] = None


def _get_eval_engine() -> VerificationEngine:
    global _eval_engine
    if _eval_engine is None:
        policy_path = Path("examples/policies/default.yaml")
        if policy_path.exists():
            policy_set = load_policy_from_yaml(policy_path)
            evaluator = PolicyEvaluator(policy_set=policy_set)
        else:
            evaluator = PolicyEvaluator()
        _eval_engine = VerificationEngine(
            config=VerificationEngineConfig(),
            policy_evaluator=evaluator,
        )
    return _eval_engine


@router.post(
    "/decisions/evaluate",
    response_model=DecisionResponse,
    summary="Evaluate Action Verification (Dry-Run / Live)",
    description="Evaluates an agent action against the deterministic policy engine, semantic intent classifier, and behavioral baseline without mutating session state when dry_run=True.",
)
def evaluate_decision(
    payload: DecisionEvaluateRequest,
    auth: AuthContext = Depends(require_permission(Permission.DECISIONS_EVALUATE.value)),
) -> DecisionResponse:
    engine = _get_eval_engine()

    act_type = ActionType.SHELL
    try:
        act_type = ActionType(payload.action_type.lower())
    except ValueError:
        pass

    params = dict(payload.params)
    if act_type == ActionType.SHELL and "command" not in params:
        params["command"] = payload.target

    ctx = ExecutionContext(
        session_id=payload.session_id,
        agent_id=payload.agent_id,
        environment=payload.environment or "development",
    )

    action = Action(
        action_type=act_type,
        name=act_type.value,
        target=payload.target,
        params=params,
        context=ctx,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
    )

    start = time.perf_counter()
    result = engine.verify(action)
    latency_ms = (time.perf_counter() - start) * 1000.0

    evidence_records = [
        {
            "source": str(e.source.value) if hasattr(e.source, "value") else str(e.source),
            "severity": e.severity,
            "title": e.title,
            "description": e.description,
            "data": e.data,
        }
        for e in result.evidence
    ]

    if not payload.dry_run:
        from runtimeverify.api.app import decisions_cache, session_db

        decision_data = {
            "verification_id": result.verification_id,
            "status": result.decision,
            "decision": result.decision,
            "risk_level": result.risk_level,
            "confidence": result.confidence,
            "reason": result.reason,
            "evidence": evidence_records,
            "policy_matches": result.policy_matches,
            "latency_ms": round(latency_ms, 2),
            "timestamp": result.timestamp.isoformat(),
            "agent_id": payload.agent_id,
            "session_id": payload.session_id,
            "event": {
                "id": result.verification_id,
                "type": payload.action_type,
                "action": payload.action_type,
                "target": payload.target,
                "agent_id": payload.agent_id,
                "session_id": payload.session_id,
                "timestamp": result.timestamp.isoformat(),
                "payload": payload.params,
            },
        }
        decisions_cache[result.verification_id] = decision_data
        session_db.setdefault(payload.session_id, []).append(
            {
                "event": decision_data["event"],
                "decision": decision_data,
            }
        )

        if result.decision == "REVIEW":
            from runtimeverify.approvals import (
                ApprovalRequest,
                ApprovalStatus,
                get_default_approval_store,
            )

            store = get_default_approval_store()
            appr_req = ApprovalRequest(
                request_id=f"appr-{result.verification_id[:8]}",
                action_id=result.verification_id,
                agent_id=payload.agent_id,
                session_id=payload.session_id,
                action_type=payload.action_type,
                action_target=payload.target,
                risk_level=result.risk_level,
                reason=result.reason,
                status=ApprovalStatus.PENDING,
                evidence=evidence_records,
                expiration=datetime.now(timezone.utc) + timedelta(seconds=60.0),
            )
            store.create_request(appr_req)

    return DecisionResponse(
        verification_id=result.verification_id,
        decision=result.decision,
        risk_level=result.risk_level,
        confidence=result.confidence,
        reason=result.reason,
        action_type=payload.action_type,
        target=payload.target,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
        evidence=evidence_records,
        policy_matches=result.policy_matches,
        latency_ms=round(latency_ms, 2),
        timestamp=result.timestamp.isoformat(),
    )


@router.get(
    "/decisions",
    response_model=PaginatedResponse[DecisionResponse],
    summary="List Evaluated Decisions",
    description="Retrieves a paginated list of historically evaluated decisions with filtering by decision verdict, agent, and session.",
)
def list_decisions(
    decision: Optional[str] = Query(None, description="Filter by verdict: ALLOW, REVIEW, or BLOCK"),
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    session_id: Optional[str] = Query(None, description="Filter by session identifier"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page (max 100)"),
    auth: AuthContext = Depends(require_permission(Permission.DECISIONS_READ.value)),
) -> PaginatedResponse[DecisionResponse]:
    from runtimeverify.api.app import decisions_cache

    results: List[DecisionResponse] = []
    for d_id, data in decisions_cache.items():
        verdict = data.get("status") or data.get("decision", "ALLOW")
        if decision and verdict.upper() != decision.upper():
            continue

        ev = data.get("event", {})
        ag_id = data.get("agent_id") or ev.get("agent_id")
        sess_id = data.get("session_id") or ev.get("session_id")

        if agent_id and ag_id != agent_id:
            continue
        if session_id and sess_id != session_id:
            continue

        ts = data.get("timestamp") or ev.get("timestamp")
        if not ts:
            ts = datetime.now(timezone.utc).isoformat()
        elif isinstance(ts, datetime):
            ts = ts.isoformat()

        ev_evidence = data.get("evidence", [])
        if ev_evidence is None:
            ev_evidence = []

        results.append(
            DecisionResponse(
                verification_id=d_id,
                decision=verdict,
                risk_level=data.get("risk_level", "LOW"),
                confidence=float(data.get("confidence", 1.0)),
                reason=data.get("reason") or "Evaluated decision record",
                action_type=ev.get("type") or ev.get("action_type"),
                target=ev.get("target") or ev.get("path") or ev.get("url"),
                agent_id=ag_id,
                session_id=sess_id,
                evidence=ev_evidence,
                policy_matches=data.get("policy_matches", []),
                latency_ms=float(data.get("latency_ms", 0.0)),
                timestamp=str(ts),
            )
        )

    return paginate_items(results, page=page, page_size=page_size)


@router.get(
    "/decisions/{decision_id}",
    response_model=DecisionResponse,
    summary="Get Decision by ID",
    description="Retrieves a specific evaluation decision record by its identifier.",
)
def get_decision(
    decision_id: str,
    auth: AuthContext = Depends(require_permission(Permission.DECISIONS_READ.value)),
) -> DecisionResponse:
    from runtimeverify.api.app import decisions_cache

    if decision_id not in decisions_cache:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Decision with ID '{decision_id}' was not found",
        )

    data = decisions_cache[decision_id]
    verdict = data.get("status") or data.get("decision", "ALLOW")
    ev = data.get("event", {})
    ag_id = data.get("agent_id") or ev.get("agent_id")
    sess_id = data.get("session_id") or ev.get("session_id")

    ts = data.get("timestamp") or ev.get("timestamp")
    if not ts:
        ts = datetime.now(timezone.utc).isoformat()
    elif isinstance(ts, datetime):
        ts = ts.isoformat()

    ev_evidence = data.get("evidence", [])
    if ev_evidence is None:
        ev_evidence = []

    return DecisionResponse(
        verification_id=decision_id,
        decision=verdict,
        risk_level=data.get("risk_level", "LOW"),
        confidence=float(data.get("confidence", 1.0)),
        reason=data.get("reason") or "Evaluated decision record",
        action_type=ev.get("type") or ev.get("action_type"),
        target=ev.get("target") or ev.get("path") or ev.get("url"),
        agent_id=ag_id,
        session_id=sess_id,
        evidence=ev_evidence,
        policy_matches=data.get("policy_matches", []),
        latency_ms=float(data.get("latency_ms", 0.0)),
        timestamp=str(ts),
    )
