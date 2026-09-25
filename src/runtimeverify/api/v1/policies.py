"""
Policies Router for RuntimeVerify API (Phase 11).
Enables policy rule inspection, YAML/JSON validation, dry-run rule testing, and single policy lookup.
"""

from pathlib import Path
from typing import Any, List, Optional
import yaml

from fastapi import APIRouter, Depends, HTTPException, Query, status

from runtimeverify.api.auth import AuthContext, Permission, require_permission
from runtimeverify.api.schemas import (
    PaginatedResponse,
    PolicyRuleSummary,
    PolicyTestRequest,
    PolicyTestResponse,
    PolicyValidateRequest,
    PolicyValidateResponse,
    paginate_items,
)
from runtimeverify.events.canonical import CanonicalEvent
from runtimeverify.events.enums import EventAction, EventType
from runtimeverify.policy.evaluator import PolicyEvaluator
from runtimeverify.policy.loader import load_policy_from_dict, load_policy_from_yaml

router = APIRouter(tags=["Policies"])

_active_policy_evaluator: Optional[PolicyEvaluator] = None


def _get_active_evaluator() -> PolicyEvaluator:
    global _active_policy_evaluator
    if _active_policy_evaluator is None:
        policy_path = Path("examples/policies/default.yaml")
        if policy_path.exists():
            policy_set = load_policy_from_yaml(policy_path)
            _active_policy_evaluator = PolicyEvaluator(policy_set=policy_set)
        else:
            _active_policy_evaluator = PolicyEvaluator()
    return _active_policy_evaluator


@router.get(
    "/policies",
    response_model=PaginatedResponse[PolicyRuleSummary],
    summary="List Active Policy Rules",
    description="Lists the active deterministic security policy rules loaded into the verification engine.",
)
def list_policies(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page (max 100)"),
    auth: AuthContext = Depends(require_permission(Permission.POLICIES_READ.value)),
) -> PaginatedResponse[PolicyRuleSummary]:
    evaluator = _get_active_evaluator()
    rules: List[PolicyRuleSummary] = []

    for p in evaluator.policy_set.policies:
        dec_val = p.decision.value if hasattr(p.decision, "value") else str(p.decision)
        sev_val = p.severity.value if hasattr(p.severity, "value") else str(p.severity)
        match_dict = p.match.model_dump() if hasattr(p.match, "model_dump") else {}

        rules.append(
            PolicyRuleSummary(
                id=p.id,
                description=p.description,
                decision=dec_val,
                severity=sev_val,
                match_criteria=match_dict,
            )
        )

    return paginate_items(rules, page=page, page_size=page_size)


@router.get(
    "/policies/{policy_id}",
    response_model=PolicyRuleSummary,
    summary="Get Policy Rule by ID",
    description="Retrieves a specific policy rule definition by its unique identifier.",
)
def get_policy(
    policy_id: str,
    auth: AuthContext = Depends(require_permission(Permission.POLICIES_READ.value)),
) -> PolicyRuleSummary:
    evaluator = _get_active_evaluator()
    for p in evaluator.policy_set.policies:
        if p.id == policy_id:
            dec_val = p.decision.value if hasattr(p.decision, "value") else str(p.decision)
            sev_val = p.severity.value if hasattr(p.severity, "value") else str(p.severity)
            match_dict = p.match.model_dump() if hasattr(p.match, "model_dump") else {}
            return PolicyRuleSummary(
                id=p.id,
                description=p.description,
                decision=dec_val,
                severity=sev_val,
                match_criteria=match_dict,
            )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Policy rule with ID '{policy_id}' was not found",
    )


@router.post(
    "/policies/validate",
    response_model=PolicyValidateResponse,
    summary="Validate Policy Specification",
    description="Validates YAML or JSON policy specifications for syntax correctness, rule schema, and required match fields.",
)
def validate_policy(
    payload: PolicyValidateRequest,
    auth: AuthContext = Depends(require_permission(Permission.POLICIES_READ.value)),
) -> PolicyValidateResponse:
    errors: List[str] = []
    warnings: List[str] = []
    rules: List[PolicyRuleSummary] = []
    version: Optional[str] = None

    try:
        if payload.format.lower() == "json":
            raw_data = yaml.safe_load(payload.content)
        else:
            raw_data = yaml.safe_load(payload.content)

        if not isinstance(raw_data, dict):
            errors.append("Root policy specification must be a dictionary/mapping")
            return PolicyValidateResponse(valid=False, errors=errors)

        policy_set = load_policy_from_dict(raw_data)
        version = policy_set.version

        for p in policy_set.policies:
            dec_val = p.decision.value if hasattr(p.decision, "value") else str(p.decision)
            sev_val = p.severity.value if hasattr(p.severity, "value") else str(p.severity)
            match_dict = p.match.model_dump() if hasattr(p.match, "model_dump") else {}
            rules.append(
                PolicyRuleSummary(
                    id=p.id,
                    description=p.description,
                    decision=dec_val,
                    severity=sev_val,
                    match_criteria=match_dict,
                )
            )

    except Exception as e:
        errors.append(f"Validation error: {e}")
        return PolicyValidateResponse(valid=False, errors=errors)

    return PolicyValidateResponse(
        valid=len(errors) == 0,
        policy_count=len(rules),
        version=version,
        errors=errors,
        warnings=warnings,
        policies=rules,
    )


@router.post(
    "/policies/test",
    response_model=PolicyTestResponse,
    summary="Dry-Run Test Policy Rule",
    description="Evaluates a candidate or active policy rule against a sample canonical event to test rule matching behavior.",
)
def test_policy(
    payload: PolicyTestRequest,
    auth: AuthContext = Depends(require_permission(Permission.POLICIES_READ.value)),
) -> PolicyTestResponse:
    evaluator = _get_active_evaluator()

    if payload.policy_content:
        try:
            raw = yaml.safe_load(payload.policy_content)
            candidate_set = load_policy_from_dict(raw)
            evaluator = PolicyEvaluator(policy_set=candidate_set)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Candidate policy failed to parse: {e}",
            )

    # Map string type to EventType enum or preserve string
    ev_type: Any = payload.event_type
    try:
        ev_type = EventType(payload.event_type)
    except ValueError:
        for member in EventType:
            if member.name == payload.event_type:
                ev_type = member
                break

    ev_action: Any = payload.action
    try:
        ev_action = EventAction(payload.action)
    except ValueError:
        for act_member in EventAction:
            if act_member.name == payload.action:
                ev_action = act_member
                break

    event = CanonicalEvent(
        event_type=ev_type,
        action=ev_action,
        target=payload.target,
        payload={"path": payload.target, "command": payload.target},
        agent_id=payload.agent_id or "test-agent",
        session_id="test-policy-session",
        metadata=payload.metadata,
    )

    decision = evaluator.evaluate(event)
    matched = decision.policy_id is not None
    dec_type = decision.decision.value if hasattr(decision.decision, "value") else str(decision.decision)

    return PolicyTestResponse(
        matched=matched,
        decision=dec_type if matched else "NO_MATCH",
        policy_id=decision.policy_id,
        severity=decision.severity.value if hasattr(decision.severity, "value") else str(decision.severity),
        reason=decision.reason,
        matched_rule=decision.matched_rule,
    )
