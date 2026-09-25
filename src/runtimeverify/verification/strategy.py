"""
Decision strategy for the Hybrid Runtime Verification Engine.
Implements the 8-tier priority precedence rules, evidence aggregation,
and structured 5-question audit explanation synthesis without score-averaging or magic numbers.
"""

from typing import Any, Dict, List, Optional

from runtimeverify.policy.models import PolicyDecision, PolicyDecisionType
from runtimeverify.semantic.models import (
    DecisionSignal,
    DecisionSignalType,
    RiskClassification,
)
from runtimeverify.verification.models import (
    DecisionExplanation,
    Evidence,
    EvidenceType,
    VerificationEngineConfig,
    VerificationResult,
)


def synthesize_verification(
    config: VerificationEngineConfig,
    action_type: str,
    target: str,
    params: Dict[str, Any],
    agent_id: Optional[str] = None,
    session_id: Optional[str] = None,
    environment: Optional[str] = None,
    policy_decision: Optional[PolicyDecision] = None,
    semantic_signal: Optional[DecisionSignal] = None,
    markov_prob: Optional[float] = None,
    markov_state: Optional[str] = None,
    prev_markov_state: Optional[str] = None,
    sprt_status: Optional[str] = None,
    sprt_llr: Optional[float] = None,
    sprt_count: int = 0,
    latency_ms: float = 0.0,
) -> VerificationResult:
    """
    Applies the explicit 8-tier precedence strategy over policy, semantic, and behavioral outputs.
    """
    evidence_list: List[Evidence] = []
    controls_triggered: List[str] = []
    policy_matches: List[Dict[str, Any]] = []

    # -------------------------------------------------------------
    # 1. Evidence Aggregation
    # -------------------------------------------------------------
    # Policy Evidence
    if policy_decision is not None:
        if policy_decision.matched_policies:
            policy_matches.extend(policy_decision.matched_policies)
        elif policy_decision.matched_rule:
            policy_matches.append(policy_decision.matched_rule)

        if policy_decision.policy_id != "default":
            evidence_list.append(
                Evidence(
                    source=EvidenceType.DETERMINISTIC_POLICY,
                    source_name="policy_evaluator",
                    severity=policy_decision.severity.value,
                    title=f"Policy Triggered: {policy_decision.policy_id}",
                    description=policy_decision.reason,
                    data={
                        "decision": policy_decision.decision.value,
                        "policy_id": policy_decision.policy_id,
                        "severity": policy_decision.severity.value,
                        "matched_rule": policy_decision.matched_rule,
                    },
                )
            )

    # Semantic Evidence
    semantic_evidence_dict = None
    if semantic_signal is not None:
        semantic_evidence_dict = semantic_signal.model_dump()
        if not semantic_signal.fallback:
            evidence_list.append(
                Evidence(
                    source=EvidenceType.SEMANTIC_SIGNAL,
                    source_name=semantic_signal.engine_name,
                    severity=semantic_signal.risk_level.value,
                    title=f"Semantic Signal: {semantic_signal.engine_name.upper()}",
                    description=semantic_signal.explanation or "Semantic analysis completed.",
                    data={
                        "action_category": semantic_signal.action_category,
                        "risk_level": semantic_signal.risk_level.value,
                        "confidence": semantic_signal.confidence,
                        "decision_signal": semantic_signal.decision_signal.value,
                    },
                )
            )
        else:
            evidence_list.append(
                Evidence(
                    source=EvidenceType.SEMANTIC_SIGNAL,
                    source_name=semantic_signal.engine_name,
                    severity="LOW",
                    title=f"Semantic Fallback: {semantic_signal.engine_name.upper()}",
                    description=f"Semantic evaluation unavailable: {semantic_signal.error}",
                    data={"fallback": True, "error": semantic_signal.error},
                )
            )

    # Behavioral Evidence
    behavioral_evidence_dict = None
    if markov_prob is not None or sprt_status is not None:
        behavioral_evidence_dict = {
            "prev_state": prev_markov_state,
            "curr_state": markov_state,
            "transition_probability": markov_prob,
            "sprt_status": sprt_status,
            "sprt_llr": sprt_llr,
            "sprt_step_count": sprt_count,
        }

        if markov_prob is not None:
            is_rare = markov_prob < config.markov_anomaly_prob_threshold
            evidence_list.append(
                Evidence(
                    source=EvidenceType.BEHAVIORAL_TRANSITION,
                    source_name="markov_model",
                    severity="HIGH" if is_rare else "INFO",
                    title="Markov Transition Analysis",
                    description=(
                        f"State transition '{prev_markov_state or 'START'}' -> '{markov_state}' "
                        f"probability: {markov_prob:.4e} "
                        f"({'ANOMALY' if is_rare else 'NORMAL'})"
                    ),
                    data={
                        "prev_state": prev_markov_state,
                        "curr_state": markov_state,
                        "probability": markov_prob,
                        "threshold": config.markov_anomaly_prob_threshold,
                    },
                )
            )

        if sprt_status is not None:
            is_sprt_drift = sprt_status in ("REJECT_H0", "ACCEPT_H1")
            evidence_list.append(
                Evidence(
                    source=EvidenceType.SPRT_DRIFT,
                    source_name="sprt_engine",
                    severity="HIGH" if is_sprt_drift else "INFO",
                    title="Sequential SPRT Verification",
                    description=(
                        f"SPRT status '{sprt_status}' with cumulative LLR {sprt_llr:.4f} "
                        f"({'DRIFT DETECTED' if is_sprt_drift else 'IN BOUNDS'})"
                    ),
                    data={
                        "status": sprt_status,
                        "llr": sprt_llr,
                        "step_count": sprt_count,
                    },
                )
            )

    # -------------------------------------------------------------
    # 2. Decision Synthesis (8-Tier Precedence Rules)
    # -------------------------------------------------------------
    decision = "ALLOW"
    risk_level = "LOW"
    confidence = 0.95
    reason = (
        "Action approved: conforms to deterministic policies, semantic intent, and statistical behavioral baselines."
    )
    why_suspicious = None
    behavioral_deviation = False

    # Tier 1: Authoritative Deterministic Policy BLOCK
    if (
        policy_decision is not None
        and policy_decision.decision == PolicyDecisionType.BLOCK
        and config.policy_block_enabled
    ):
        decision = "BLOCK"
        risk_level = policy_decision.severity.value
        confidence = 1.0
        reason = f"Deterministic security policy violation: {policy_decision.reason}"
        why_suspicious = (
            f"Explicitly forbidden by deterministic rule '{policy_decision.policy_id}': {policy_decision.reason}"
        )
        controls_triggered.append(f"policy:{policy_decision.policy_id}")

    # Tier 2: Semantic CRITICAL Risk Escalation
    elif (
        semantic_signal is not None
        and not semantic_signal.fallback
        and semantic_signal.risk_level == RiskClassification.CRITICAL
        and semantic_signal.confidence >= config.semantic_min_confidence
    ):
        decision = config.semantic_critical_escalates_to.upper()
        risk_level = "CRITICAL"
        confidence = semantic_signal.confidence
        reason = f"[SEMANTIC ESCALATION: {semantic_signal.engine_name}] Critical risk detected: {semantic_signal.explanation}"
        why_suspicious = (
            f"Semantic classifier flagged action as CRITICAL risk with "
            f"{semantic_signal.confidence:.2f} confidence: {semantic_signal.explanation}"
        )
        controls_triggered.append(f"semantic:{semantic_signal.engine_name}:critical")

    # Tier 3: Authoritative Deterministic Policy REVIEW
    elif (
        policy_decision is not None
        and policy_decision.decision == PolicyDecisionType.REVIEW
        and config.policy_review_enabled
    ):
        decision = "REVIEW"
        risk_level = policy_decision.severity.value
        confidence = 1.0
        reason = f"Deterministic policy requires human review: {policy_decision.reason}"
        why_suspicious = f"Triggered review policy '{policy_decision.policy_id}': {policy_decision.reason}"
        controls_triggered.append(f"policy:{policy_decision.policy_id}")

    # Tier 4: Statistical Sequential SPRT Drift Anomaly
    elif sprt_status is not None and sprt_status in ("REJECT_H0", "ACCEPT_H1"):
        decision = config.sprt_drift_escalates_to.upper()
        risk_level = "HIGH"
        confidence = max(0.85, 1.0 - config.sprt_alpha)
        behavioral_deviation = True
        reason = (
            f"[SPRT DRIFT DETECTED] Cumulative log-likelihood ratio ({sprt_llr:.4f}) crossed Wald anomaly threshold."
        )
        why_suspicious = "Cumulative statistical drift detected over sequential transitions. Agent trajectory deviates persistently from benign baseline."
        controls_triggered.append("sprt:wald_upper_threshold")

    # Tier 5: Semantic HIGH Risk or Review Escalation
    elif (
        semantic_signal is not None
        and not semantic_signal.fallback
        and (
            semantic_signal.risk_level == RiskClassification.HIGH
            or semantic_signal.decision_signal == DecisionSignalType.REVIEW
        )
        and semantic_signal.confidence >= config.semantic_min_confidence
    ):
        decision = config.semantic_high_escalates_to.upper()
        risk_level = "HIGH"
        confidence = semantic_signal.confidence
        reason = (
            f"[SEMANTIC ESCALATION: {semantic_signal.engine_name}] High risk detected: {semantic_signal.explanation}"
        )
        why_suspicious = f"Semantic classifier identified elevated risk: {semantic_signal.explanation}"
        controls_triggered.append(f"semantic:{semantic_signal.engine_name}:high")

    # Tier 6: Combined Risk (Moderate Semantic Risk + Rare Markov Transition)
    elif (
        config.combined_risk_escalation
        and semantic_signal is not None
        and not semantic_signal.fallback
        and semantic_signal.risk_level == RiskClassification.MEDIUM
        and markov_prob is not None
        and markov_prob < config.markov_anomaly_prob_threshold
    ):
        decision = "REVIEW"
        risk_level = "MEDIUM"
        confidence = 0.80
        behavioral_deviation = True
        reason = f"[COMBINED RISK] Moderate semantic risk accompanied by rare Markov transition (p={markov_prob:.2e})."
        why_suspicious = "Multiple sub-threshold indicators correlated: non-standard intent profile accompanied by novel operational transition."
        controls_triggered.extend([f"semantic:{semantic_signal.engine_name}:medium", "markov:rare_transition"])

    # Tier 7: Isolated Markov Transition Anomaly
    elif markov_prob is not None and markov_prob < config.markov_anomaly_prob_threshold:
        decision = config.markov_anomaly_escalates_to.upper()
        risk_level = "MEDIUM"
        confidence = 0.75
        behavioral_deviation = True
        reason = f"[BEHAVIORAL ANOMALY] Transition from '{prev_markov_state or 'START'}' to '{markov_state}' has near-zero baseline probability ({markov_prob:.4e})."
        why_suspicious = f"Agent performed a novel or unobserved sequence step ('{prev_markov_state or 'START'}' -> '{markov_state}')."
        controls_triggered.append("markov:rare_transition")

    # Tier 8: Normal Baseline Execution (Default)
    else:
        decision = "ALLOW"
        risk_level = "LOW"
        confidence = 0.95
        reason = (
            "Action approved: satisfies all deterministic policies, semantic classifications, and behavioral baselines."
        )
        why_suspicious = None

    # -------------------------------------------------------------
    # 3. Action Taken Resolution
    # -------------------------------------------------------------
    if decision == "BLOCK":
        action_taken = "BLOCK"
    elif decision == "REVIEW":
        action_taken = "HOLD_FOR_APPROVAL"
    else:
        action_taken = "EXECUTE"

    # -------------------------------------------------------------
    # 4. Formulate 5-Question Explainability Report
    # -------------------------------------------------------------
    what_happened = f"Agent '{agent_id or 'unknown'}' attempted {action_type} action targeting '{target}'."
    if environment:
        what_happened += f" (Environment: {environment})"

    explanation = DecisionExplanation(
        what_happened=what_happened,
        why_suspicious=why_suspicious,
        which_controls_triggered=controls_triggered,
        behavioral_deviation=behavioral_deviation,
        action_taken=action_taken,
        summary=f"[{decision}] {reason}",
    )

    return VerificationResult(
        decision=decision,
        risk_level=risk_level,
        confidence=confidence,
        reason=reason,
        explanation=explanation,
        evidence=evidence_list,
        policy_matches=policy_matches,
        behavioral_evidence=behavioral_evidence_dict,
        semantic_evidence=semantic_evidence_dict,
        policy_decision=policy_decision,
        semantic_signal=semantic_signal,
        agent_id=agent_id,
        session_id=session_id,
        environment=environment,
        action_type=action_type,
        target=target,
        latency_ms=latency_ms,
    )
