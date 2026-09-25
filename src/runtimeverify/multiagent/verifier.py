"""
Unified Multi-Agent Verifier for RuntimeVerify (Phase 17).
Orchestrates topology validation, privilege boundary enforcement,
Markov behavioral transitions, and SPRT sequential trajectory verification.
"""

from typing import Any, Dict, List, Optional
from runtimeverify.events.base import Event
from runtimeverify.multiagent.models import (
    MultiAgentAnomaly,
    MultiAgentAnomalyType,
    MultiAgentDecision,
)
from runtimeverify.multiagent.markov import MultiAgentMarkovModel
from runtimeverify.multiagent.sprt import MultiAgentSPRTEngine
from runtimeverify.multiagent.topology import TopologyGraph


class MultiAgentVerifier:
    """
    Coordinates multi-agent verification policies, topological structures,
    and statistical behavioral tracking across collaborating autonomous agent swarms.
    """

    def __init__(
        self,
        topology: Optional[TopologyGraph] = None,
        markov_model: Optional[MultiAgentMarkovModel] = None,
        sprt_engine: Optional[MultiAgentSPRTEngine] = None,
        fail_closed: bool = True,
    ):
        self.topology = topology or TopologyGraph.pipeline()
        self.markov_model = markov_model
        self.sprt_engine = sprt_engine
        self.fail_closed = fail_closed

    def verify_event(self, event: Event) -> MultiAgentDecision:
        """
        Verifies a multi-agent event across topological, privilege, and statistical dimensions.
        """
        source_agent = event.agent_id
        source_role = event.agent_role or event.agent_type or "worker"
        target_agent = event.target_agent_id
        target_role = event.target_agent_role
        action = event.action or event.event_type or "message"
        depth = getattr(event, "delegation_depth", 0)
        call_chain = getattr(event, "call_chain", []) or []

        all_anomalies: List[MultiAgentAnomaly] = []
        evidence_list: List[Dict[str, Any]] = []

        # 1. Structural Topology & Privilege Hierarchy Validation
        topo_anomalies = self.topology.validate_interaction(
            source_agent=source_agent,
            source_role=source_role,
            target_agent=target_agent,
            target_role=target_role,
            action=action,
            delegation_depth=depth,
            call_chain=call_chain,
        )
        all_anomalies.extend(topo_anomalies)

        for anom in topo_anomalies:
            evidence_list.append(
                {
                    "type": "topology_violation",
                    "anomaly_type": anom.anomaly_type.value,
                    "severity": anom.severity,
                    "reason": anom.reason,
                    "details": anom.evidence,
                }
            )

        # 2. Sequential Probability Ratio Test (SPRT) Verification
        sprt_decision = None
        if self.sprt_engine is not None:
            sprt_decision = self.sprt_engine.observe_event(event)
            evidence_list.append(
                {
                    "type": "multiagent_sprt",
                    "status": sprt_decision.status,
                    "log_likelihood_ratio": sprt_decision.log_likelihood_ratio,
                    "transition": sprt_decision.last_transition,
                    "probability": sprt_decision.transition_probability,
                }
            )

            if sprt_decision.status == "ACCEPT_H1":
                all_anomalies.append(
                    MultiAgentAnomaly(
                        anomaly_type=MultiAgentAnomalyType.CROSS_AGENT_ANOMALY,
                        source_agent=source_agent,
                        source_role=source_role,
                        target_agent=target_agent,
                        target_role=target_role,
                        action=action,
                        severity="HIGH",
                        reason=(
                            f"Statistical multi-agent behavioral drift detected (LLR={sprt_decision.log_likelihood_ratio:.2f} "
                            f">= threshold {sprt_decision.upper_threshold:.2f})."
                        ),
                        evidence=sprt_decision.to_dict(),
                    )
                )

        # 3. Decision Synthesis & Precedence Rules
        if not all_anomalies:
            # Check if edge explicitly requires human approval
            edge_key = (source_role.lower(), (target_role or "").lower())
            edge = self.topology._edges.get(edge_key)
            if edge and edge.require_approval:
                return MultiAgentDecision(
                    decision="REVIEW",
                    risk_level="MEDIUM",
                    confidence=1.0,
                    anomalies=[],
                    reason=f"Transition along edge '{source_role} -> {target_role}' requires human approval by policy.",
                    evidence=evidence_list,
                    topology_matched=True,
                )

            return MultiAgentDecision(
                decision="ALLOW",
                risk_level="LOW",
                confidence=1.0,
                anomalies=[],
                reason=f"Interaction '{source_role} -> {target_role or 'self'}:{action}' conforms to topology '{self.topology.name}'.",
                evidence=evidence_list,
                topology_matched=True,
            )

        # Anomalies detected: determine severity and action
        has_critical = any(a.severity == "CRITICAL" for a in all_anomalies)
        has_privilege_escalation = any(
            a.anomaly_type == MultiAgentAnomalyType.PRIVILEGE_ESCALATION for a in all_anomalies
        )
        has_unauthorized = any(
            a.anomaly_type
            in (
                MultiAgentAnomalyType.UNEXPECTED_DELEGATION,
                MultiAgentAnomalyType.ABNORMAL_HANDOFF,
                MultiAgentAnomalyType.CYCLIC_DELEGATION,
                MultiAgentAnomalyType.EXCESSIVE_DELEGATION_DEPTH,
            )
            for a in all_anomalies
        )

        if has_critical or has_privilege_escalation or (has_unauthorized and self.fail_closed):
            primary_reason = all_anomalies[0].reason
            return MultiAgentDecision(
                decision="BLOCK",
                risk_level="CRITICAL" if (has_critical or has_privilege_escalation) else "HIGH",
                confidence=0.95,
                anomalies=all_anomalies,
                reason=primary_reason,
                evidence=evidence_list,
                topology_matched=False,
            )

        # Otherwise HOLD for review
        return MultiAgentDecision(
            decision="REVIEW",
            risk_level="HIGH",
            confidence=0.85,
            anomalies=all_anomalies,
            reason=all_anomalies[0].reason,
            evidence=evidence_list,
            topology_matched=False,
        )
