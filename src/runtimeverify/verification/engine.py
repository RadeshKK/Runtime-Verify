"""
Unified Hybrid Verification Engine for RuntimeVerify (Phase 6).
Coordinates deterministic policy checks, semantic intent classification,
Markov transition probabilities, and SPRT sequential verification into a single pipeline.
"""

import logging
import time
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from runtimeverify.events.base import Event
from runtimeverify.policy.evaluator import PolicyEvaluator
from runtimeverify.runtime.context import ExecutionContext
from runtimeverify.semantic.base import DecisionEngine
from runtimeverify.semantic.null import NullDecisionEngine
from runtimeverify.sprt.engine import SPRTEngine
from runtimeverify.state.adapter import MarkovStateAdapter
from runtimeverify.state.security import SecurityState

if TYPE_CHECKING:
    from runtimeverify.interception.models import Action
from runtimeverify.verification.models import (
    VerificationEngineConfig,
    VerificationResult,
)
from runtimeverify.verification.strategy import synthesize_verification

logger = logging.getLogger(__name__)


class VerificationEngine:
    """
    Unified hybrid verification pipeline.
    Executes multi-tier verification over incoming actions or canonical telemetry events:
    1. Deterministic Policy Engine (Hard structural constraints)
    2. Semantic Decision Engine (Laya / intent classification)
    3. Markov Behavioral Model (State transition probabilities)
    4. Wald Sequential Probability Ratio Test (SPRT trajectory drift)
    """

    def __init__(
        self,
        config: Optional[VerificationEngineConfig] = None,
        policy_evaluator: Optional[PolicyEvaluator] = None,
        semantic_engine: Optional[DecisionEngine] = None,
        markov_adapter: Optional[MarkovStateAdapter] = None,
        sprt_engine: Optional[SPRTEngine] = None,
        multiagent_verifier: Optional[Any] = None,
    ):
        self.config = config or VerificationEngineConfig()
        self.policy_evaluator = policy_evaluator or PolicyEvaluator()
        self.semantic_engine = semantic_engine or NullDecisionEngine()
        self.markov_adapter = markov_adapter
        self.sprt_engine = sprt_engine
        self.multiagent_verifier = multiagent_verifier

        # Track previous state tokens per session for Markov transitions
        self._session_prev_tokens: Dict[str, str] = {}

    def reset_session(self, session_id: str) -> None:
        """Resets tracking accumulators for a specific session."""
        self._session_prev_tokens.pop(session_id, None)
        if self.sprt_engine is not None:
            self.sprt_engine.reset_session(session_id)

    def verify(
        self,
        event_or_action: Union["Action", Event, Dict[str, Any]],
        context: Optional[ExecutionContext] = None,
    ) -> VerificationResult:
        """
        Executes the hybrid verification pipeline and synthesizes a VerificationResult.
        """
        start_time = time.perf_counter()

        # ---------------------------------------------------------
        # 1. Normalize Action / Event Metadata
        # ---------------------------------------------------------
        action_type = "generic"
        target = "unknown"
        params: Dict[str, Any] = {}
        agent_id: Optional[str] = None
        session_id: Optional[str] = None
        environment: Optional[str] = None
        canonical_event: Optional[Event] = None

        if hasattr(event_or_action, "to_canonical_event") and hasattr(event_or_action, "action_type"):
            action_obj: Any = event_or_action
            action_type = (
                action_obj.action_type.value
                if hasattr(action_obj.action_type, "value")
                else str(action_obj.action_type)
            )
            target = str(getattr(action_obj, "target", "") or "")
            params = dict(getattr(action_obj, "params", {}))
            agent_id = getattr(action_obj, "agent_id", None)
            session_id = getattr(action_obj, "session_id", None)
            ctx = getattr(action_obj, "context", None)
            environment = getattr(ctx, "environment", None) if ctx else None
            try:
                canonical_event = action_obj.to_canonical_event()
            except Exception as e:
                logger.error(
                    "Failed to construct canonical event from action '%s': %s",
                    getattr(action_obj, "action_id", "unknown"),
                    e,
                )
                canonical_event = None

        elif isinstance(event_or_action, Event):
            raw_action_type = getattr(event_or_action, "event_type", getattr(event_or_action, "type", "generic"))
            if hasattr(raw_action_type, "value"):
                action_type = str(raw_action_type.value)
            else:
                action_type = str(raw_action_type)
            target = str(getattr(event_or_action, "target", getattr(event_or_action, "path", "unknown")))
            agent_id = getattr(event_or_action, "agent_id", None)
            session_id = getattr(event_or_action, "session_id", None)
            canonical_event = event_or_action

        elif isinstance(event_or_action, dict):
            action_type = str(event_or_action.get("action_type") or event_or_action.get("type", "generic"))
            target = str(
                event_or_action.get("target")
                or event_or_action.get("command")
                or event_or_action.get("path", "unknown")
            )
            params = event_or_action.get("params") or {}
            agent_id = event_or_action.get("agent_id")
            session_id = event_or_action.get("session_id")

        if context is not None:
            if not agent_id:
                agent_id = context.agent_id
            if not session_id:
                session_id = context.session_id
            if not environment and context.environment:
                environment = context.environment

        active_session_id = session_id or "default-session"

        # ---------------------------------------------------------
        # 1.5 Multi-Agent Verification (Phase 17)
        # ---------------------------------------------------------
        if self.multiagent_verifier and canonical_event is not None:
            if (
                canonical_event.target_agent_id
                or canonical_event.parent_agent_id
                or canonical_event.agent_role
                or canonical_event.event_type in ("agent.communication", "agent.delegation", "agent.handoff")
            ):
                try:
                    ma_res = self.multiagent_verifier.verify_event(canonical_event)
                    if ma_res.decision == "BLOCK":
                        from runtimeverify.verification.models import DecisionExplanation, Evidence, EvidenceType

                        latency_ms = (time.perf_counter() - start_time) * 1000.0
                        return VerificationResult(
                            decision="BLOCK",
                            risk_level=ma_res.risk_level,
                            confidence=ma_res.confidence,
                            reason=f"[MULTI-AGENT VIOLATION] {ma_res.reason}",
                            explanation=DecisionExplanation(
                                what_happened=f"Multi-agent interaction {canonical_event.agent_id} -> {canonical_event.target_agent_id or 'unknown'}",
                                why_suspicious=ma_res.reason,
                                which_controls_triggered=["MultiAgentTopologyPolicy"],
                                behavioral_deviation=True,
                                action_taken="BLOCKED",
                                summary=f"[MULTI-AGENT VIOLATION] {ma_res.reason}",
                            ),
                            evidence=[
                                Evidence(
                                    source=EvidenceType.ANOMALY_DETECTION,
                                    source_name="multiagent_topology",
                                    severity=e.get("severity", "HIGH"),
                                    title=f"Multi-Agent Anomaly: {e.get('anomaly_type', 'violation')}",
                                    description=e.get("reason", "Topological or privilege violation"),
                                    data=e,
                                )
                                for e in ma_res.evidence
                            ],
                            policy_matches=[],
                            behavioral_evidence=None,
                            semantic_evidence=None,
                            latency_ms=latency_ms,
                        )
                except Exception as e:
                    logger.error("Multi-agent verification error: %s", e)

        # ---------------------------------------------------------
        # 2. Tier 1: Deterministic Policy Evaluation
        # ---------------------------------------------------------
        policy_decision = None
        if self.policy_evaluator and canonical_event is not None:
            try:
                policy_decision = self.policy_evaluator.evaluate(canonical_event)
            except Exception as e:
                logger.error("Policy evaluation error during verification: %s", e)

        # ---------------------------------------------------------
        # 3. Tier 2: Semantic Intent & Risk Evaluation
        # ---------------------------------------------------------
        semantic_signal = None
        if self.semantic_engine:
            try:
                semantic_signal = self.semantic_engine.evaluate(event_or_action, context)
            except Exception as e:
                logger.error("Semantic engine error during verification: %s", e)

        # ---------------------------------------------------------
        # 4. Tier 3: Behavioral Markov & SPRT Evaluation
        # ---------------------------------------------------------
        markov_prob: Optional[float] = None
        markov_state: Optional[str] = None
        prev_markov_state: Optional[str] = None
        sprt_status: Optional[str] = None
        sprt_llr: Optional[float] = None
        sprt_count: int = 0

        # Classify state through adapter if available
        classified_security_state: Optional[SecurityState] = None
        if self.markov_adapter and canonical_event is not None:
            try:
                classified_security_state = self.markov_adapter.event_to_state(canonical_event)
                curr_token = self.markov_adapter.state_to_token(classified_security_state)
                markov_state = curr_token
                prev_token = self._session_prev_tokens.get(active_session_id)
                prev_markov_state = prev_token

                if prev_token is not None:
                    markov_prob = self.markov_adapter.model.transition_probability(prev_token, curr_token)
                else:
                    markov_prob = 1.0  # Initial transition in session

                # Update session previous token
                self._session_prev_tokens[active_session_id] = curr_token
            except Exception as e:
                logger.warning("Markov adapter observation failed: %s", e)

        # Run sequential SPRT accumulator
        if self.sprt_engine and classified_security_state is not None:
            try:
                sprt_res = self.sprt_engine.observe_sprt(classified_security_state)
                sprt_status = sprt_res.status
                sprt_llr = sprt_res.log_likelihood_ratio
                sprt_count = sprt_res.observation_count
            except Exception as e:
                logger.warning("SPRT sequential verification failed: %s", e)

        # ---------------------------------------------------------
        # 5. Synthesize Decisions with Explicit Precedence
        # ---------------------------------------------------------
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        return synthesize_verification(
            config=self.config,
            action_type=action_type,
            target=target,
            params=params,
            agent_id=agent_id,
            session_id=active_session_id,
            environment=environment,
            policy_decision=policy_decision,
            semantic_signal=semantic_signal,
            markov_prob=markov_prob,
            markov_state=markov_state,
            prev_markov_state=prev_markov_state,
            sprt_status=sprt_status,
            sprt_llr=sprt_llr,
            sprt_count=sprt_count,
            latency_ms=latency_ms,
        )
