from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

from runtimeverify.approvals.models import (
    ApprovalDecisionType,
    ApprovalRequest,
    ApprovalTimeoutBehavior,
)
from runtimeverify.approvals.provider import ApprovalProvider
from runtimeverify.interception.exceptions import (
    ExecutionBlockedError,
    ExecutionReviewRequiredError,
    SecurityFailClosedError,
)
from runtimeverify.interception.executor import ActionExecutor, SafeActionExecutor
from runtimeverify.interception.models import (
    Action,
    ActionResult,
    AuditLogEntry,
    InterceptionDecision,
    InterceptionMode,
)
from runtimeverify.policy.evaluator import PolicyEvaluator
from runtimeverify.policy.models import PolicyDecisionType
from runtimeverify.semantic import (
    DecisionEngine,
    NullDecisionEngine,
    get_semantic_engine,
)
from runtimeverify.audit.service import AuditService
from runtimeverify.sprt.engine import SPRTEngine
from runtimeverify.state.adapter import MarkovStateAdapter
from runtimeverify.verification.engine import VerificationEngine
from runtimeverify.verification.strategy import synthesize_verification

logger = logging.getLogger(__name__)


class ActionInterceptor(ABC):
    """
    Vendor-neutral abstraction for intercepting, inspecting, and governing agent actions
    prior to execution.
    """

    @abstractmethod
    def intercept(
        self,
        action: Action,
        execute_fn: Optional[Callable[[Action], Any]] = None,
    ) -> Tuple[InterceptionDecision, Optional[ActionResult]]:
        """
        Intercepts an agent action, performs policy and behavioral evaluation,
        and either executes the action or enforces a security block / review.

        Args:
            action: The proposed agent action.
            execute_fn: Optional execution callable overriding the default executor.

        Returns:
            Tuple of (InterceptionDecision, Optional[ActionResult]).
        """
        pass


class RuntimeActionInterceptor(ActionInterceptor):
    """
    Production implementation of the runtime interception layer.
    Coordinates canonical event creation, policy evaluation, behavioral verification,
    and execution dispatching with full auditability and fail-closed security guarantees.
    """

    def __init__(
        self,
        mode: InterceptionMode = InterceptionMode.ENFORCE,
        policy_evaluator: Optional[PolicyEvaluator] = None,
        semantic_engine: Optional[DecisionEngine] = None,
        behavioral_adapter: Optional[MarkovStateAdapter] = None,
        sprt_engine: Optional[SPRTEngine] = None,
        verification_engine: Optional[VerificationEngine] = None,
        executor: Optional[ActionExecutor] = None,
        fail_closed: bool = True,
        approval_provider: Optional[ApprovalProvider] = None,
        approval_timeout: float = 60.0,
        approval_fail_closed: bool = True,
        audit_service: Optional[AuditService] = None,
        audit_sink: Optional[Callable[[AuditLogEntry], None]] = None,
    ):
        self.mode = mode
        if verification_engine is not None:
            self.verification_engine = verification_engine
            self.policy_evaluator = verification_engine.policy_evaluator
            self.semantic_engine = verification_engine.semantic_engine
            self.behavioral_adapter = verification_engine.markov_adapter
            self.sprt_engine = verification_engine.sprt_engine
        else:
            self.policy_evaluator = policy_evaluator or PolicyEvaluator()
            if semantic_engine is not None:
                self.semantic_engine = semantic_engine
            elif (
                self.policy_evaluator
                and hasattr(self.policy_evaluator, "policy_set")
                and getattr(self.policy_evaluator.policy_set, "semantic_engine", None)
            ):
                self.semantic_engine = get_semantic_engine(self.policy_evaluator.policy_set.semantic_engine)
            else:
                self.semantic_engine = NullDecisionEngine()
            self.behavioral_adapter = behavioral_adapter
            self.sprt_engine = sprt_engine
            self.verification_engine = VerificationEngine(
                policy_evaluator=self.policy_evaluator,
                semantic_engine=self.semantic_engine,
                markov_adapter=self.behavioral_adapter,
                sprt_engine=self.sprt_engine,
            )
        self.executor = executor or SafeActionExecutor()
        self.fail_closed = fail_closed
        self.approval_provider = approval_provider
        self.approval_timeout = approval_timeout
        self.approval_fail_closed = approval_fail_closed
        self.audit_service = audit_service
        self.audit_sink = audit_sink
        self._audit_log: List[AuditLogEntry] = []
        self._session_prev_tokens: Dict[str, str] = {}

    @property
    def audit_log(self) -> List[AuditLogEntry]:
        """Returns the in-memory audit log history."""
        return list(self._audit_log)

    def clear_audit_log(self) -> None:
        """Clears in-memory audit records."""
        self._audit_log.clear()

    def intercept(
        self,
        action: Action,
        execute_fn: Optional[Callable[[Action], Any]] = None,
    ) -> Tuple[InterceptionDecision, Optional[ActionResult]]:
        """
        Executes the interception pipeline for an incoming agent action.
        """
        # 1. Event Creation: Convert Action to CanonicalEvent
        try:
            canonical_event = action.to_canonical_event()
        except Exception as e:
            logger.error("Failed to construct canonical event from action '%s': %s", action.action_id, e)
            if self.fail_closed and self.mode == InterceptionMode.ENFORCE:
                raise SecurityFailClosedError(action.action_id, f"Canonical event generation error: {e}") from e
            canonical_event = None

        # 2. Policy Evaluation
        policy_decision = None
        if self.policy_evaluator and canonical_event is not None:
            try:
                policy_decision = self.policy_evaluator.evaluate(canonical_event)
            except Exception as e:
                logger.error("Policy evaluation failed on action '%s': %s", action.action_id, e)
                if self.fail_closed and self.mode == InterceptionMode.ENFORCE:
                    raise SecurityFailClosedError(action.action_id, f"Policy evaluator error: {e}") from e

        # 3. Semantic Engine Evaluation
        semantic_signal = None
        if self.semantic_engine:
            try:
                semantic_signal = self.semantic_engine.evaluate(action)
            except Exception as e:
                logger.error("Semantic engine evaluation failed on action '%s': %s", action.action_id, e)
                if self.fail_closed and self.mode == InterceptionMode.ENFORCE:
                    raise SecurityFailClosedError(action.action_id, f"Semantic engine error: {e}") from e

        # 4. Behavioral & Statistical SPRT Evaluation
        behavioral_score = None
        behavioral_decision = None
        markov_state = None
        prev_markov_state = None
        sprt_status = None
        sprt_llr = None
        sprt_count = 0
        classified_security_state = None

        if self.behavioral_adapter and canonical_event is not None:
            try:
                prev_token = self._session_prev_tokens.get(action.session_id)
                classified_security_state, prob = self.behavioral_adapter.observe_event(prev_token, canonical_event)
                curr_token = self.behavioral_adapter.state_to_token(classified_security_state)
                markov_state = curr_token
                prev_markov_state = prev_token
                behavioral_score = prob
                behavioral_decision = (
                    "NORMAL" if prob >= self.verification_engine.config.markov_anomaly_prob_threshold else "ANOMALY"
                )
                self._session_prev_tokens[action.session_id] = curr_token
            except Exception as e:
                logger.warning("Behavioral adapter observation failed for action '%s': %s", action.action_id, e)

        if self.sprt_engine and classified_security_state is not None:
            try:
                sprt_res = self.sprt_engine.observe_sprt(classified_security_state)
                sprt_status = sprt_res.status
                sprt_llr = sprt_res.log_likelihood_ratio
                sprt_count = sprt_res.observation_count
            except Exception as e:
                logger.warning("SPRT sequential verification failed for action '%s': %s", action.action_id, e)

        # 5. Hybrid Verification Synthesis using explicit precedence
        v_res = synthesize_verification(
            config=self.verification_engine.config,
            action_type=action.action_type.value,
            target=action.target,
            params=dict(action.params),
            agent_id=action.agent_id,
            session_id=action.session_id,
            environment=getattr(action.context, "environment", None) if action.context else None,
            policy_decision=policy_decision,
            semantic_signal=semantic_signal,
            markov_prob=behavioral_score,
            markov_state=markov_state,
            prev_markov_state=prev_markov_state,
            sprt_status=sprt_status,
            sprt_llr=sprt_llr,
            sprt_count=sprt_count,
            latency_ms=0.0,
        )

        final_status = v_res.decision
        final_reason = v_res.reason

        audit_snapshot = {
            "action_id": action.action_id,
            "action_type": action.action_type.value,
            "target": action.target,
            "params": action.params,
            "agent_id": action.agent_id,
            "session_id": action.session_id,
            "mode": self.mode.value,
            "policy_decision": policy_decision.model_dump() if policy_decision else None,
            "semantic_signal": semantic_signal.model_dump() if semantic_signal else None,
            "behavioral_score": behavioral_score,
            "behavioral_decision": behavioral_decision,
            "verification_result": v_res.model_dump(),
            "final_status": final_status,
            "final_reason": final_reason,
        }

        # Handle OBSERVE Mode
        if self.mode == InterceptionMode.OBSERVE:
            decision = InterceptionDecision(
                action_id=action.action_id,
                mode=self.mode,
                status=final_status,
                execution_permitted=True,
                effective_action="EXECUTE",
                policy_decision=policy_decision,
                semantic_signal=semantic_signal,
                behavioral_score=behavioral_score,
                behavioral_decision=behavioral_decision,
                verification_result=v_res,
                reason=f"[OBSERVE MODE] {final_reason} Action executed without enforcement.",
                audit_record=audit_snapshot,
            )
            result = self._execute_action(action, execute_fn)
            self._record_audit(action, decision, result)
            return decision, result

        # Handle ENFORCE Mode
        if final_status == PolicyDecisionType.BLOCK.value:
            decision = InterceptionDecision(
                action_id=action.action_id,
                mode=self.mode,
                status=PolicyDecisionType.BLOCK.value,
                execution_permitted=False,
                effective_action="BLOCK",
                policy_decision=policy_decision,
                semantic_signal=semantic_signal,
                behavioral_score=behavioral_score,
                behavioral_decision=behavioral_decision,
                verification_result=v_res,
                reason=final_reason,
                audit_record=audit_snapshot,
            )
            self._record_audit(action, decision, None)
            raise ExecutionBlockedError(
                action_id=action.action_id,
                policy_id=(
                    policy_decision.policy_id
                    if (policy_decision and policy_decision.policy_id != "default")
                    else (semantic_signal.engine_name if semantic_signal else "security-engine")
                ),
                reason=final_reason,
                severity=(
                    policy_decision.severity.value
                    if policy_decision
                    else (semantic_signal.risk_level.value if semantic_signal else "CRITICAL")
                ),
                matched_rule=policy_decision.matched_rule if policy_decision else None,
                audit_record=audit_snapshot,
            )

        if final_status == PolicyDecisionType.REVIEW.value:
            # Check if an approval provider is active to pause and request human authorization
            if self.approval_provider is not None:
                approval_req = ApprovalRequest(
                    event_id=canonical_event.event_id if canonical_event else None,
                    action_id=action.action_id,
                    agent_id=action.agent_id,
                    session_id=action.session_id,
                    action={
                        "action_type": action.action_type.value,
                        "target": action.target,
                        "params": action.params,
                    },
                    risk=v_res.risk_level if v_res else "HIGH",
                    reason=final_reason,
                    evidence=[e.model_dump(mode="json") for e in v_res.evidence] if v_res else [],
                    expiration=datetime.now(timezone.utc) + timedelta(seconds=self.approval_timeout),
                    timeout_seconds=self.approval_timeout,
                    timeout_behavior=(
                        ApprovalTimeoutBehavior.DENY if self.approval_fail_closed else ApprovalTimeoutBehavior.APPROVE
                    ),
                )

                approval_dec = self.approval_provider.request_approval(approval_req)

                if approval_dec.decision == ApprovalDecisionType.APPROVE:
                    decision = InterceptionDecision(
                        action_id=action.action_id,
                        mode=self.mode,
                        status=PolicyDecisionType.ALLOW.value,
                        execution_permitted=True,
                        effective_action="EXECUTE",
                        policy_decision=policy_decision,
                        semantic_signal=semantic_signal,
                        behavioral_score=behavioral_score,
                        behavioral_decision=behavioral_decision,
                        verification_result=v_res,
                        reason=f"[HUMAN APPROVED: {approval_dec.decided_by}] {approval_dec.reason or 'Action authorized by human reviewer'}",
                        audit_record={
                            **audit_snapshot,
                            "approval_decision": approval_dec.model_dump(mode="json"),
                        },
                    )
                    result = self._execute_action(action, execute_fn)
                    self._record_audit(action, decision, result)
                    return decision, result
                else:
                    decision = InterceptionDecision(
                        action_id=action.action_id,
                        mode=self.mode,
                        status=PolicyDecisionType.BLOCK.value,
                        execution_permitted=False,
                        effective_action="BLOCK",
                        policy_decision=policy_decision,
                        semantic_signal=semantic_signal,
                        behavioral_score=behavioral_score,
                        behavioral_decision=behavioral_decision,
                        verification_result=v_res,
                        reason=f"[HUMAN DENIED: {approval_dec.decided_by}] {approval_dec.reason or 'Action denied by human reviewer'}",
                        audit_record={
                            **audit_snapshot,
                            "approval_decision": approval_dec.model_dump(mode="json"),
                        },
                    )
                    self._record_audit(action, decision, None)
                    raise ExecutionBlockedError(
                        action_id=action.action_id,
                        policy_id="human-approval-denied",
                        severity=v_res.risk_level if v_res else "HIGH",
                        reason=decision.reason,
                        audit_record=decision.audit_record,
                    )

            decision = InterceptionDecision(
                action_id=action.action_id,
                mode=self.mode,
                status=PolicyDecisionType.REVIEW.value,
                execution_permitted=False,
                effective_action="HOLD_FOR_APPROVAL",
                policy_decision=policy_decision,
                semantic_signal=semantic_signal,
                behavioral_score=behavioral_score,
                behavioral_decision=behavioral_decision,
                verification_result=v_res,
                reason=final_reason,
                audit_record=audit_snapshot,
            )
            self._record_audit(action, decision, None)
            raise ExecutionReviewRequiredError(
                action_id=action.action_id,
                policy_id=(
                    policy_decision.policy_id
                    if (policy_decision and policy_decision.policy_id != "default")
                    else (semantic_signal.engine_name if semantic_signal else "security-engine")
                ),
                reason=final_reason,
                matched_rule=policy_decision.matched_rule if policy_decision else None,
            )

        # ALLOW
        decision = InterceptionDecision(
            action_id=action.action_id,
            mode=self.mode,
            status=PolicyDecisionType.ALLOW.value,
            execution_permitted=True,
            effective_action="EXECUTE",
            policy_decision=policy_decision,
            semantic_signal=semantic_signal,
            behavioral_score=behavioral_score,
            behavioral_decision=behavioral_decision,
            verification_result=v_res,
            reason=final_reason,
            audit_record=audit_snapshot,
        )
        result = self._execute_action(action, execute_fn)
        self._record_audit(action, decision, result)
        return decision, result

    def _execute_action(
        self,
        action: Action,
        execute_fn: Optional[Callable[[Action], Any]] = None,
    ) -> ActionResult:
        """Dispatches execution to execute_fn or the registered ActionExecutor."""
        if execute_fn is not None:
            output = execute_fn(action)
            return ActionResult(
                action_id=action.action_id,
                success=True,
                output=output,
                duration_ms=0.0,
            )
        return self.executor.execute(action)

    def _record_audit(
        self,
        action: Action,
        decision: InterceptionDecision,
        result: Optional[ActionResult],
    ) -> None:
        """Stores audit log entry in memory and forwards to audit_sink and audit_service if configured."""
        entry = AuditLogEntry(
            action=action,
            decision=decision,
            result=result,
            timestamp=datetime.now(timezone.utc),
        )
        self._audit_log.append(entry)
        if self.audit_sink:
            try:
                self.audit_sink(entry)
            except Exception as e:
                logger.error("Audit sink failed to record entry: %s", e)

        if self.audit_service:
            try:
                trace_id = getattr(action, "trace_id", None) or (
                    getattr(action.context, "trace_id", None) if action.context else None
                )
                env = getattr(action.context, "environment", None) if action.context else None

                # 1. Log event record
                self.audit_service.log_event(
                    summary=f"Intercepted {action.action_type.value} action targeting '{action.target}'",
                    event_id=getattr(action, "event_id", None),
                    trace_id=trace_id,
                    session_id=action.session_id,
                    agent_id=action.agent_id,
                    action_id=action.action_id,
                    details={
                        "action_type": action.action_type.value,
                        "target": action.target,
                        "params": action.params,
                    },
                    environment=env,
                )

                # 2. Log policy decision if present
                if decision.policy_decision:
                    pd = decision.policy_decision
                    self.audit_service.log_policy_decision(
                        decision_verdict=pd.decision.value,
                        policy_id=pd.policy_id,
                        reason=pd.reason,
                        severity_str=pd.severity.value,
                        trace_id=trace_id,
                        session_id=action.session_id,
                        agent_id=action.agent_id,
                        action_id=action.action_id,
                        matched_rule=pd.matched_rule,
                        environment=env,
                    )

                # 3. Log semantic decision if present
                if decision.semantic_signal and decision.semantic_signal.engine_name != "null":
                    sig = decision.semantic_signal
                    self.audit_service.log_semantic_decision(
                        engine_name=sig.engine_name,
                        decision_signal=sig.decision_signal.value,
                        risk_level=sig.risk_level.value,
                        confidence=sig.confidence,
                        explanation=sig.explanation,
                        trace_id=trace_id,
                        session_id=action.session_id,
                        agent_id=action.agent_id,
                        action_id=action.action_id,
                        environment=env,
                    )

                # 4. Log behavioral decision if present
                if decision.behavioral_score is not None:
                    self.audit_service.log_behavioral_decision(
                        from_state=self._session_prev_tokens.get(action.session_id),
                        to_state=str(action.action_type.value),
                        transition_prob=decision.behavioral_score,
                        is_anomaly=decision.behavioral_decision == "ANOMALY",
                        trace_id=trace_id,
                        session_id=action.session_id,
                        agent_id=action.agent_id,
                        action_id=action.action_id,
                        environment=env,
                    )

                # 5. Log execution result if executed
                if result is not None:
                    self.audit_service.log_execution_result(
                        action_id=action.action_id,
                        success=result.success,
                        output=result.output,
                        duration_ms=result.duration_ms or 0.0,
                        trace_id=trace_id,
                        session_id=action.session_id,
                        agent_id=action.agent_id,
                        environment=env,
                    )
            except Exception as e:
                logger.error("Audit service failed to record entries: %s", e)
