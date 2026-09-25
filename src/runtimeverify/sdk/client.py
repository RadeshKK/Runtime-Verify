"""
RuntimeVerifyClient implementation for RuntimeVerify SDK (Phase 9).
Provides in-process runtime verification, deterministic policy evaluation,
and audit trail management without external server dependencies.
"""

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from runtimeverify.approvals.provider import ApprovalProvider
from runtimeverify.audit import (
    AuditRecord,
    AuditRepository,
    AuditService,
    AuditSink,
    FileAuditRepository,
    FileAuditSink,
    MemoryAuditRepository,
    MemoryAuditSink,
)
from runtimeverify.events.canonical import CanonicalEvent
from runtimeverify.interception.executor import ActionExecutor, SafeActionExecutor
from runtimeverify.interception.interceptor import RuntimeActionInterceptor
from runtimeverify.interception.models import (
    Action,
    ActionResult,
    InterceptionDecision,
    InterceptionMode,
)
from runtimeverify.policy.evaluator import PolicyEvaluator
from runtimeverify.policy.loader import load_policy_from_yaml
from runtimeverify.policy.models import PolicyDecisionType, PolicySet
from runtimeverify.sdk.session import AgentSession
from runtimeverify.semantic import DecisionEngine
from runtimeverify.sprt.engine import SPRTEngine
from runtimeverify.state.adapter import MarkovStateAdapter


class RuntimeVerifyClient:
    """
    Primary client for the RuntimeVerify SDK.
    Coordinates verification, deterministic policy gating, and structured auditing in-process.
    """

    def __init__(
        self,
        mode: Union[InterceptionMode, str] = InterceptionMode.ENFORCE,
        policy_set: Optional[PolicySet] = None,
        policy_path: Optional[Union[str, Path]] = None,
        audit_service: Optional[AuditService] = None,
        audit_log_path: Optional[str] = ".runtimeverify/audit.log",
        audit_sink: Optional[AuditSink] = None,
        audit_repository: Optional[AuditRepository] = None,
        in_memory_audit: bool = False,
        approval_provider: Optional[ApprovalProvider] = None,
        approval_timeout: float = 60.0,
        approval_fail_closed: bool = True,
        fail_closed: bool = True,
        semantic_engine: Optional[DecisionEngine] = None,
        behavioral_adapter: Optional[MarkovStateAdapter] = None,
        sprt_engine: Optional[SPRTEngine] = None,
        executor: Optional[ActionExecutor] = None,
        default_agent_id: str = "default-agent",
        environment: Optional[str] = None,
    ):
        # 1. Operating mode
        if isinstance(mode, str):
            mode = InterceptionMode(mode.lower())
        self.mode = mode
        self.default_agent_id = default_agent_id
        self.environment = environment

        # 2. Audit infrastructure
        if audit_service is not None:
            self.audit_service = audit_service
        elif in_memory_audit:
            mem_sink = audit_sink or MemoryAuditSink()
            mem_repo = audit_repository or MemoryAuditRepository()
            self.audit_service = AuditService(sink=mem_sink, repository=mem_repo)
        else:
            sink = audit_sink or (FileAuditSink(file_path=audit_log_path) if audit_log_path else MemoryAuditSink())
            repo = audit_repository or (
                FileAuditRepository(log_path=audit_log_path) if audit_log_path else MemoryAuditRepository()
            )
            self.audit_service = AuditService(sink=sink, repository=repo)

        # 3. Policy evaluation
        if policy_set is not None:
            self.policy_set = policy_set
        elif policy_path is not None:
            self.policy_set = load_policy_from_yaml(policy_path)
        else:
            # Fallback search for default policy
            default_loc = Path("examples/policies/default.yaml")
            if default_loc.exists():
                self.policy_set = load_policy_from_yaml(default_loc)
            else:
                self.policy_set = PolicySet(name="sdk-default-policy")

        self.policy_evaluator = PolicyEvaluator(policy_set=self.policy_set)

        # 4. Action Interceptor
        self.executor = executor or SafeActionExecutor()
        self.interceptor = RuntimeActionInterceptor(
            mode=self.mode,
            policy_evaluator=self.policy_evaluator,
            semantic_engine=semantic_engine,
            behavioral_adapter=behavioral_adapter,
            sprt_engine=sprt_engine,
            executor=self.executor,
            fail_closed=fail_closed,
            approval_provider=approval_provider,
            approval_timeout=approval_timeout,
            approval_fail_closed=approval_fail_closed,
            audit_service=self.audit_service,
        )

        self._active_sessions: List[AgentSession] = []

    @property
    def audit_repository(self) -> Optional[AuditRepository]:
        """Returns the underlying AuditRepository if configured."""
        return getattr(self.audit_service, "repository", None) if self.audit_service else None

    @property
    def audit_sink(self) -> Optional[AuditSink]:
        """Returns the underlying AuditSink if configured."""
        return getattr(self.audit_service, "sink", None) if self.audit_service else None

    def session(
        self,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        environment: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentSession:
        """
        Creates a scoped AgentSession preserving correlation IDs.
        Can be used as a context manager:
            with client.session(agent_id="my-agent") as session:
                session.execute(...)
        """
        sess = AgentSession(
            client=self,
            agent_id=agent_id or self.default_agent_id,
            session_id=session_id,
            trace_id=trace_id,
            environment=environment or self.environment,
            metadata=metadata,
        )
        self._active_sessions.append(sess)
        return sess

    def check(self, action: Action) -> InterceptionDecision:
        """
        Dry-run inspection of an intended action.
        Evaluates deterministic policies, semantic signals, and verification pipeline
        without executing the underlying action.
        """
        # Save previous mode and evaluate without execution
        prev_mode = self.interceptor.mode
        try:
            self.interceptor.mode = InterceptionMode.OBSERVE
            decision, _ = self.interceptor.intercept(action, execute_fn=lambda act: None)
            is_permitted = decision.status == PolicyDecisionType.ALLOW.value
            return decision.model_copy(
                update={
                    "execution_permitted": is_permitted,
                    "mode": prev_mode,
                }
            )
        finally:
            self.interceptor.mode = prev_mode

    def observe(
        self,
        action: Action,
        execute_fn: Optional[Callable[[Action], Any]] = None,
    ) -> Tuple[InterceptionDecision, Optional[ActionResult]]:
        """
        Observes an action without blocking execution.
        Evaluates policies, generates canonical events, and audits decisions.
        """
        prev_mode = self.interceptor.mode
        try:
            self.interceptor.mode = InterceptionMode.OBSERVE
            return self.interceptor.intercept(action, execute_fn=execute_fn)
        finally:
            self.interceptor.mode = prev_mode

    def authorize(
        self,
        action: Action,
        execute_fn: Optional[Callable[[Action], Any]] = None,
    ) -> ActionResult:
        """
        Enforces runtime verification on an action.
        - If ALLOW: executes and returns ActionResult.
        - If BLOCK: raises ExecutionBlockedError.
        - If REVIEW: pauses for human approval or raises ExecutionReviewRequiredError.
        """
        _, result = self.interceptor.intercept(action, execute_fn=execute_fn)
        if result is None:
            # Action was blocked (exception already raised) or dry-run
            return ActionResult(
                action_id=action.action_id,
                success=False,
                output=None,
                error="Action did not produce an execution result",
            )
        return result

    def record(self, event: CanonicalEvent) -> AuditRecord:
        """Emits a canonical event directly into the audit service."""
        return self.audit_service.log_event(
            summary=f"Event {event.event_type} on target '{event.target}'",
            event_id=event.event_id,
            trace_id=event.trace_id,
            session_id=event.session_id,
            agent_id=event.agent_id,
            details=event.payload or {},
        )

    def close(self) -> None:
        """Closes all active sessions and flushes audit sinks."""
        for sess in list(self._active_sessions):
            if sess.is_active:
                sess.close()
        self._active_sessions.clear()

        # Flush sink if available
        if hasattr(self.audit_service.sink, "flush"):
            try:
                self.audit_service.sink.flush()
            except Exception:
                pass
