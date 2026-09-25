"""
Comprehensive unit and integration tests for the Semantic Decision Engine integration (Phase 5).
Covers:
- NullDecisionEngine
- SemanticEngineConfig and DecisionSignal models
- Factory and registry behavior
- LayaDecisionEngine with mocked Router (categorization, risk, confidence, routing metadata)
- Timeout safeguards and error recovery
- 4-Tier Security Hierarchy in RuntimeActionInterceptor:
    1. Hard deterministic policy
    2. Semantic signal escalation
    3. Behavioral verification anomaly
    4. Final policy decision
"""

import time
from typing import Any, Dict
import pytest

from runtimeverify.interception import (
    Action,
    ExecutionBlockedError,
    ExecutionReviewRequiredError,
    InterceptionMode,
    RuntimeActionInterceptor,
)
from runtimeverify.policy.evaluator import PolicyEvaluator
from runtimeverify.policy.loader import load_policy_from_yaml
from runtimeverify.semantic import (
    DecisionEngine,
    DecisionSignal,
    DecisionSignalType,
    LayaDecisionEngine,
    NullDecisionEngine,
    RiskClassification,
    SemanticEngineConfig,
    get_semantic_engine,
    register_engine_provider,
)


class MockLayaRouter:
    """
    Mocked Laya Router simulating Laya's public Router.predict API without downloading weights.
    """

    def __init__(
        self,
        category: str = "shell",
        risk: str = "low",
        confidence: float = 0.92,
        requires_review_noul: float = 0.05,
        delay_sec: float = 0.0,
        raise_exc: bool = False,
    ):
        self.category = category
        self.risk = risk
        self.confidence = confidence
        self.requires_review_noul = requires_review_noul
        self.delay_sec = delay_sec
        self.raise_exc = raise_exc
        self.last_state_text = None
        self.last_questions = None

    def predict(self, state: str, questions: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
        self.last_state_text = state
        self.last_questions = questions

        if self.delay_sec > 0:
            time.sleep(self.delay_sec)

        if self.raise_exc:
            raise RuntimeError("Simulated Laya GPU CUDA Out of Memory error")

        return {
            "answers": {
                "action_category": {
                    "type": "choice",
                    "choice": self.category,
                    "confidence": 0.95,
                },
                "risk_level": {
                    "type": "choice",
                    "choice": self.risk,
                    "confidence": self.confidence,
                },
                "requires_review": {
                    "type": "noul",
                    "noul": self.requires_review_noul,
                },
            },
            "routing": {
                "model": "english",
                "repo": "convaiinnovations/laya",
                "reason": "English Latin script detected",
            },
        }


class TestSemanticModels:
    """Verifies data models, enums, confidence validation, and serialization."""

    def test_decision_signal_validation(self):
        sig = DecisionSignal(
            engine_name="laya",
            action_category="shell",
            risk_level=RiskClassification.HIGH,
            confidence=0.88,
            decision_signal=DecisionSignalType.REVIEW,
            explanation="Action requires human review.",
            latency_ms=12.4,
        )
        assert sig.engine_name == "laya"
        assert sig.risk_level == RiskClassification.HIGH
        assert sig.confidence == 0.88
        assert sig.decision_signal == DecisionSignalType.REVIEW
        assert sig.fallback is False

    def test_confidence_normalization_bounds(self):
        # Value > 1.0 clamped
        sig = DecisionSignal(
            engine_name="mock",
            confidence=1.5,
        )
        assert sig.confidence == 1.0

        # Value < 0.0 clamped
        sig_neg = DecisionSignal(
            engine_name="mock",
            confidence=-0.2,
        )
        assert sig_neg.confidence == 0.0

    def test_semantic_engine_config_defaults(self):
        cfg = SemanticEngineConfig()
        assert cfg.enabled is False
        assert cfg.provider == "null"
        assert cfg.timeout_ms == 50.0
        assert cfg.block_risk_threshold == RiskClassification.CRITICAL
        assert cfg.review_risk_threshold == RiskClassification.HIGH
        assert cfg.min_confidence_threshold == 0.60
        assert cfg.escalate_on_critical is True


class TestNullDecisionEngine:
    """Verifies NullDecisionEngine behavior."""

    def test_null_engine_evaluate(self):
        engine = NullDecisionEngine()
        assert engine.name == "null"
        assert engine.is_available() is True

        action = Action.shell(command="ls -la", session_id="s1", agent_id="a1")
        sig = engine.evaluate(action)

        assert sig.engine_name == "null"
        assert sig.decision_signal == DecisionSignalType.NEUTRAL
        assert sig.risk_level == RiskClassification.UNKNOWN
        assert sig.confidence == 1.0
        assert sig.fallback is False
        assert sig.latency_ms == 0.0


class TestEngineFactory:
    """Verifies dynamic engine resolution and custom provider registrations."""

    def test_factory_null_engine(self):
        engine = get_semantic_engine(SemanticEngineConfig(enabled=False))
        assert isinstance(engine, NullDecisionEngine)

        engine2 = get_semantic_engine(SemanticEngineConfig(enabled=True, provider="null"))
        assert isinstance(engine2, NullDecisionEngine)

    def test_factory_laya_engine(self):
        mock_router = MockLayaRouter()
        cfg = SemanticEngineConfig(enabled=True, provider="laya")
        engine = get_semantic_engine(cfg, router=mock_router)
        assert isinstance(engine, LayaDecisionEngine)
        assert engine.name == "laya"

    def test_factory_custom_provider(self):
        class CustomEngine(DecisionEngine):
            @property
            def name(self) -> str:
                return "custom_ai"

            def is_available(self) -> bool:
                return True

            def evaluate(self, event_or_action: Any, context: Any = None) -> DecisionSignal:
                return DecisionSignal(
                    engine_name=self.name,
                    decision_signal=DecisionSignalType.ALLOW,
                )

        register_engine_provider("custom_ai", lambda cfg, kwargs: CustomEngine(cfg))

        engine = get_semantic_engine(SemanticEngineConfig(enabled=True, provider="custom_ai"))
        assert isinstance(engine, CustomEngine)
        assert engine.evaluate(None).engine_name == "custom_ai"

    def test_factory_unsupported_provider(self):
        with pytest.raises(ValueError, match="Unsupported semantic decision engine provider"):
            get_semantic_engine(SemanticEngineConfig(enabled=True, provider="unknown_model_provider"))


class TestLayaDecisionEngine:
    """Verifies Laya adapter with mocked Router over public API contracts."""

    def test_laya_benign_action_allow(self):
        mock_router = MockLayaRouter(category="safe_query", risk="low", confidence=0.96)
        engine = LayaDecisionEngine(router=mock_router)

        action = Action.shell(command="echo 'hello'", session_id="s1", agent_id="a1")
        sig = engine.evaluate(action)

        assert sig.engine_name == "laya"
        assert sig.action_category == "safe_query"
        assert sig.risk_level == RiskClassification.LOW
        assert sig.decision_signal == DecisionSignalType.ALLOW
        assert sig.confidence == 0.96
        assert sig.fallback is False
        assert sig.error is None
        assert "echo 'hello'" in mock_router.last_state_text
        assert "action_category" in mock_router.last_questions

    def test_laya_critical_action_block_signal(self):
        mock_router = MockLayaRouter(category="destructive", risk="critical", confidence=0.94)
        engine = LayaDecisionEngine(router=mock_router)

        action = Action.shell(command="rm -rf /", session_id="s1", agent_id="a1")
        sig = engine.evaluate(action)

        assert sig.risk_level == RiskClassification.CRITICAL
        assert sig.decision_signal == DecisionSignalType.BLOCK
        assert sig.confidence == 0.94
        assert "CRITICAL" in sig.explanation

    def test_laya_high_action_review_signal(self):
        mock_router = MockLayaRouter(category="shell", risk="high", confidence=0.85)
        engine = LayaDecisionEngine(router=mock_router)

        action = Action.shell(command="sudo chmod -R 777 /var", session_id="s1", agent_id="a1")
        sig = engine.evaluate(action)

        assert sig.risk_level == RiskClassification.HIGH
        assert sig.decision_signal == DecisionSignalType.REVIEW
        assert sig.confidence == 0.85

    def test_laya_noul_review_escalation(self):
        # Low choice risk, but noul indicates 0.88 probability of needing human review
        mock_router = MockLayaRouter(category="git", risk="low", confidence=0.90, requires_review_noul=0.88)
        engine = LayaDecisionEngine(router=mock_router)

        action = Action.git(operation="push", repository="repo", target="origin/main", session_id="s1", agent_id="a1")
        sig = engine.evaluate(action)

        assert sig.decision_signal == DecisionSignalType.REVIEW
        assert "human approval" in sig.explanation

    def test_laya_timeout_fallback(self):
        # 10ms timeout threshold, router takes 50ms
        cfg = SemanticEngineConfig(enabled=True, provider="laya", timeout_ms=10.0)
        mock_router = MockLayaRouter(delay_sec=0.05)
        engine = LayaDecisionEngine(config=cfg, router=mock_router)

        action = Action.shell(command="sleep 1", session_id="s1", agent_id="a1")
        sig = engine.evaluate(action)

        assert sig.fallback is True
        assert sig.decision_signal == DecisionSignalType.NEUTRAL
        assert "timed out" in sig.explanation
        assert "Timeout" in sig.error

    def test_laya_runtime_error_fallback(self):
        mock_router = MockLayaRouter(raise_exc=True)
        engine = LayaDecisionEngine(router=mock_router)

        action = Action.shell(command="ls", session_id="s1", agent_id="a1")
        sig = engine.evaluate(action)

        assert sig.fallback is True
        assert sig.decision_signal == DecisionSignalType.NEUTRAL
        assert "CUDA Out of Memory" in sig.error


class TestSecurityHierarchyInterception:
    """
    Verifies the 4-tier security hierarchy:
    1. Hard deterministic policy (Authoritative: BLOCK cannot be overturned, REVIEW cannot be downgraded)
    2. Semantic signal (Escalation only: ALLOW -> BLOCK/REVIEW; REVIEW -> BLOCK)
    3. Behavioral verification (Escalation only: ALLOW -> REVIEW on anomaly)
    4. Final policy decision
    """

    @pytest.fixture
    def default_policy_evaluator(self) -> PolicyEvaluator:
        return PolicyEvaluator(load_policy_from_yaml("examples/policies/default.yaml"))

    def test_deterministic_block_cannot_be_overridden_by_semantic_allow(
        self, default_policy_evaluator: PolicyEvaluator
    ):
        """
        Hard rule denies ~/.ssh/* (BLOCK).
        Semantic engine claims this action is LOW risk (ALLOW).
        Result MUST remain BLOCK.
        """
        semantic_engine = LayaDecisionEngine(router=MockLayaRouter(category="safe_query", risk="low", confidence=0.99))
        interceptor = RuntimeActionInterceptor(
            mode=InterceptionMode.ENFORCE,
            policy_evaluator=default_policy_evaluator,
            semantic_engine=semantic_engine,
        )

        action = Action.filesystem(
            operation="read",
            path="~/.ssh/id_rsa",
            session_id="s-auth",
            agent_id="a-auth",
        )

        with pytest.raises(ExecutionBlockedError) as exc_info:
            interceptor.intercept(action)

        assert exc_info.value.policy_id == "deny-ssh-keys"
        # Verify in audit log that semantic signal was captured but did not overturn BLOCK
        audit = interceptor.audit_log[-1]
        assert audit.decision.status == "BLOCK"
        assert audit.decision.semantic_signal.decision_signal == DecisionSignalType.ALLOW
        assert audit.decision.semantic_signal.risk_level == RiskClassification.LOW

    def test_deterministic_review_cannot_be_downgraded_by_semantic_allow(
        self, default_policy_evaluator: PolicyEvaluator
    ):
        """
        Hard rule requires REVIEW for git push.
        Semantic engine claims action is LOW risk (ALLOW).
        Result MUST remain REVIEW.
        """
        semantic_engine = LayaDecisionEngine(router=MockLayaRouter(category="git", risk="low", confidence=0.95))
        interceptor = RuntimeActionInterceptor(
            mode=InterceptionMode.ENFORCE,
            policy_evaluator=default_policy_evaluator,
            semantic_engine=semantic_engine,
        )

        action = Action.git(
            operation="push",
            repository="Runtime-Verify",
            target="origin/main",
            session_id="s-git",
            agent_id="a-git",
        )

        with pytest.raises(ExecutionReviewRequiredError) as exc_info:
            interceptor.intercept(action)

        assert exc_info.value.policy_id == "review-git-push"
        audit = interceptor.audit_log[-1]
        assert audit.decision.status == "REVIEW"

    def test_semantic_escalation_blocks_deterministic_allow(self, default_policy_evaluator: PolicyEvaluator):
        """
        Action has no matching deterministic policy (defaults to ALLOW).
        Semantic engine classifies it as CRITICAL risk with high confidence.
        Result MUST be escalated to BLOCK.
        """
        semantic_engine = LayaDecisionEngine(
            router=MockLayaRouter(category="destructive", risk="critical", confidence=0.92)
        )
        interceptor = RuntimeActionInterceptor(
            mode=InterceptionMode.ENFORCE,
            policy_evaluator=default_policy_evaluator,
            semantic_engine=semantic_engine,
        )

        # Non-standard destructive payload not explicitly listed in static regexes
        action = Action.shell(
            command="python -c 'import shutil; shutil.rmtree(\"/etc\")'",
            session_id="s-escalate",
            agent_id="a-escalate",
        )

        with pytest.raises(ExecutionBlockedError) as exc_info:
            interceptor.intercept(action)

        assert "SEMANTIC ESCALATION: laya" in exc_info.value.reason
        audit = interceptor.audit_log[-1]
        assert audit.decision.status == "BLOCK"
        assert audit.decision.semantic_signal.risk_level == RiskClassification.CRITICAL

    def test_semantic_escalation_reviews_deterministic_allow(self, default_policy_evaluator: PolicyEvaluator):
        """
        Action has no matching deterministic policy (defaults to ALLOW).
        Semantic engine classifies it as HIGH risk with high confidence.
        Result MUST be escalated to REVIEW.
        """
        semantic_engine = LayaDecisionEngine(router=MockLayaRouter(category="shell", risk="high", confidence=0.88))
        interceptor = RuntimeActionInterceptor(
            mode=InterceptionMode.ENFORCE,
            policy_evaluator=default_policy_evaluator,
            semantic_engine=semantic_engine,
        )

        action = Action.shell(
            command="tar -czf /tmp/backup.tar.gz /home/app/data",
            session_id="s-review",
            agent_id="a-review",
        )

        with pytest.raises(ExecutionReviewRequiredError) as exc_info:
            interceptor.intercept(action)

        assert "SEMANTIC ESCALATION: laya" in exc_info.value.reason
        audit = interceptor.audit_log[-1]
        assert audit.decision.status == "REVIEW"
        assert audit.decision.semantic_signal.risk_level == RiskClassification.HIGH

    def test_semantic_escalation_in_observe_mode(self, default_policy_evaluator: PolicyEvaluator):
        """
        In OBSERVE mode, semantic escalation identifies BLOCK/REVIEW status,
        records it in the audit log, but permits execution without raising exceptions.
        """
        semantic_engine = LayaDecisionEngine(
            router=MockLayaRouter(category="destructive", risk="critical", confidence=0.95)
        )
        interceptor = RuntimeActionInterceptor(
            mode=InterceptionMode.OBSERVE,
            policy_evaluator=default_policy_evaluator,
            semantic_engine=semantic_engine,
        )

        action = Action.shell(
            command="dangerous_command_xyz",
            session_id="s-obs",
            agent_id="a-obs",
        )

        decision, result = interceptor.intercept(action)

        assert decision.execution_permitted is True
        assert decision.status == "BLOCK"
        assert "OBSERVE MODE" in decision.reason
        assert "SEMANTIC ESCALATION" in decision.reason
        assert result is not None
        assert result.success is True

    def test_yaml_loader_with_semantic_engine_config(self, tmp_path):
        """Verifies loading a YAML policy set containing a semantic_engine section."""
        yaml_content = """
version: "1.0"
name: "policy-with-semantic"
semantic_engine:
  enabled: true
  provider: "laya"
  timeout_ms: 60
  model_name: "multilingual"
  min_confidence_threshold: 0.75
policies:
  - id: "allow-tests"
    match:
      command:
        exact: "pytest"
    decision: "ALLOW"
"""
        yaml_file = tmp_path / "policy_semantic.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        policy_set = load_policy_from_yaml(yaml_file)
        assert policy_set.semantic_engine is not None
        assert policy_set.semantic_engine.enabled is True
        assert policy_set.semantic_engine.provider == "laya"
        assert policy_set.semantic_engine.timeout_ms == 60.0
        assert policy_set.semantic_engine.model_name == "multilingual"
        assert policy_set.semantic_engine.min_confidence_threshold == 0.75

    def test_interceptor_auto_loads_null_when_semantic_disabled(self, tmp_path):
        """Verifies interceptor defaults to NullDecisionEngine when semantic_engine is disabled."""
        yaml_content = """
version: "1.0"
name: "policy-no-semantic"
policies: []
"""
        yaml_file = tmp_path / "policy_plain.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        evaluator = PolicyEvaluator(load_policy_from_yaml(yaml_file))
        interceptor = RuntimeActionInterceptor(policy_evaluator=evaluator)
        assert isinstance(interceptor.semantic_engine, NullDecisionEngine)
