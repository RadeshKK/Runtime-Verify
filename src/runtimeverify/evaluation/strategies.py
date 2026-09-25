"""
Verification Strategy Abstractions for Benchmark Framework (Phase 13).
Compares:
A. Rules only (Deterministic Policy Engine)
B. Semantic engine only (Intent & Risk Classifier)
C. Markov + SPRT (Statistical Sequential Verification)
D. Rules + semantic + Markov + SPRT (Unified Hybrid Verification Engine)
"""

from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
import time
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field

from runtimeverify.interception.models import Action
from runtimeverify.policy.evaluator import PolicyEvaluator
from runtimeverify.policy.loader import load_policy_from_yaml
from runtimeverify.semantic.base import DecisionEngine
from runtimeverify.semantic.heuristic import HeuristicSemanticEngine
from runtimeverify.sprt import Hypothesis, SPRTEngine
from runtimeverify.state.adapter import MarkovStateAdapter
from runtimeverify.verification.engine import VerificationEngine
from runtimeverify.verification.models import VerificationEngineConfig


class BenchmarkStrategyType(str, Enum):
    """The 4 comparative verification strategies."""

    RULES_ONLY = "rules_only"
    SEMANTIC_ONLY = "semantic_only"
    MARKOV_SPRT = "markov_sprt"
    HYBRID_ALL = "hybrid_all"

    @property
    def display_name(self) -> str:
        names = {
            BenchmarkStrategyType.RULES_ONLY: "Rules Only (Deterministic Policy)",
            BenchmarkStrategyType.SEMANTIC_ONLY: "Semantic Only (Intent Classifier)",
            BenchmarkStrategyType.MARKOV_SPRT: "Markov + SPRT (Statistical Sequential)",
            BenchmarkStrategyType.HYBRID_ALL: "Hybrid (Rules + Semantic + Markov + SPRT)",
        }
        return names.get(self, self.value)


class StrategyVerdict(BaseModel):
    """Evaluation verdict produced by a verification strategy."""

    model_config = ConfigDict(frozen=True)

    strategy: BenchmarkStrategyType
    decision: str = Field(..., description="ALLOW, REVIEW, or BLOCK")
    is_flagged: bool = Field(..., description="True if action is blocked or requires review")
    latency_ms: float = Field(..., description="Wall-clock latency in milliseconds")
    semantic_latency_ms: float = Field(0.0, description="Latency specifically from semantic inference in ms")
    reason: str = Field("", description="Justification explanation")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BaseStrategy(ABC):
    """Abstract base class for benchmark verification strategies."""

    def __init__(self, strategy_type: BenchmarkStrategyType, name: str, description: str):
        self.strategy_type = strategy_type
        self.name = name
        self.description = description

    @abstractmethod
    def evaluate(self, action: Action) -> StrategyVerdict:
        """Evaluates an action and returns a StrategyVerdict."""
        ...

    def reset(self) -> None:
        """Resets any session or statistical tracking state."""
        pass


class RulesOnlyStrategy(BaseStrategy):
    """
    Strategy A: Deterministic Policy Engine Only.
    Evaluates actions against strict structural, path, and command rules.
    """

    def __init__(self, policy_evaluator: Optional[PolicyEvaluator] = None):
        super().__init__(
            strategy_type=BenchmarkStrategyType.RULES_ONLY,
            name="Rules Only",
            description="Fast deterministic rule-based evaluation without semantic or behavioral inference",
        )
        if policy_evaluator is not None:
            self.evaluator = policy_evaluator
        else:
            default_path = Path("examples/policies/default.yaml")
            if default_path.exists():
                self.evaluator = PolicyEvaluator(policy_set=load_policy_from_yaml(default_path))
            else:
                self.evaluator = PolicyEvaluator()

    def evaluate(self, action: Action) -> StrategyVerdict:
        start = time.perf_counter()
        canonical_event = action.to_canonical_event()
        eval_result = self.evaluator.evaluate(canonical_event)
        latency_ms = (time.perf_counter() - start) * 1000.0

        decision_str = (
            eval_result.decision.value if hasattr(eval_result.decision, "value") else str(eval_result.decision)
        )
        is_flagged = decision_str in ("BLOCK", "REVIEW")

        return StrategyVerdict(
            strategy=self.strategy_type,
            decision=decision_str,
            is_flagged=is_flagged,
            latency_ms=round(latency_ms, 3),
            semantic_latency_ms=0.0,
            reason=eval_result.reason or "Deterministic policy evaluation",
            metadata={"policy_id": eval_result.policy_id},
        )


class SemanticOnlyStrategy(BaseStrategy):
    """
    Strategy B: Semantic Engine Only.
    Evaluates actions using intent classification and risk scoring.
    """

    def __init__(self, semantic_engine: Optional[DecisionEngine] = None):
        super().__init__(
            strategy_type=BenchmarkStrategyType.SEMANTIC_ONLY,
            name="Semantic Engine Only",
            description="Semantic intent classification and risk evaluation without hard rules or behavioral models",
        )
        self.engine = semantic_engine or HeuristicSemanticEngine()

    def evaluate(self, action: Action) -> StrategyVerdict:
        start = time.perf_counter()
        signal = self.engine.evaluate(action)
        total_latency_ms = (time.perf_counter() - start) * 1000.0

        sig_str = (
            signal.decision_signal.value if hasattr(signal.decision_signal, "value") else str(signal.decision_signal)
        )
        decision_map = {
            "BLOCK": "BLOCK",
            "REVIEW": "REVIEW",
            "ALLOW": "ALLOW",
            "NEUTRAL": "ALLOW",
        }
        decision = decision_map.get(sig_str, "ALLOW")
        is_flagged = decision in ("BLOCK", "REVIEW")

        return StrategyVerdict(
            strategy=self.strategy_type,
            decision=decision,
            is_flagged=is_flagged,
            latency_ms=round(total_latency_ms, 3),
            semantic_latency_ms=round(signal.latency_ms or total_latency_ms, 3),
            reason=signal.explanation or "Semantic intent classification",
            metadata={
                "category": signal.action_category,
                "risk_level": signal.risk_level.value
                if hasattr(signal.risk_level, "value")
                else str(signal.risk_level),
                "confidence": signal.confidence,
            },
        )


class MarkovSPRTStrategy(BaseStrategy):
    """
    Strategy C: Markov + Sequential SPRT Only.
    Evaluates actions using statistical state transition likelihoods and Wald hypothesis boundaries.
    """

    def __init__(
        self,
        markov_adapter: Optional[MarkovStateAdapter] = None,
        sprt_engine: Optional[SPRTEngine] = None,
    ):
        super().__init__(
            strategy_type=BenchmarkStrategyType.MARKOV_SPRT,
            name="Markov + SPRT Only",
            description="Statistical sequential verification tracking trajectory drift against baseline behavior",
        )
        self.adapter = markov_adapter or MarkovStateAdapter()
        self.sprt = sprt_engine or SPRTEngine(
            markov_model=self.adapter.model,
            hypothesis=Hypothesis(alpha=0.05, beta=0.05, vocabulary_size=10),
        )
        self._session_prev_tokens: Dict[str, str] = {}

    def reset(self) -> None:
        self._session_prev_tokens.clear()
        if hasattr(self.sprt, "reset_session"):
            for sid in list(getattr(self.sprt, "_session_llr", {}).keys()):
                self.sprt.reset_session(sid)

    def evaluate(self, action: Action) -> StrategyVerdict:
        start = time.perf_counter()
        canonical_event = action.to_canonical_event()
        session_id = action.session_id or "default-bench-sess"

        # 1. State extraction
        sec_state = self.adapter.event_to_state(canonical_event)
        curr_token = self.adapter.state_to_token(sec_state)
        prev_token = self._session_prev_tokens.get(session_id)
        self._session_prev_tokens[session_id] = curr_token

        # 2. Transition Probability
        if prev_token is not None:
            p_normal = self.adapter.model.transition_probability(prev_token, curr_token)
        else:
            p_normal = 1.0  # Initial state in session

        # 3. Anomaly check: Unseen transitions (p=0) or low likelihood transitions
        is_anomaly = False
        reason = "Normal behavioral transition trajectory"
        decision = "ALLOW"

        # Check for zero-probability illegal transition
        if prev_token is not None and p_normal == 0.0:
            is_anomaly = True
            decision = "BLOCK"
            reason = f"Unseen or prohibited state transition: {prev_token} -> {curr_token} (P=0.0)"
        else:
            # SPRT cumulative likelihood update
            try:
                sprt_res = self.sprt.observe_sprt(sec_state)
                if sprt_res.status == "ACCEPT_H1":
                    is_anomaly = True
                    decision = "BLOCK"
                    reason = f"SPRT cumulative log-likelihood ratio {sprt_res.log_likelihood_ratio:.3f} breached upper threshold {sprt_res.upper_threshold:.3f}"
            except Exception:
                pass

        latency_ms = (time.perf_counter() - start) * 1000.0

        return StrategyVerdict(
            strategy=self.strategy_type,
            decision=decision,
            is_flagged=is_anomaly,
            latency_ms=round(latency_ms, 3),
            semantic_latency_ms=0.0,
            reason=reason,
            metadata={"prev_token": prev_token, "curr_token": curr_token, "p_normal": p_normal},
        )


class HybridAllStrategy(BaseStrategy):
    """
    Strategy D: Unified Hybrid Verification Engine.
    Synthesizes Rules + Semantic + Markov + SPRT into a cohesive security verdict.
    """

    def __init__(self, engine: Optional[VerificationEngine] = None):
        super().__init__(
            strategy_type=BenchmarkStrategyType.HYBRID_ALL,
            name="Hybrid (Rules + Semantic + Markov + SPRT)",
            description="Defense-in-depth verification combining deterministic policies, semantic classification, and behavioral SPRT",
        )
        if engine is not None:
            self.engine = engine
        else:
            default_path = Path("examples/policies/default.yaml")
            evaluator = (
                PolicyEvaluator(policy_set=load_policy_from_yaml(default_path))
                if default_path.exists()
                else PolicyEvaluator()
            )
            semantic_engine = HeuristicSemanticEngine()
            adapter = MarkovStateAdapter()
            sprt = SPRTEngine(
                markov_model=adapter.model, hypothesis=Hypothesis(alpha=0.05, beta=0.05, vocabulary_size=10)
            )

            self.engine = VerificationEngine(
                config=VerificationEngineConfig(),
                policy_evaluator=evaluator,
                semantic_engine=semantic_engine,
                markov_adapter=adapter,
                sprt_engine=sprt,
            )

    def reset(self) -> None:
        self.engine.reset_session("default-bench-sess")

    def evaluate(self, action: Action) -> StrategyVerdict:
        start = time.perf_counter()
        result = self.engine.verify(action)
        latency_ms = (time.perf_counter() - start) * 1000.0

        is_flagged = result.decision in ("BLOCK", "REVIEW")

        # Extract semantic latency from evidence if present
        sem_lat = 0.0
        for ev in result.evidence:
            if ev.source.value == "semantic_engine" and ev.data:
                sem_lat = ev.data.get("latency_ms", 0.0)

        return StrategyVerdict(
            strategy=self.strategy_type,
            decision=result.decision,
            is_flagged=is_flagged,
            latency_ms=round(latency_ms, 3),
            semantic_latency_ms=round(sem_lat, 3),
            reason=result.reason,
            metadata={"risk_level": result.risk_level, "confidence": result.confidence},
        )
