"""
Laya semantic decision engine adapter for RuntimeVerify.
Integrates with Laya (System 1 non-autoregressive decision engine) via its public Router API.
Provides typed action categorization, risk classification, calibrated confidence,
and timeout-guarded evaluation.
"""

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
import logging
import time
from typing import Any, Dict, Optional

from runtimeverify.runtime.context import ExecutionContext
from runtimeverify.semantic.base import DecisionEngine
from runtimeverify.semantic.models import (
    DecisionSignal,
    DecisionSignalType,
    RiskClassification,
    SemanticEngineConfig,
)

logger = logging.getLogger(__name__)

# Check for Laya availability without making it a hard runtime dependency
try:
    from laya import Router as LayaRouter

    _LAYA_AVAILABLE = True
except ImportError:
    _LAYA_AVAILABLE = False
    LayaRouter = None  # type: ignore


# Default typed question set for Laya System 1 evaluation
DEFAULT_LAYA_QUESTIONS: Dict[str, Any] = {
    "action_category": {
        "type": "choice",
        "instructions": "Which technical category best describes this agent action?",
        "criteria": {
            "filesystem": "reading, writing, or deleting files or directories",
            "shell": "executing terminal, bash, or powershell commands",
            "network": "making http requests, opening sockets, or fetching external resources",
            "credential": "accessing api keys, credentials, ssh keys, or passwords",
            "git": "git commits, pushes, branches, or repository modifications",
            "process": "spawning, killing, or managing operating system processes",
            "benign_query": "reading non-sensitive documentation or standard compute",
            "destructive": "permanently deleting files, dropping tables, or system shutdown",
        },
    },
    "risk_level": {
        "type": "choice",
        "instructions": "What is the security risk level of this agent action?",
        "criteria": {
            "critical": "destructive system commands, credential theft, or unauthorized privilege escalation",
            "high": "arbitrary code execution, modifying sensitive configuration, or external data exfiltration",
            "medium": "standard file modifications, installing dependencies, or external web requests",
            "low": "read-only access, harmless queries, or local test execution",
        },
    },
    "requires_review": {
        "type": "noul",
        "instructions": "Does this action require human confirmation or pose dangerous operational risk?",
    },
}


class LayaDecisionEngine(DecisionEngine):
    """
    Adapter integrating Laya's non-autoregressive System 1 decision engine.
    Uses Laya's public Router.predict API over typed questions.
    """

    def __init__(
        self,
        config: Optional[SemanticEngineConfig] = None,
        router: Optional[Any] = None,
    ):
        super().__init__(config=config or SemanticEngineConfig(enabled=True, provider="laya"))
        self._custom_router = router
        self._router_instance: Optional[Any] = None
        self._thread_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="LayaEngine")

    @property
    def name(self) -> str:
        return "laya"

    def is_available(self) -> bool:
        """Returns True if a router was supplied or the laya package is installed."""
        return self._custom_router is not None or _LAYA_AVAILABLE

    def _get_router(self) -> Any:
        """Lazily obtains or instantiates the Laya Router."""
        if self._custom_router is not None:
            return self._custom_router
        if self._router_instance is None:
            if not _LAYA_AVAILABLE:
                raise ImportError(
                    "The 'laya' package is not installed. Install via 'pip install laya' "
                    "or supply a pre-configured router instance."
                )
            self._router_instance = LayaRouter(
                preload=self.config.preload,
                device=self.config.device,
            )
        return self._router_instance

    def evaluate(
        self,
        event_or_action: Any,
        context: Optional[ExecutionContext] = None,
    ) -> DecisionSignal:
        """
        Evaluates the action or event using Laya with strict timeout protection and error handling.
        """
        start_time = time.perf_counter()
        state_text = self.extract_text_representation(event_or_action, context)
        timeout_sec = self.config.timeout_ms / 1000.0

        if not self.is_available():
            latency = (time.perf_counter() - start_time) * 1000.0
            logger.warning("LayaDecisionEngine invoked but 'laya' package is not available.")
            return DecisionSignal(
                engine_name=self.name,
                decision_signal=DecisionSignalType.NEUTRAL,
                risk_level=RiskClassification.UNKNOWN,
                confidence=0.0,
                explanation="Laya engine is unavailable (package not installed).",
                latency_ms=latency,
                fallback=True,
                error="laya package not installed",
            )

        # Execute router prediction in worker thread guarded by timeout
        try:
            future = self._thread_pool.submit(self._predict, state_text)
            raw_result = future.result(timeout=timeout_sec)
            latency = (time.perf_counter() - start_time) * 1000.0
            return self._parse_laya_result(raw_result, latency)

        except FutureTimeoutError:
            latency = (time.perf_counter() - start_time) * 1000.0
            logger.warning(
                "Laya decision engine timed out after %.1fms (threshold: %.1fms)",
                latency,
                self.config.timeout_ms,
            )
            return DecisionSignal(
                engine_name=self.name,
                decision_signal=DecisionSignalType.NEUTRAL,
                risk_level=RiskClassification.UNKNOWN,
                confidence=0.0,
                explanation=f"Laya inference timed out after {self.config.timeout_ms}ms.",
                latency_ms=latency,
                fallback=True,
                error=f"Timeout of {self.config.timeout_ms}ms exceeded",
            )
        except Exception as e:
            latency = (time.perf_counter() - start_time) * 1000.0
            logger.error("Laya decision engine error during evaluation: %s", e, exc_info=True)
            return DecisionSignal(
                engine_name=self.name,
                decision_signal=DecisionSignalType.NEUTRAL,
                risk_level=RiskClassification.UNKNOWN,
                confidence=0.0,
                explanation=f"Laya evaluation failed: {e}",
                latency_ms=latency,
                fallback=True,
                error=str(e),
            )

    def _predict(self, state_text: str) -> Dict[str, Any]:
        """Invokes Laya's public Router.predict API."""
        router = self._get_router()
        predict_kwargs: Dict[str, Any] = {}
        if self.config.model_name:
            predict_kwargs["model"] = self.config.model_name
        return router.predict(state_text, DEFAULT_LAYA_QUESTIONS, **predict_kwargs)

    def _parse_laya_result(self, raw_result: Dict[str, Any], latency_ms: float) -> DecisionSignal:
        """Parses Laya's standard dictionary output into a typed DecisionSignal."""
        answers = raw_result.get("answers", {})
        routing = raw_result.get("routing", {})

        # 1. Action Category
        category_data = answers.get("action_category", {})
        action_category = category_data.get("choice")

        # 2. Risk Classification
        risk_data = answers.get("risk_level", {})
        risk_choice = str(risk_data.get("choice", "low")).upper()
        risk_level_map = {
            "CRITICAL": RiskClassification.CRITICAL,
            "HIGH": RiskClassification.HIGH,
            "MEDIUM": RiskClassification.MEDIUM,
            "LOW": RiskClassification.LOW,
        }
        risk_level = risk_level_map.get(risk_choice, RiskClassification.UNKNOWN)

        # 3. Confidence Normalization
        raw_confidence = float(risk_data.get("confidence", 0.0))
        normalized_confidence = max(0.0, min(1.0, raw_confidence))

        # 4. Review Probability (noul question)
        review_data = answers.get("requires_review", {})
        noul_prob = float(review_data.get("noul", 0.0))

        # 5. Synthesize Decision Signal
        min_conf = self.config.min_confidence_threshold
        if risk_level == RiskClassification.CRITICAL and normalized_confidence >= min_conf:
            decision_signal = DecisionSignalType.BLOCK
            explanation = f"Laya classified action as CRITICAL risk (confidence: {normalized_confidence:.2f})."
        elif risk_level == RiskClassification.HIGH and normalized_confidence >= min_conf:
            decision_signal = DecisionSignalType.REVIEW
            explanation = f"Laya classified action as HIGH risk (confidence: {normalized_confidence:.2f})."
        elif noul_prob >= 0.75:
            decision_signal = DecisionSignalType.REVIEW
            explanation = f"Laya indicated action requires human approval (probability: {noul_prob:.2f})."
        elif risk_level == RiskClassification.MEDIUM and normalized_confidence >= min_conf:
            decision_signal = DecisionSignalType.REVIEW
            explanation = f"Laya classified action as MEDIUM risk (confidence: {normalized_confidence:.2f})."
        else:
            decision_signal = DecisionSignalType.ALLOW
            explanation = f"Laya classified action as {risk_level.value} risk with acceptable profile."

        return DecisionSignal(
            engine_name=self.name,
            action_category=action_category,
            risk_level=risk_level,
            confidence=normalized_confidence,
            decision_signal=decision_signal,
            explanation=explanation,
            raw_scores={
                "answers": answers,
                "noul_review_probability": noul_prob,
            },
            latency_ms=latency_ms,
            fallback=False,
            metadata=routing,
        )
