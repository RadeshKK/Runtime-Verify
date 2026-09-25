"""
Null and disabled decision engine implementation.
Acts as a no-op semantic pass-through when semantic evaluation is disabled or unconfigured.
"""

from typing import Any, Optional

from runtimeverify.runtime.context import ExecutionContext
from runtimeverify.semantic.base import DecisionEngine
from runtimeverify.semantic.models import (
    DecisionSignal,
    DecisionSignalType,
    RiskClassification,
    SemanticEngineConfig,
)


class NullDecisionEngine(DecisionEngine):
    """
    Default no-op implementation of DecisionEngine.
    Returns neutral signals with zero latency and does not influence policy or behavioral outcomes.
    """

    def __init__(self, config: Optional[SemanticEngineConfig] = None):
        super().__init__(config=config or SemanticEngineConfig(enabled=False, provider="null"))

    @property
    def name(self) -> str:
        return "null"

    def is_available(self) -> bool:
        return True

    def evaluate(
        self,
        event_or_action: Any,
        context: Optional[ExecutionContext] = None,
    ) -> DecisionSignal:
        return DecisionSignal(
            engine_name="null",
            action_category=None,
            risk_level=RiskClassification.UNKNOWN,
            confidence=1.0,
            decision_signal=DecisionSignalType.NEUTRAL,
            explanation="Semantic decision engine is disabled or set to null pass-through.",
            latency_ms=0.0,
            fallback=False,
        )
