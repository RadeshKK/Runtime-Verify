"""
Abstract base class definition for semantic decision engines in RuntimeVerify.
Enables pluggable, vendor-neutral semantic classification and risk signaling.
"""

from abc import ABC, abstractmethod
import json
from typing import Any, Optional

from runtimeverify.runtime.context import ExecutionContext
from runtimeverify.semantic.models import DecisionSignal, SemanticEngineConfig


class DecisionEngine(ABC):
    """
    Abstract interface for semantic decision engines.
    Provides structured semantic signals (action category, risk classification,
    calibrated confidence, decision signal) without direct coupling to specific model runtimes.
    """

    def __init__(self, config: Optional[SemanticEngineConfig] = None):
        self.config = config or SemanticEngineConfig()

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the unique name identifier of this decision engine."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Returns True if the engine dependencies and checkpoints are ready for inference."""
        ...

    @abstractmethod
    def evaluate(
        self,
        event_or_action: Any,
        context: Optional[ExecutionContext] = None,
    ) -> DecisionSignal:
        """
        Evaluates an intercepted action or canonical event and returns a structured DecisionSignal.
        Must never raise unhandled exceptions; failures must be captured in fallback signals.
        """
        ...

    def extract_text_representation(
        self,
        event_or_action: Any,
        context: Optional[ExecutionContext] = None,
    ) -> str:
        """
        Helper to convert heterogeneous actions, events, or dictionaries into a clean,
        structured text representation suitable for semantic evaluation models.
        """
        parts = []

        # Check for Action object
        if hasattr(event_or_action, "action_type") and hasattr(event_or_action, "target"):
            action_type_val = (
                event_or_action.action_type.value
                if hasattr(event_or_action.action_type, "value")
                else str(event_or_action.action_type)
            )
            parts.append(f"Action Type: {action_type_val}")
            parts.append(f"Target: {event_or_action.target}")
            if getattr(event_or_action, "params", None):
                parts.append(f"Parameters: {json.dumps(event_or_action.params, default=str)}")
            if getattr(event_or_action, "agent_id", None):
                parts.append(f"Agent: {event_or_action.agent_id}")

        # Check for CanonicalEvent object
        elif hasattr(event_or_action, "event_type") and hasattr(event_or_action, "action"):
            event_type_val = (
                event_or_action.event_type.value
                if hasattr(event_or_action.event_type, "value")
                else str(event_or_action.event_type)
            )
            parts.append(f"Event Type: {event_type_val}")
            parts.append(f"Action: {event_or_action.action}")
            if getattr(event_or_action, "target", None):
                parts.append(f"Target: {event_or_action.target}")
            if getattr(event_or_action, "context", None):
                parts.append(f"Context: {json.dumps(event_or_action.context, default=str)}")

        # Dict input
        elif isinstance(event_or_action, dict):
            for k in ("action_type", "type", "event_type", "action", "target", "command", "path", "url"):
                if k in event_or_action and event_or_action[k]:
                    parts.append(f"{k.replace('_', ' ').title()}: {event_or_action[k]}")

        # Fallback string representation
        else:
            parts.append(f"Payload: {str(event_or_action)}")

        if context is not None:
            if getattr(context, "environment", None):
                parts.append(f"Environment: {context.environment}")
            if getattr(context, "agent_type", None):
                parts.append(f"Agent Type: {context.agent_type}")

        return "\n".join(parts)
