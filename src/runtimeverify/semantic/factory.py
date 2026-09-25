"""
Factory and registry for semantic decision engines in RuntimeVerify.
Allows dynamic instantiation and vendor-neutral swapping of semantic decision providers.
"""

from typing import Any, Callable, Dict, Optional

from runtimeverify.semantic.base import DecisionEngine
from runtimeverify.semantic.laya import LayaDecisionEngine
from runtimeverify.semantic.models import SemanticEngineConfig
from runtimeverify.semantic.null import NullDecisionEngine

_ENGINE_REGISTRY: Dict[str, Callable[[SemanticEngineConfig, Dict[str, Any]], DecisionEngine]] = {}


def register_engine_provider(
    name: str,
    factory: Callable[[SemanticEngineConfig, Dict[str, Any]], DecisionEngine],
) -> None:
    """Registers a custom decision engine provider factory."""
    _ENGINE_REGISTRY[name.lower()] = factory


def get_semantic_engine(
    config: Optional[SemanticEngineConfig] = None,
    **kwargs: Any,
) -> DecisionEngine:
    """
    Instantiates a DecisionEngine based on configuration.
    Defaults to NullDecisionEngine if disabled or unconfigured.
    """
    cfg = config or SemanticEngineConfig()

    if not cfg.enabled or cfg.provider.lower() == "null":
        return NullDecisionEngine(config=cfg)

    provider = cfg.provider.lower()
    if provider == "laya":
        return LayaDecisionEngine(config=cfg, router=kwargs.get("router"))

    if provider == "heuristic":
        from runtimeverify.semantic.heuristic import HeuristicSemanticEngine

        return HeuristicSemanticEngine(config=cfg)

    if provider in _ENGINE_REGISTRY:
        return _ENGINE_REGISTRY[provider](cfg, kwargs)

    raise ValueError(
        f"Unsupported semantic decision engine provider: '{cfg.provider}'. "
        f"Registered providers: {['null', 'laya'] + list(_ENGINE_REGISTRY.keys())}"
    )
