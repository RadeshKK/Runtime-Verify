from typing import Optional
from runtimeverify.runtime.engine import RuntimeEngine

class RuntimeManager:
    """
    Central manager exposing global configuration access to the active RuntimeEngine.
    """
    def __init__(self, engine: Optional[RuntimeEngine] = None):
        self.engine = engine


_GLOBAL_ENGINE: Optional[RuntimeEngine] = None

def get_global_engine() -> RuntimeEngine:
    """Retrieves the global RuntimeEngine instance."""
    global _GLOBAL_ENGINE
    if _GLOBAL_ENGINE is None:
        raise ValueError("Global RuntimeEngine has not been set.")
    return _GLOBAL_ENGINE

def set_global_engine(engine: RuntimeEngine) -> None:
    """Overrides the global RuntimeEngine reference."""
    global _GLOBAL_ENGINE
    _GLOBAL_ENGINE = engine
