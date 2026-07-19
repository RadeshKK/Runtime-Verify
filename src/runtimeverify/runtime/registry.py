from typing import Dict, List
from runtimeverify.runtime.pipeline import RuntimePipeline

class PipelineRegistry:
    """
    Registry for managing multiple RuntimePipeline configurations.
    Allows downstream applications to swap pipeline rules dynamically.
    """
    
    def __init__(self):
        self._pipelines: Dict[str, RuntimePipeline] = {}

    def register(self, name: str, pipeline: RuntimePipeline) -> None:
        """Registers a named RuntimePipeline configuration."""
        self._pipelines[name.lower()] = pipeline

    def get(self, name: str) -> RuntimePipeline:
        """Retrieves a registered pipeline by name, raising KeyError if missing."""
        key = name.lower()
        if key not in self._pipelines:
            raise KeyError(f"Pipeline '{name}' is not registered.")
        return self._pipelines[key]

    def list_pipelines(self) -> List[str]:
        """Returns a list of all registered pipeline names."""
        return list(self._pipelines.keys())

    def clear(self) -> None:
        """Clears all registered pipelines."""
        self._pipelines.clear()
