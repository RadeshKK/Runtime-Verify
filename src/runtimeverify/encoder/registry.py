from typing import Dict, List
from runtimeverify.encoder.base import BaseEncoder

class EncoderRegistry:
    """
    Registry for managing multiple state encoder configurations.
    Allows dynamic registration and loading of modular encoders (e.g. RuleBased, MLBased).
    """
    
    def __init__(self):
        self._encoders: Dict[str, BaseEncoder] = {}

    def register(self, name: str, encoder: BaseEncoder) -> None:
        """Registers a BaseEncoder implementation."""
        self._encoders[name.lower()] = encoder

    def get(self, name: str) -> BaseEncoder:
        """Retrieves a registered encoder, raising KeyError if missing."""
        encoder_key = name.lower()
        if encoder_key not in self._encoders:
            raise KeyError(f"Encoder '{name}' is not registered.")
        return self._encoders[encoder_key]

    def list_encoders(self) -> List[str]:
        """Returns a list of all registered encoder names."""
        return list(self._encoders.keys())

    def clear(self) -> None:
        """Clears all registered encoders."""
        self._encoders.clear()
