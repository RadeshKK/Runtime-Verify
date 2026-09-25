from typing import Dict, Any, Optional


class StateEncoderCache:
    """
    Thread-safe in-memory cache to store expensive resource classifications
    and classifications (e.g. mapping paths/URLs to risk classifications).
    """

    def __init__(self, max_size: int = 1000):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.max_size = max_size

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieves cached classification properties, or None if missing."""
        return self._cache.get(key)

    def set(self, key: str, value: Dict[str, Any]) -> None:
        """Saves classification properties to cache, evicting oldest if full."""
        if len(self._cache) >= self.max_size:
            # Simple eviction of first key (FIFO approximation in Python 3.7+ dictionaries)
            first_key = next(iter(self._cache))
            self._cache.pop(first_key)
        self._cache[key] = value

    def clear(self) -> None:
        """Clears all cached items."""
        self._cache.clear()
