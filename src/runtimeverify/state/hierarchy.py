from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict

class StateHierarchy(BaseModel):
    """
    Represents a hierarchical state path (e.g. ['FILE', 'READ', 'SOURCE_CODE', 'PYTHON', 'LOCAL']).
    Allows detectors to aggregate behavior at various resolution levels.
    """
    model_config = ConfigDict(frozen=True)
    
    path: List[str] = Field(..., description="Ordered list of hierarchy tokens from root to leaf")

    @property
    def dot_path(self) -> str:
        """Returns the dot-separated string representation of the state path in uppercase."""
        return ".".join(self.path).upper()

    def parent(self) -> Optional["StateHierarchy"]:
        """Returns the parent state hierarchy or None if already at the root."""
        if len(self.path) <= 1:
            return None
        return StateHierarchy(path=self.path[:-1])

    def is_descendant_of(self, other: "StateHierarchy") -> bool:
        """
        Returns True if this state path is a sub-state of the other state path.
        
        Example:
            FILE.READ.SOURCE.PYTHON is descendant of FILE.READ
        """
        if len(self.path) <= len(other.path):
            return False
        return self.path[:len(other.path)] == other.path

    def level(self, depth: int) -> "StateHierarchy":
        """
        Returns a new StateHierarchy truncated to the specified depth.
        If depth is larger than the current hierarchy length, returns self.
        """
        if depth <= 0 or depth > len(self.path):
            return self
        return StateHierarchy(path=self.path[:depth])
