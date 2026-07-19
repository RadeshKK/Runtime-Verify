from pydantic import BaseModel, Field, ConfigDict
from typing import Dict

class TransitionStats(BaseModel):
    """
    Immutable representation of transition counts between two states.
    """
    model_config = ConfigDict(frozen=True)

    source_state: str
    target_state: str
    count: int = Field(ge=0, description="Number of times this transition was observed")

class MarkovModelSnapshot(BaseModel):
    """
    A serializable snapshot of the Markov transition matrix.
    """
    model_config = ConfigDict(frozen=True)

    # Map of source_state -> {target_state: probability}
    transition_matrix: Dict[str, Dict[str, float]]
    # Total observations per state for incremental updates
    state_counts: Dict[str, int]
    alphabet: list[str]
