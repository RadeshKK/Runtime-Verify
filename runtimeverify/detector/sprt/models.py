from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime

class SPRTConfig(BaseModel):
    """
    Configuration for the Sequential Probability Ratio Test.
    
    Attributes:
        alpha: Probability of Type I error (False Positive Rate).
        beta: Probability of Type II error (False Negative Rate).
        h1_probability_floor: Minimum probability assigned to transitions under H1 
                               to prevent infinite log-likelihoods for unseen transitions.
    """
    model_config = ConfigDict(frozen=True)

    alpha: float = Field(default=0.01, gt=0, lt=1, description="False Positive Rate")
    beta: float = Field(default=0.01, gt=0, lt=1, description="False Negative Rate")
    h1_probability_floor: float = Field(default=1e-6, gt=0, description="Floor for H1 probabilities")

class SPRTState(BaseModel):
    """
    Immutable snapshot of the current SPRT accumulator state.
    """
    model_config = ConfigDict(frozen=True)

    cumulative_log_likelihood: float = Field(description="The current value of Lambda_t")
    sample_count: int = Field(default=0, description="Number of transitions processed in current session")
    decision: str = Field(description="CURRENT, ACCEPT_H0, or REJECT_H0")
    timestamp: datetime = Field(default_factory=lambda: datetime.now())
