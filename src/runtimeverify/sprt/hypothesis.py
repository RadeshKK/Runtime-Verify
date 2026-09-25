from typing import Optional
from pydantic import BaseModel, Field, ConfigDict
from runtimeverify.sprt.alternative import AlternativeModel
from runtimeverify.state.base import StateInterface


class Hypothesis(BaseModel):
    """
    Defines the statistical bounds of the SPRT test.
    Immutable to protect runtime boundary calculations.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    alpha: float = Field(0.05, gt=0.0, lt=0.5, description="Significance level (False Positive probability limit)")
    beta: float = Field(0.05, gt=0.0, lt=0.5, description="Type II error rate (False Negative probability limit)")
    vocabulary_size: int = Field(..., gt=1, description="Size of state alphabet |Sigma| to calculate Q")
    llr_cap: float = Field(100.0, gt=0.0, description="Maximum absolute increment allowed per transition")
    alternative_model: Optional[AlternativeModel] = Field(
        default=None, description="Pluggable alternative hypothesis model Q"
    )

    def get_q_probability(self, prev: str, curr: StateInterface) -> float:
        """Returns Q(curr | prev). Delegates to alternative_model, falling back to uniform if None."""
        if self.alternative_model is not None:
            return self.alternative_model.get_probability(prev, curr)
        # Fallback to uniform
        return 1.0 / self.vocabulary_size
