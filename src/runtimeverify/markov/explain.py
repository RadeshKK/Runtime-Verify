from typing import Dict, Any, List
from pydantic import BaseModel, Field
from runtimeverify.markov.matrix import TransitionCounter, ProbabilityMatrix


class TransitionExplanation(BaseModel):
    """Structured explanation details detailing why a transition probability was returned."""

    prev_state: str = Field(..., description="The source state")
    curr_state: str = Field(..., description="The target state")
    probability: float = Field(..., description="Calculated transition probability")
    observed_transition_count: int = Field(
        ..., description="Number of times this specific transition was seen during training"
    )
    total_outgoing_count: int = Field(..., description="Total count of all transitions starting from the source state")
    expected_transitions: List[Dict[str, Any]] = Field(
        default_factory=list, description="Top expected target states from the source state and their probabilities"
    )


class MarkovExplainer:
    """Computes detailed mathematical explanations of transition probabilities under the model."""

    @staticmethod
    def explain(
        prev_state: str, curr_state: str, counter: TransitionCounter, matrix: ProbabilityMatrix
    ) -> TransitionExplanation:
        prev = prev_state.upper()
        curr = curr_state.upper()

        prob = matrix.get_probability(prev, curr)

        # Get count stats
        observed_count = counter.transition_counts.get(prev, {}).get(curr, 0)
        total_outgoing = counter.state_counts.get(prev, 0)

        # Get expected transitions
        expected: List[Dict[str, Any]] = []
        outgoing_probs = matrix.probabilities.get(prev, {})
        for target, target_prob in outgoing_probs.items():
            if target_prob > 0:
                expected.append(
                    {
                        "state": target,
                        "probability": target_prob,
                        "count": counter.transition_counts.get(prev, {}).get(target, 0),
                    }
                )

        # Sort expected target states by probability descending
        expected.sort(key=lambda x: x["probability"], reverse=True)

        return TransitionExplanation(
            prev_state=prev,
            curr_state=curr,
            probability=prob,
            observed_transition_count=observed_count,
            total_outgoing_count=total_outgoing,
            expected_transitions=expected[:5],  # Top 5 expected target states
        )
