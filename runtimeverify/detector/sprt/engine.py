import math
from typing import Protocol, Dict, Optional
from runtimeverify.detector.sprt.models import SPRTConfig, SPRTState
from runtimeverify.detector import DetectorResult

class ProbabilityProvider(Protocol):
    """
    Interface for providing probabilities under H0 and H1.
    """
    def get_probability_h0(self, source: str, target: str) -> float: ...
    def get_probability_h1(self, source: str, target: str) -> float: ...

class SPRTDetector:
    """
    Implements the Sequential Probability Ratio Test (SPRT) for behavior drift.
    
    This engine accumulates the log-likelihood ratio of two competing hypotheses:
    H0: The transition follows the 'normal' behavioral model.
    H1: The transition follows an 'anomalous' model.
    """

    def __init__(self, config: SPRTConfig, prob_provider: ProbabilityProvider):
        self.config = config
        self.prob_provider = prob_provider
        
        # Calculate Wald's thresholds
        # Lower boundary A = ln(beta / (1 - alpha))
        # Upper boundary B = ln((1 - beta) / alpha)
        self.lower_boundary = math.log(self.config.beta / (1 - self.config.alpha))
        self.upper_boundary = math.log((1 - self.config.beta) / self.config.alpha)
        
        self._current_lambda = 0.0
        self._sample_count = 0

    def update(self, source: str, target: str) -> SPRTState:
        """
        Updates the cumulative log-likelihood ratio based on a new transition.
        
        Args:
            source: The source state token.
            target: The target state token.
            
        Returns:
            An SPRTState containing the updated Lambda_t and the current decision.
        """
        p0 = self.prob_provider.get_probability_h0(source, target)
        p1 = self.prob_provider.get_probability_h1(source, target)

        # Handle zero probabilities to ensure numerical stability
        # We use a tiny epsilon or the floor defined in config
        p0 = max(p0, 1e-10) 
        p1 = max(p1, self.config.h1_probability_floor)

        # Lambda_t = Lambda_{t-1} + ln(P(transition|H1) / P(transition|H0))
        log_likelihood_ratio = math.log(p1 / p0)
        self._current_lambda += log_likelihood_ratio
        self._sample_count += 1

        decision = "CONTINUE"
        if self._current_lambda >= self.upper_boundary:
            decision = "REJECT_H0" # Drift detected
        elif self._current_lambda <= self.lower_boundary:
            decision = "ACCEPT_H0" # Confirmed normal
            # Typically, upon accepting H0, the accumulator is reset to 0
            self.reset()

        return SPRTState(
            cumulative_log_likelihood=self._current_lambda,
            sample_count=self._sample_count,
            decision=decision
        )

    def reset(self) -> None:
        """Resets the accumulator and sample counter."""
        self._current_lambda = 0.0
        self._sample_count = 0

    def get_current_state(self) -> SPRTState:
        """Returns the current status of the SPRT process."""
        decision = "CONTINUE"
        if self._current_lambda >= self.upper_boundary:
            decision = "REJECT_H0"
        elif self._current_lambda <= self.lower_boundary:
            decision = "ACCEPT_H0"
            
        return SPRTState(
            cumulative_log_likelihood=self._current_lambda,
            sample_count=self._sample_count,
            decision=decision
        )

    def explain(self) -> str:
        """Returns a human-readable explanation of the current statistical state."""
        return (
            f"SPRT Analysis: Lambda={self._current_lambda:.4f}, "
            f"Boundaries=[{self.lower_boundary:.4f}, {self.upper_boundary:.4f}], "
            f"Samples={self._sample_count}"
        )
