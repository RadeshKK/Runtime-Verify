import math
from runtimeverify.sprt.hypothesis import Hypothesis


class WaldThresholds:
    """Computes upper and lower Wald log-likelihood boundaries from a Hypothesis."""

    def __init__(self, hypothesis: Hypothesis):
        self.alpha = hypothesis.alpha
        self.beta = hypothesis.beta
        # Lower boundary A = ln( beta / (1 - alpha) )
        self.lower_boundary = math.log(self.beta / (1.0 - self.alpha))
        # Upper boundary B = ln( (1 - beta) / alpha )
        self.upper_boundary = math.log((1.0 - self.beta) / self.alpha)
