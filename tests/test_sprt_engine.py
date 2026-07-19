import pytest
import math
from runtimeverify.detector.sprt import SPRTDetector, SPRTConfig

class MockProbProvider:
    """Provider for testing SPRT logic with controlled probabilities."""
    def __init__(self, h0_val: float, h1_val: float):
        self.h0_val = h0_val
        self.h1_val = h1_val

    def get_probability_h0(self, source: str, target: str) -> float:
        return self.h0_val

    def get_probability_h1(self, source: str, target: str) -> float:
        return self.h1_val

def test_threshold_calculation():
    """Verify that thresholds are calculated correctly based on alpha and beta."""
    config = SPRTConfig(alpha=0.01, beta=0.01)
    # Mock provider just to instantiate
    provider = MockProbProvider(0.5, 0.1)
    detector = SPRTDetector(config, provider)
    
    # A = ln(0.01 / 0.99) approx -4.595
    # B = ln(0.99 / 0.01) approx 4.595
    assert detector.lower_boundary == pytest.approx(math.log(0.01 / 0.99))
    assert detector.upper_boundary == pytest.approx(math.log(0.99 / 0.01))

def test_drift_detection_flow():
    """Verify that a sequence of high-likelihood H1 transitions triggers REJECT_H0."""
    config = SPRTConfig(alpha=0.05, beta=0.05)
    # H1 is much more likely than H0 for the observed transitions
    provider = MockProbProvider(h0_val=0.1, h1_val=0.9)
    detector = SPRTDetector(config, provider)
    
    # Process transitions until drift is detected
    decision = "CONTINUE"
    for _ in range(10):
        state = detector.update("S1", "S2")
        decision = state.decision
        if decision == "REJECT_H0":
            break
            
    assert decision == "REJECT_H0"
    assert detector.get_current_state().cumulative_log_likelihood > detector.upper_boundary

def test_normal_behavior_acceptance():
    """Verify that a sequence of high-likelihood H0 transitions triggers ACCEPT_H0."""
    config = SPRTConfig(alpha=0.05, beta=0.05)
    # H0 is much more likely than H1
    provider = MockProbProvider(h0_val=0.9, h1_val=0.1)
    detector = SPRTDetector(config, provider)
    
    decision = "CONTINUE"
    for _ in range(10):
        state = detector.update("S1", "S2")
        decision = state.decision
        if decision == "ACCEPT_H0":
            break
            
    assert decision == "ACCEPT_H0"
    # After ACCEPT_H0, the detector should reset
    assert detector.get_current_state().cumulative_log_likelihood == 0.0

def test_numerical_stability_zero_prob():
    """Verify that the detector does not crash on zero probabilities."""
    config = SPRTConfig(alpha=0.01, beta=0.01)
    # Extreme case: H0 probability is 0
    provider = MockProbProvider(h0_val=0.0, h1_val=0.1)
    detector = SPRTDetector(config, provider)
    
    # Should not raise ZeroDivisionError or ValueError (math domain error)
    state = detector.update("S1", "S2")
    assert state.cumulative_log_likelihood > 0
    assert state.decision == "REJECT_H0"

def test_sprt_serialization_via_models():
    """Verify that SPRTState can be converted to JSON and back."""
    from runtimeverify.detector.sprt.models import SPRTState
    
    state = SPRTState(cumulative_log_likelihood=2.5, sample_count=5, decision="CONTINUE")
    json_data = state.model_dump_json()
    
    restored = SPRTState.model_validate_json(json_data)
    assert restored.cumulative_log_likelihood == 2.5
    assert restored.decision == "CONTINUE"
