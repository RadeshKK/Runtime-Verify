import pytest
from runtimeverify.evaluation import (
    BenchmarkRunner, 
    ExperimentConfig, 
    TraceGenerator
)
from runtimeverify.detector.interfaces import BaseDetector
from runtimeverify.detector import DetectorResult, DetectorMetadata

class MockEvaluatorDetector(BaseDetector):
    """A detector that triggers anomaly after a certain number of steps."""
    def __init__(self, trigger_at: int = 5):
        self.trigger_at = trigger_at
        self.count = 0

    @property
    def metadata(self):
        return DetectorMetadata(name="EvalMock", version="1.0")

    def train(self, trace_sequences): pass
    def reset(self): self.count = 0

    def update(self, current_state: str) -> DetectorResult:
        self.count += 1
        decision = "DRIFT" if self.count >= self.trigger_at else "NORMAL"
        return DetectorResult(deviation_score=10.0 if decision == "DRIFT" else 0.0, 
                             decision=decision, evidence={})

def test_evaluation_pipeline():
    """Verify the full flow from generation to metric reporting."""
    # 1. Generate trace
    gen = TraceGenerator()
    alphabet = ["S1", "S2", "S3"]
    normal_trace = gen.generate_normal_trace(alphabet, 20, {"S1": ["S2"], "S2": ["S3"], "S3": ["S1"]})
    
    # Inject anomaly at index 10
    trace, gt = gen.inject_anomaly(normal_trace, 10, ["ANOMALY_S1", "ANOMALY_S2"])
    
    # 2. Setup Benchmark
    config = ExperimentConfig(
        experiment_name="Test_Exp",
        dataset_name="Synthetic_Drift",
        detector_type="Mock",
        expected_anomaly_index=10
    )
    
    # Mock detector triggers at index 12 (delay of 2)
    runner = BenchmarkRunner(lambda: MockEvaluatorDetector(trigger_at=12))
    
    # 3. Run
    report = runner.evaluate_experiment(config, trace, gt, 10)
    
    # 4. Validate Metrics
    assert report.metrics.avg_detection_delay == 2.0
    assert report.metrics.recall > 0
    assert report.config.experiment_name == "Test_Exp"

def test_metrics_calculator_edge_cases():
    """Test the MetricsCalculator with perfect and failed detections."""
    from runtimeverify.evaluation.metrics import MetricsCalculator
    
    # Perfect detection
    gt = [False, False, True, True]
    pred = [False, False, True, True]
    res = MetricsCalculator.calculate(gt, pred, [2], 2, 100.0, 10.0, 4)
    assert res.f1_score == 1.0
    assert res.fpr == 0.0
    
    # Total failure (all False)
    pred_fail = [False, False, False, False]
    res_fail = MetricsCalculator.calculate(gt, pred_fail, [], 2, 100.0, 10.0, 4)
    assert res_fail.recall == 0.0
    assert res_fail.precision == 0.0
