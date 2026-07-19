from typing import List, Dict, Any, Callable
from runtimeverify.evaluation.models import ExperimentConfig, EvaluationReport, MetricResult
from runtimeverify.evaluation.replay import ReplayEngine
from runtimeverify.evaluation.metrics import MetricsCalculator
from runtimeverify.detector.interfaces import BaseDetector

class BenchmarkRunner:
    """
    Orchestrates the evaluation of one or more detectors against a dataset.
    """
    def __init__(self, detector_factory: Callable[[], BaseDetector]):
        self.detector_factory = detector_factory

    def evaluate_experiment(
        self, 
        config: ExperimentConfig, 
        dataset: List[str], 
        ground_truth: List[bool], 
        anomaly_start_index: int
    ) -> EvaluationReport:
        """
        Runs a full evaluation experiment.
        """
        # Instantiate detector
        detector = self.detector_factory()
        
        # Replay trace
        replay = ReplayEngine(detector)
        predictions, detection_indices, runtime, memory = replay.run(dataset)
        
        # Calculate metrics
        metrics = MetricsCalculator.calculate(
            ground_truth=ground_truth,
            predictions=predictions,
            detection_indices=detection_indices,
            anomaly_start_index=anomaly_start_index,
            runtime_ms=runtime,
            memory_mb=memory,
            total_events=len(dataset)
        )
        
        return EvaluationReport(
            config=config,
            metrics=metrics,
            detector_metadata=getattr(detector.metadata, 'model_dump', lambda: {"name": "unknown"})() 
                               if hasattr(detector, 'metadata') else {}
        )
