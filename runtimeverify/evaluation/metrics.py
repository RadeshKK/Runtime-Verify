from typing import List, Tuple
from runtimeverify.evaluation.models import MetricResult

class MetricsCalculator:
    """
    Calculates classification and performance metrics for detector evaluations.
    """
    @staticmethod
    def calculate(
        ground_truth: List[bool], 
        predictions: List[bool], 
        detection_indices: List[int],
        anomaly_start_index: int,
        runtime_ms: float,
        memory_mb: float,
        total_events: int
    ) -> MetricResult:
        """
        Computes the statistical performance of a detector.
        
        Args:
            ground_truth: Boolean list where True indicates an anomalous state.
            predictions: Boolean list where True indicates a detector triggered 'REJECT_H0'.
            detection_indices: List of indices where the detector triggered.
            anomaly_start_index: The index where the actual anomaly began.
            runtime_ms: Total execution time.
            memory_mb: Peak memory usage.
            total_events: Total number of processed transitions.
        """
        tp = sum(1 for g, p in zip(ground_truth, predictions) if g and p)
        fp = sum(1 for g, p in zip(ground_truth, predictions) if not g and p)
        tn = sum(1 for g, p in zip(ground_truth, predictions) if not g and not p)
        fn = sum(1 for g, p in zip(ground_truth, predictions) if g and not p)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        # Detection Delay: How many steps after anomaly start did the first detection occur?
        delay = 0.0
        if detection_indices:
            first_det = detection_indices[0]
            if first_det >= anomaly_start_index:
                delay = float(first_det - anomaly_start_index)
        
        return MetricResult(
            fpr=fpr,
            fnr=fnr,
            precision=precision,
            recall=recall,
            f1_score=f1,
            avg_detection_delay=delay,
            runtime_ms=runtime_ms,
            memory_usage_mb=memory_mb,
            throughput_events_per_sec=total_events / (runtime_ms / 1000.0) if runtime_ms > 0 else 0.0
        )
