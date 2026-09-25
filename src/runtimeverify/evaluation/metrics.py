"""
Evaluation & Benchmark Metrics Calculator (Phase 13).
Computes statistical classification metrics (accuracy, precision, recall, F1,
false allow rate, false block rate), execution timings, CPU/memory overhead,
and per-scenario detection rates.
"""

import statistics
from typing import Any, Dict, List
from pydantic import BaseModel, Field


class BenchmarkStrategyMetrics(BaseModel):
    """
    Comprehensive performance metrics for a single verification strategy.
    """

    strategy_name: str = Field(..., description="Name of the evaluated strategy")
    total_cases: int = Field(0, description="Total number of evaluated cases")
    attacks_count: int = Field(0, description="Total attack cases in test set")
    normal_count: int = Field(0, description="Total benign cases in test set")
    true_positives: int = Field(0, description="Attacks correctly flagged as BLOCK/REVIEW")
    false_positives: int = Field(0, description="Benign actions erroneously flagged as BLOCK/REVIEW")
    true_negatives: int = Field(0, description="Benign actions correctly ALLOWED")
    false_negatives: int = Field(0, description="Attacks missed and erroneously ALLOWED")
    accuracy: float = Field(0.0, description="Overall classification accuracy [0.0, 1.0]")
    precision: float = Field(0.0, description="Precision: TP / (TP + FP)")
    recall: float = Field(0.0, description="Recall (TPR): TP / (TP + FN)")
    f1_score: float = Field(0.0, description="Harmonic mean of precision and recall")
    false_allow_rate: float = Field(0.0, description="False Negative Rate (Miss Rate): FN / (TP + FN)")
    false_block_rate: float = Field(0.0, description="False Positive Rate (False Alarm): FP / (FP + TN)")
    mean_latency_ms: float = Field(0.0, description="Average wall-clock latency per evaluation in ms")
    p50_latency_ms: float = Field(0.0, description="Median latency in ms")
    p95_latency_ms: float = Field(0.0, description="95th percentile latency in ms")
    p99_latency_ms: float = Field(0.0, description="99th percentile latency in ms")
    semantic_latency_ms: float = Field(0.0, description="Latency specifically from semantic inference in ms")
    cpu_overhead_ms: float = Field(0.0, description="Average CPU time (user + system) per evaluation in ms")
    memory_overhead_kb: float = Field(0.0, description="Peak memory delta in KB measured during evaluation")
    events_before_detection: float = Field(
        0.0, description="Average number of events observed before anomaly detection"
    )
    scenario_breakdown: Dict[str, Dict[str, float]] = Field(
        default_factory=dict, description="Per-scenario accuracy, recall, and detection counts"
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class EvaluationMetrics:
    """
    Computes statistical evaluation metrics (accuracy, delay, timings, overhead)
    over a set of trace benchmarks.
    """

    @staticmethod
    def calculate_classification_metrics(
        ground_truths: List[bool],
        predictions: List[bool],
    ) -> Dict[str, float]:
        """
        Calculates precision, recall, f1, FPR, and FNR.

        Args:
            ground_truths: True if trace/action is anomalous/attack, False if normal.
            predictions: True if detector flagged anomaly/BLOCK/REVIEW, False otherwise.
        """
        tp = fp = tn = fn = 0

        for gt, pred in zip(ground_truths, predictions):
            if gt is True and pred is True:
                tp += 1
            elif gt is False and pred is True:
                fp += 1
            elif gt is False and pred is False:
                tn += 1
            elif gt is True and pred is False:
                fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2.0 * (precision * recall) / (precision + recall) if (precision + recall) > 0.0 else 0.0

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0

        accuracy = (tp + tn) / len(ground_truths) if ground_truths else 0.0

        return {
            "true_positives": float(tp),
            "false_positives": float(fp),
            "true_negatives": float(tn),
            "false_negatives": float(fn),
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
        }

    @staticmethod
    def calculate_average_delay(delays: List[int]) -> float:
        """Calculates the average number of observations before detection was triggered."""
        if not delays:
            return 0.0
        return sum(delays) / len(delays)

    @classmethod
    def compute_strategy_metrics(
        cls,
        strategy_name: str,
        case_results: List[Dict[str, Any]],
        latencies_ms: List[float],
        semantic_latencies_ms: List[float],
        cpu_times_ms: List[float],
        peak_memory_kb: float,
        delays: List[int],
    ) -> BenchmarkStrategyMetrics:
        """
        Synthesizes full BenchmarkStrategyMetrics from a completed benchmark run.
        """
        ground_truths = [r["is_attack"] for r in case_results]
        predictions = [bool(r.get("is_flagged", r.get("flagged", False))) for r in case_results]

        cls_metrics = cls.calculate_classification_metrics(ground_truths, predictions)

        # Percentile calculations
        sorted_lats = sorted(latencies_ms) if latencies_ms else [0.0]
        mean_lat = statistics.mean(sorted_lats) if sorted_lats else 0.0
        p50 = statistics.median(sorted_lats) if sorted_lats else 0.0
        p95 = cls._percentile(sorted_lats, 0.95)
        p99 = cls._percentile(sorted_lats, 0.99)

        sem_mean = statistics.mean(semantic_latencies_ms) if semantic_latencies_ms else 0.0
        cpu_mean = statistics.mean(cpu_times_ms) if cpu_times_ms else 0.0
        avg_delay = cls.calculate_average_delay(delays) if delays else 1.0

        # Scenario breakdown
        scenario_groups: Dict[str, List[Dict[str, Any]]] = {}
        for r in case_results:
            scen = r.get("scenario", "unknown")
            scenario_groups.setdefault(scen, []).append(r)

        scenario_breakdown: Dict[str, Dict[str, float]] = {}
        for scen, items in scenario_groups.items():
            scen_gt = [item["is_attack"] for item in items]
            scen_pred = [bool(item.get("is_flagged", item.get("flagged", False))) for item in items]
            m = cls.calculate_classification_metrics(scen_gt, scen_pred)
            scenario_breakdown[scen] = {
                "total": float(len(items)),
                "accuracy": m["accuracy"],
                "recall": m["recall"],
                "precision": m["precision"],
                "f1_score": m["f1_score"],
            }

        return BenchmarkStrategyMetrics(
            strategy_name=strategy_name,
            total_cases=len(case_results),
            attacks_count=sum(1 for gt in ground_truths if gt),
            normal_count=sum(1 for gt in ground_truths if not gt),
            true_positives=int(cls_metrics["true_positives"]),
            false_positives=int(cls_metrics["false_positives"]),
            true_negatives=int(cls_metrics["true_negatives"]),
            false_negatives=int(cls_metrics["false_negatives"]),
            accuracy=round(cls_metrics["accuracy"], 4),
            precision=round(cls_metrics["precision"], 4),
            recall=round(cls_metrics["recall"], 4),
            f1_score=round(cls_metrics["f1_score"], 4),
            false_allow_rate=round(cls_metrics["false_negative_rate"], 4),
            false_block_rate=round(cls_metrics["false_positive_rate"], 4),
            mean_latency_ms=round(mean_lat, 3),
            p50_latency_ms=round(p50, 3),
            p95_latency_ms=round(p95, 3),
            p99_latency_ms=round(p99, 3),
            semantic_latency_ms=round(sem_mean, 3),
            cpu_overhead_ms=round(cpu_mean, 3),
            memory_overhead_kb=round(peak_memory_kb, 2),
            events_before_detection=round(avg_delay, 2),
            scenario_breakdown=scenario_breakdown,
        )

    @staticmethod
    def _percentile(sorted_data: List[float], p: float) -> float:
        if not sorted_data:
            return 0.0
        k = (len(sorted_data) - 1) * p
        f = int(k)
        c = f + 1
        if c < len(sorted_data):
            return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])
        return sorted_data[-1]
