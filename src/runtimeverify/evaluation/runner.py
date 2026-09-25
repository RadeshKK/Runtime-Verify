"""
Security Benchmark Runner for RuntimeVerify (Phase 13).
Executes reproducible comparative benchmarks across the 4 verification strategies
and 9 security scenarios, measuring accuracy, latency, CPU time, and memory usage.
Outputs machine-readable JSON and CSV.
"""

from csv import DictWriter
from datetime import datetime, timezone
import io
import json
import time
import tracemalloc
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from runtimeverify.evaluation.datasets import (
    BenchmarkDataset,
    build_synthetic_dataset,
)
from runtimeverify.evaluation.metrics import (
    BenchmarkStrategyMetrics,
    EvaluationMetrics,
)
from runtimeverify.evaluation.scenarios import BenchmarkScenario
from runtimeverify.evaluation.strategies import (
    BaseStrategy,
    HybridAllStrategy,
    MarkovSPRTStrategy,
    RulesOnlyStrategy,
    SemanticOnlyStrategy,
)


class SecurityBenchmarkReportData(BaseModel):
    """
    Complete structured benchmark results container.
    """

    dataset_id: str
    dataset_name: str
    is_synthetic: bool = Field(..., description="True if synthetic benchmark, False if real-world traces")
    scenarios: List[str]
    strategies: Dict[str, BenchmarkStrategyMetrics]
    total_evaluations: int
    duration_seconds: float
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_json(self, indent: int = 2) -> str:
        """Serializes benchmark results to machine-readable JSON."""
        return json.dumps(self.model_dump(mode="json"), indent=indent)

    def to_csv(self) -> str:
        """Serializes high-level strategy comparison to machine-readable CSV."""
        output = io.StringIO()
        fieldnames = [
            "strategy_name",
            "is_synthetic",
            "total_cases",
            "accuracy",
            "precision",
            "recall",
            "f1_score",
            "false_allow_rate",
            "false_block_rate",
            "mean_latency_ms",
            "p50_latency_ms",
            "p95_latency_ms",
            "p99_latency_ms",
            "semantic_latency_ms",
            "cpu_overhead_ms",
            "memory_overhead_kb",
            "events_before_detection",
        ]

        writer = DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for strat_name, metrics in self.strategies.items():
            row = {
                "strategy_name": strat_name,
                "is_synthetic": self.is_synthetic,
                "total_cases": metrics.total_cases,
                "accuracy": metrics.accuracy,
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1_score": metrics.f1_score,
                "false_allow_rate": metrics.false_allow_rate,
                "false_block_rate": metrics.false_block_rate,
                "mean_latency_ms": metrics.mean_latency_ms,
                "p50_latency_ms": metrics.p50_latency_ms,
                "p95_latency_ms": metrics.p95_latency_ms,
                "p99_latency_ms": metrics.p99_latency_ms,
                "semantic_latency_ms": metrics.semantic_latency_ms,
                "cpu_overhead_ms": metrics.cpu_overhead_ms,
                "memory_overhead_kb": metrics.memory_overhead_kb,
                "events_before_detection": metrics.events_before_detection,
            }
            writer.writerow(row)

        return output.getvalue()


class SecurityBenchmarkRunner:
    """
    Orchestrates execution of the 4 verification strategies across benchmark datasets.
    Measures genuine wall-clock time, CPU time, and memory overhead without fabricating results.
    """

    def __init__(
        self,
        dataset: Optional[BenchmarkDataset] = None,
        strategies: Optional[List[BaseStrategy]] = None,
        scenario_filter: Optional[List[BenchmarkScenario]] = None,
    ):
        self.dataset = dataset or build_synthetic_dataset(seed=42)
        self.strategies = strategies or [
            RulesOnlyStrategy(),
            SemanticOnlyStrategy(),
            MarkovSPRTStrategy(),
            HybridAllStrategy(),
        ]
        self.scenario_filter = scenario_filter

    def run(self, dataset: Optional[BenchmarkDataset] = None) -> SecurityBenchmarkReportData:
        """
        Executes the benchmark suite and aggregates performance metrics.
        """
        overall_start = time.perf_counter()
        target_dataset = dataset or self.dataset

        # Filter cases if scenario_filter specified
        cases_to_run = target_dataset.cases
        if self.scenario_filter:
            cases_to_run = [c for c in cases_to_run if c.scenario in self.scenario_filter]

        strategy_metrics_map: Dict[str, BenchmarkStrategyMetrics] = {}
        total_evals = 0

        scenarios_present = sorted(list({c.scenario.value for c in cases_to_run}))

        for strategy in self.strategies:
            strategy.reset()

            case_results: List[Dict[str, Any]] = []
            latencies_ms: List[float] = []
            semantic_latencies_ms: List[float] = []
            cpu_times_ms: List[float] = []
            delays: List[int] = []

            # Measure memory using tracemalloc
            tracemalloc.start()
            tracemalloc.reset_peak()

            for case in cases_to_run:
                case_flagged = False
                first_flag_step = -1

                # Execute action sequence in case
                for step_idx, action in enumerate(case.actions):
                    total_evals += 1
                    t_cpu_0 = time.process_time()
                    t_wall_0 = time.perf_counter()

                    verdict = strategy.evaluate(action)

                    wall_ms = (time.perf_counter() - t_wall_0) * 1000.0
                    cpu_ms = (time.process_time() - t_cpu_0) * 1000.0

                    latencies_ms.append(wall_ms)
                    cpu_times_ms.append(cpu_ms)
                    if verdict.semantic_latency_ms > 0:
                        semantic_latencies_ms.append(verdict.semantic_latency_ms)

                    if verdict.is_flagged:
                        case_flagged = True
                        if first_flag_step == -1:
                            first_flag_step = step_idx + 1

                # If case is an attack and triggered, record detection delay
                if case.is_attack and case_flagged and first_flag_step != -1:
                    delays.append(first_flag_step)

                case_results.append(
                    {
                        "case_id": case.case_id,
                        "scenario": case.scenario.value,
                        "is_attack": case.is_attack,
                        "is_flagged": case_flagged,
                    }
                )

            current_mem, peak_mem = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            peak_memory_kb = peak_mem / 1024.0

            metrics = EvaluationMetrics.compute_strategy_metrics(
                strategy_name=strategy.name,
                case_results=case_results,
                latencies_ms=latencies_ms,
                semantic_latencies_ms=semantic_latencies_ms,
                cpu_times_ms=cpu_times_ms,
                peak_memory_kb=peak_memory_kb,
                delays=delays,
            )

            strategy_metrics_map[strategy.strategy_type.value] = metrics

        duration = time.perf_counter() - overall_start

        return SecurityBenchmarkReportData(
            dataset_id=target_dataset.dataset_id,
            dataset_name=target_dataset.name,
            is_synthetic=target_dataset.is_synthetic,
            scenarios=scenarios_present,
            strategies=strategy_metrics_map,
            total_evaluations=total_evals,
            duration_seconds=round(duration, 3),
        )
