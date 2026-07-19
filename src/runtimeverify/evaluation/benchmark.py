from typing import List, Dict, Any
from runtimeverify.events.base import Event
from runtimeverify.runtime.engine import RuntimeEngine
from runtimeverify.evaluation.replay import SessionReplayer
from runtimeverify.evaluation.metrics import EvaluationMetrics

class BenchmarkRunner:
    """
    Orchestrator runner that executes benchmarks over multiple configured RuntimeEngines,
    accumulating confusion matrices, accuracy outputs, and execution speed.
    """
    
    def __init__(self, normal_traces: List[List[Event]], anomalous_traces: List[List[Event]]):
        self.normal_traces = normal_traces
        self.anomalous_traces = anomalous_traces

    def evaluate_engine(self, engine: RuntimeEngine, detector_name: str) -> Dict[str, Any]:
        """
        Runs the benchmark corpus (normal and anomalous) through the engine
        and returns metrics, delays, and latencies.
        """
        replayer = SessionReplayer(engine)
        
        ground_truths: List[bool] = []
        predictions: List[bool] = []
        delays: List[int] = []
        all_step_latencies: List[float] = []

        # 1. Process Normal Traces (ground_truth = False)
        for trace in self.normal_traces:
            res = replayer.replay(trace)
            ground_truths.append(False)
            predictions.append(res["anomaly_triggered"])
            all_step_latencies.extend(res["step_latencies_ms"])

        # 2. Process Anomalous Traces (ground_truth = True)
        for trace in self.anomalous_traces:
            res = replayer.replay(trace)
            ground_truths.append(True)
            predictions.append(res["anomaly_triggered"])
            all_step_latencies.extend(res["step_latencies_ms"])
            
            if res["anomaly_triggered"] and res["detection_delay_steps"] != -1:
                delays.append(res["detection_delay_steps"])

        # 3. Calculate metrics
        metrics = EvaluationMetrics.calculate_classification_metrics(ground_truths, predictions)
        avg_delay = EvaluationMetrics.calculate_average_delay(delays)
        avg_latency = sum(all_step_latencies) / len(all_step_latencies) if all_step_latencies else 0.0

        return {
            "name": detector_name,
            "metrics": metrics,
            "average_delay": avg_delay,
            "avg_latency": avg_latency,
            "all_step_latencies": all_step_latencies
        }
