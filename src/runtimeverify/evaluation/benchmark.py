from typing import List, Dict, Any, Union
import random
from runtimeverify.events.base import Event
from runtimeverify.runtime.engine import RuntimeEngine
from runtimeverify.evaluation.replay import SessionReplayer
from runtimeverify.evaluation.metrics import EvaluationMetrics
from runtimeverify.sprt.engine import SPRTEngine
from runtimeverify.state.base import StateInterface
from runtimeverify.state.context import StateContext

class MockState:
    """Simplified StateInterface implementation for synthetic benchmarks."""
    def __init__(self, name: str, session_id: str = "test-session"):
        self._name = name
        self._session_id = session_id
        # Minimal mock properties to satisfy SPRTEngine
        self.context = StateContext(session_id=session_id)
        # Other properties can be added if needed by the detector
        self.category = None
        self.hierarchy = None
        self.metadata = None

    @property
    def name(self) -> str: return self._name
    @property
    def id(self) -> str: return self._name
    @property
    def context(self) -> StateContext: return self._context
    # Need to fix the init and properties for a real MockState

class BenchmarkState:
    """Correctly implements StateInterface for benchmarks."""
    def __init__(self, name: str, session_id: str = "test-session"):
        self._name = name
        self._context = StateContext(session_id=session_id)

    @property
    def name(self) -> str: return self._name
    @property
    def id(self) -> str: return self._name
    @property
    def context(self) -> StateContext: return self._context
    @property
    def category(self) -> Any: return None
    @property
    def hierarchy(self) -> Any: return None
    @property
    def metadata(self) -> Any: return None
    @property
    def dot_path(self) -> str: return self._name

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

class MonteCarloBenchmarkRunner:
    """
    Validates the empirical alpha and beta of an SPRT engine using Monte Carlo simulation.
    """
    def __init__(self, iterations: int = 10000, trace_length: int = 100):
        self.iterations = iterations
        self.trace_length = trace_length

    def validate_sprt(self, engine: SPRTEngine) -> Dict[str, Any]:
        """
        Generates synthetic sequences from H0 and H1, and verifies empirical error rates.
        """
        # 1. Generate H0 (Null) traces using the Markov Model
        h0_triggered = 0
        for i in range(self.iterations):
            # Start from a random state in the model's alphabet
            alphabet = list(engine.model.trainer.matrix.states)
            curr_state = random.choice(alphabet) if alphabet else "START"

            session_id = f"h0-session-{i}"
            triggered = False
            for _ in range(self.trace_length):
                state = BenchmarkState(curr_state, session_id)
                res = engine.observe(state)
                if res.decision == "ANOMALY":
                    triggered = True
                    break
                curr_state = engine.model.sample(curr_state)

            if triggered: h0_triggered += 1

        # 2. Generate H1 (Alternative) traces
        h1_triggered = 0
        for i in range(self.iterations):
            alphabet = list(engine.model.trainer.matrix.states)
            curr_state = random.choice(alphabet) if alphabet else "START"

            session_id = f"h1-session-{i}"
            triggered = False
            for _ in range(self.trace_length):
                state = BenchmarkState(curr_state, session_id)
                res = engine.observe(state)
                if res.decision == "ANOMALY":
                    triggered = True
                    break
                curr_state = engine.hypothesis.alternative_model.sample(curr_state) if engine.hypothesis.alternative_model else "UNKNOWN"

            if triggered: h1_triggered += 1

        empirical_alpha = h0_triggered / self.iterations
        empirical_beta = 1.0 - (h1_triggered / self.iterations)

        return {
            "theoretical_alpha": engine.hypothesis.alpha,
            "empirical_alpha": empirical_alpha,
            "theoretical_beta": engine.hypothesis.beta,
            "empirical_beta": empirical_beta,
            "diff_alpha": abs(empirical_alpha - engine.hypothesis.alpha),
            "diff_beta": abs(empirical_beta - engine.hypothesis.beta)
        }
