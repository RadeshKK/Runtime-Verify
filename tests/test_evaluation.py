import pytest
from runtimeverify.events import Event, FilesystemEvent, ToolEvent
from runtimeverify.runtime.engine import RuntimeEngine
from runtimeverify.markov.model import MarkovModel
from runtimeverify.sprt import Hypothesis, SPRTEngine
from runtimeverify.evaluation import (
    RandomDetector,
    ThresholdDetector,
    FrequencyDetector,
    TraceGenerator,
    EvaluationMetrics,
    SessionReplayer,
    BenchmarkRunner,
)

def test_evaluation_generators():
    normal_trace = TraceGenerator.generate_coding_session("session_1")
    assert len(normal_trace) == 6
    assert normal_trace[0].type == "agent_start"
    assert normal_trace[-1].type == "agent_end"

    rare = TraceGenerator.inject_rare_transition(normal_trace)
    assert len(rare) == 2
    assert rare[0].type == "agent_start"
    assert rare[1].type == "agent_end"

    escalated = TraceGenerator.inject_permission_escalation(normal_trace)
    paths = [ev.path for ev in escalated if isinstance(ev, FilesystemEvent)]
    assert "/etc/shadow" in paths

    misuse = TraceGenerator.inject_tool_misuse(normal_trace)
    tool_names = [ev.tool_name for ev in misuse if isinstance(ev, ToolEvent)]
    assert "execute_command" in tool_names

    loop = TraceGenerator.inject_infinite_loop(normal_trace)
    assert len(loop) > 20

def test_evaluation_metrics_calculator():
    # Ground Truth: [Normal, Normal, Anomaly, Anomaly] -> [False, False, True, True]
    # Predictions:  [Normal, Anomaly, Normal, Anomaly] -> [False, True, False, True]
    # TP: (True, True) -> 1
    # FP: (False, True) -> 1
    # TN: (False, False) -> 1
    # FN: (True, False) -> 1
    gt = [False, False, True, True]
    preds = [False, True, False, True]
    
    metrics = EvaluationMetrics.calculate_classification_metrics(gt, preds)
    
    assert metrics["true_positives"] == 1.0
    assert metrics["false_positives"] == 1.0
    assert metrics["true_negatives"] == 1.0
    assert metrics["false_negatives"] == 1.0
    assert metrics["accuracy"] == 0.5
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1_score"] == 0.5
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["false_negative_rate"] == 0.5

def test_baselines_observes():
    # Random detector
    rand = RandomDetector(anomaly_rate=0.0)
    trace = TraceGenerator.generate_coding_session("session_1")
    # Convert Event trace to state nodes (requires StateEncoder, or just test observe directly)
    # Since baseline observe takes StateInterface:
    from runtimeverify.state.execution import ExecutionState
    from runtimeverify.state.context import StateContext
    from runtimeverify.state.hierarchy import StateHierarchy
    
    mock_state = ExecutionState(
        name="READ",
        category="filesystem",
        hierarchy=StateHierarchy(path=["FILESYSTEM", "READ"]),
        context=StateContext(agent_id="agent_1", session_id="session_1")
    )
    
    res = rand.observe(mock_state)
    assert res.decision == "NORMAL"
    
    # Threshold detector
    thresh = ThresholdDetector(risk_threshold="critical")
    # Critical state
    from runtimeverify.state.metadata import StateMetadata
    critical_state = ExecutionState(
        name="ESCALATION",
        category="filesystem",
        hierarchy=StateHierarchy(path=["FILESYSTEM", "ESCALATION"]),
        context=StateContext(agent_id="agent_1", session_id="session_1"),
        metadata=StateMetadata(risk_level="critical")
    )
    res_crit = thresh.observe(critical_state)
    assert res_crit.decision == "ANOMALY"
