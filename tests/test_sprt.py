import math
from runtimeverify.state.hierarchy import StateHierarchy
from runtimeverify.state.context import StateContext
from runtimeverify.state.execution import ExecutionState
from runtimeverify.markov import MarkovModel
from runtimeverify.sprt import Hypothesis, WaldThresholds, SPRTEngine


def make_mock_state(name: str, session_id: str) -> ExecutionState:
    return ExecutionState(
        name=name,
        category="tool",
        hierarchy=StateHierarchy(path=["TOOL", name]),
        context=StateContext(agent_id="agent_1", session_id=session_id),
    )


def test_wald_threshold_calculations():
    # Textbook verification: alpha=0.05, beta=0.05
    # A = ln(0.05 / 0.95) = -2.9444389791664403
    # B = ln(0.95 / 0.05) = 2.9444389791664403
    hyp = Hypothesis(alpha=0.05, beta=0.05, vocabulary_size=10)
    thresholds = WaldThresholds(hyp)

    assert abs(thresholds.lower_boundary - math.log(0.05 / 0.95)) < 1e-12
    assert abs(thresholds.upper_boundary - math.log(0.95 / 0.05)) < 1e-12


def test_sprt_normal_vs_abnormal_detection():
    # 1. Train Markov model on safe/normal traces
    normal_training = [
        ["START", "READ_CODE", "WRITE_CODE", "RUN_TEST", "COMMIT"],
        ["START", "READ_CODE", "WRITE_CODE", "RUN_TEST", "COMMIT"],
    ]
    model = MarkovModel(smoothing=0.01)  # Add smoothing to avoid absolute 0 probabilities
    model.train(normal_training)

    # Vocabulary is: START, READ_CODE, WRITE_CODE, RUN_TEST, COMMIT (size 5)
    hyp = Hypothesis(alpha=0.05, beta=0.05, vocabulary_size=5)
    engine = SPRTEngine(model, hyp)

    # --- Test Case A: Streaming a Normal Sequence ---
    # Transitions match H0 (normal behavior)
    normal_run = ["START", "READ_CODE", "WRITE_CODE", "RUN_TEST", "COMMIT"]

    results = []
    for state_name in normal_run:
        state = make_mock_state(state_name, "session_normal")
        res = engine.observe(state)
        results.append(res)

    # Standard normal runs should remain PENDING or resolve to NORMAL (ACCEPT_H0)
    # None of the steps should flag an ANOMALY (ACCEPT_H1)
    for res in results:
        assert res.decision != "ANOMALY"
        assert res.deviation_score < engine.thresholds.upper_boundary

    # The last transition or so may hit lower boundary and resolve to NORMAL (ACCEPT_H0)
    # (Since normal P is higher than uniform alternative Q, LLR decreases and becomes negative)
    last_res = results[-1]
    assert last_res.deviation_score <= 0.0

    # --- Test Case B: Streaming an Abnormal Sequence ---
    # Transition: START -> COMMIT is highly unlikely, and committing to unseen state is 0-prob
    engine.reset()  # Reset session stats

    abnormal_run = ["START", "COMMIT", "RUN_TEST", "COMMIT", "RUN_TEST"]

    anomaly_triggered = False
    for state_name in abnormal_run:
        state = make_mock_state(state_name, "session_abnormal")
        res = engine.observe(state)
        if res.decision == "ANOMALY":
            anomaly_triggered = True
            break

    assert anomaly_triggered is True
