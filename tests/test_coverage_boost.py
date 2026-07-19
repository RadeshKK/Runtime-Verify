import os
import json
import math
import time
import pytest
from unittest.mock import MagicMock, patch
from runtimeverify.events import Event, FilesystemEvent, ToolEvent, LLMEvent
from runtimeverify.telemetry.manager import get_global_manager
from runtimeverify.integrations.langgraph import LangGraphAdapter
from runtimeverify.integrations.pydanticai import PydanticAIAdapter
from runtimeverify.integrations.crewai import CrewAIAdapter
from runtimeverify.cloud.client import CloudVerificationClient
from runtimeverify.sprt.alternative import (
    UniformAlternativeModel,
    AdversarialAlternativeModel,
    EmpiricalAlternativeModel
)
from runtimeverify.evaluation.baselines import (
    RandomDetector,
    ThresholdDetector,
    FrequencyDetector
)
from runtimeverify.evaluation.replay import SessionReplayer
from runtimeverify.evaluation.benchmark import BenchmarkRunner
from runtimeverify.evaluation.reports import ReportGenerator
from runtimeverify.markov.predictor import MarkovPredictor
from runtimeverify.markov.matrix import ProbabilityMatrix
from runtimeverify.markov.model import MarkovModel
from runtimeverify.state.execution import ExecutionState
from runtimeverify.state.categories import StateCategory
from runtimeverify.state.hierarchy import StateHierarchy
from runtimeverify.state.context import StateContext
from runtimeverify.state.metadata import StateMetadata

# 1. Test Integrations
def test_integrations_langgraph():
    events_published = []
    manager = get_global_manager()
    manager.bus.subscribe(lambda ev: events_published.append(ev))

    def dummy_node(state):
        if "fail" in state:
            raise ValueError("Node failure")
        return {"result": "success"}

    wrapped = LangGraphAdapter.instrument_node("test_node", dummy_node)
    
    # Success path
    class MockState(dict):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.session_id = "s123"
            self.agent_id = "a123"
            
    state = MockState({"keys": ["k1"]})
    res = wrapped(state)
    assert res == {"result": "success"}
    assert len(events_published) >= 2
    assert events_published[-2].tool_name == "test_node"
    assert events_published[-2].status == "running"
    assert events_published[-1].status == "success"

    # Failure path
    state_fail = MockState({"fail": True})
    with pytest.raises(ValueError):
        wrapped(state_fail)
        
    assert events_published[-1].status == "error"


def test_integrations_pydanticai():
    events_published = []
    manager = get_global_manager()
    manager.bus.subscribe(lambda ev: events_published.append(ev))

    class MockUsage:
        prompt_tokens = 10
        completion_tokens = 20
        total_tokens = 30

    class MockResult:
        model_name = "gpt-mock"
        data = "hello world"
        usage = MockUsage()

    class MockAgent:
        name = "mock_agent"
        def run(self, prompt, **kwargs):
            if "fail" in prompt:
                raise ValueError("Agent failed")
            return MockResult()

    agent = MockAgent()
    PydanticAIAdapter.instrument_agent(agent)
    
    res = agent.run("hello", session_id="s_pydantic")
    assert res.data == "hello world"
    assert len(events_published) >= 1
    assert isinstance(events_published[-1], LLMEvent)
    assert events_published[-1].prompt_tokens == 10
    assert events_published[-1].metadata["response"] == "hello world"


def test_integrations_crewai():
    events_published = []
    manager = get_global_manager()
    manager.bus.subscribe(lambda ev: events_published.append(ev))

    callback = CrewAIAdapter.create_task_callback("s_crew", "a_crew")
    
    class MockTaskOutput:
        description = "Task description"
        agent = "crew_agent"
        raw = "output raw data"

    callback(MockTaskOutput())
    assert len(events_published) >= 1
    assert events_published[-1].tool_name == "crewai_task_execution"
    assert events_published[-1].output == "output raw data"


# 2. Test Cloud Client
@patch("requests.Session.post")
def test_cloud_client(mock_post):
    # Setup mock post responses
    mock_post.return_value.status_code = 200
    
    client = CloudVerificationClient("https://api.verify.cloud", "api_key_123")
    
    res_dec = client.push_decision("s1", "a1", {"status": "ALLOW"})
    assert res_dec is True
    
    mock_post.return_value.status_code = 201
    res_alert = client.push_alert("s1", "a1", "threshold_exceeded", {"score": 10.0})
    assert res_alert is True

    # Error handling gracefully degrades
    mock_post.side_effect = Exception("Connection Timeout")
    assert client.push_decision("s1", "a1", {}) is False
    assert client.push_alert("s1", "a1", "x", {}) is False


# 3. Test Alternative Hypotheses
def test_alternative_models():
    # Uniform
    uniform = UniformAlternativeModel(vocabulary_size=8)
    assert uniform.get_probability("ANY", "THING") == 0.125
    
    # Adversarial
    adversarial = AdversarialAlternativeModel(vocabulary_size=8, high_risk_identifiers={"EXECUTE_COMMAND"}, high_risk_prob=0.8)
    assert adversarial.get_probability("ANY", ExecutionState(name="EXECUTE_COMMAND", category=StateCategory.TOOL, hierarchy=StateHierarchy(path=["TOOL", "EXECUTE_COMMAND"]), context=StateContext(session_id="s1", agent_id="a1"))) == 0.8
    assert adversarial.get_probability("ANY", ExecutionState(name="OTHER", category=StateCategory.TOOL, hierarchy=StateHierarchy(path=["TOOL", "OTHER"]), context=StateContext(session_id="s1", agent_id="a1"))) == pytest.approx(0.2 / 7)
    
    # Empirical
    empirical = EmpiricalAlternativeModel(transition_matrix={"STATE": {"NEXT": 0.5}}, vocabulary_size=8)
    assert empirical.get_probability("STATE", ExecutionState(name="NEXT", category=StateCategory.TOOL, hierarchy=StateHierarchy(path=["TOOL", "NEXT"]), context=StateContext(session_id="s1", agent_id="a1"))) == 0.5
    assert empirical.get_probability("STATE", ExecutionState(name="OTHER", category=StateCategory.TOOL, hierarchy=StateHierarchy(path=["TOOL", "OTHER"]), context=StateContext(session_id="s1", agent_id="a1"))) == 0.125
    assert empirical.get_probability("UNSEEN", ExecutionState(name="ANY", category=StateCategory.TOOL, hierarchy=StateHierarchy(path=["TOOL", "ANY"]), context=StateContext(session_id="s1", agent_id="a1"))) == 0.125


# 4. Test Evaluation & Baselines
def test_evaluation_baselines():
    dummy_state = ExecutionState(
        name="READ",
        category=StateCategory.FILESYSTEM,
        hierarchy=StateHierarchy(path=["FILESYSTEM", "READ"]),
        context=StateContext(session_id="s1", agent_id="a1")
    )
    
    # Random
    r_det = RandomDetector()
    res1 = r_det.observe(dummy_state)
    assert res1.decision in ["NORMAL", "ANOMALY"]
    
    # Threshold
    t_det = ThresholdDetector(risk_threshold="critical")
    # Target high risk
    high_state = ExecutionState(
        name="EXECUTE_COMMAND",
        category=StateCategory.TOOL,
        hierarchy=StateHierarchy(path=["TOOL", "EXECUTE_COMMAND"]),
        context=StateContext(session_id="s1", agent_id="a1"),
        metadata=StateMetadata(risk_level="critical")
    )
    res_high = t_det.observe(high_state)
    assert res_high.decision == "ANOMALY"
    res_low = t_det.observe(dummy_state)
    assert res_low.decision == "NORMAL"
    
    # Frequency
    model = MarkovModel(smoothing=0.01)
    f_det = FrequencyDetector(markov_model=model, min_prob_threshold=0.1)
    res_freq = f_det.observe(dummy_state)
    assert res_freq.decision in ["NORMAL", "ANOMALY", "PENDING"]


def test_evaluation_replay():
    events = [
        ToolEvent(session_id="s1", agent_id="a1", tool_name="tool_1", arguments={}, status="success"),
        ToolEvent(session_id="s1", agent_id="a1", tool_name="tool_2", arguments={}, status="success"),
    ]
    
    from runtimeverify.runtime.engine import RuntimeEngine
    from runtimeverify.runtime.pipeline import RuntimePipeline
    from runtimeverify.encoder.pipeline import StateEncoderPipeline
    from runtimeverify.encoder.normalizer import DefaultTelemetryNormalizer
    from runtimeverify.encoder.classifier import DefaultResourceClassifier
    from runtimeverify.encoder.enrichers import DefaultContextEnricher
    from runtimeverify.encoder.rules import DefaultRuleEngine
    from runtimeverify.runtime.dispatcher import Dispatcher
    from runtimeverify.policy.engine import PolicyEngine

    encoder = StateEncoderPipeline(
        DefaultTelemetryNormalizer(),
        DefaultResourceClassifier(),
        DefaultContextEnricher(),
        DefaultRuleEngine([])
    )
    pipeline = RuntimePipeline(encoder, Dispatcher([]), PolicyEngine())
    engine = RuntimeEngine(pipeline)
    
    runner = SessionReplayer(engine)
    results = runner.replay(events)
    assert len(results["decisions"]) == 2
    assert results["decisions"][0].status == "ALLOW"


def test_evaluation_benchmark_and_reports():
    # Setup minimal benchmark runs
    normal_traces = [
        [
            ToolEvent(session_id="s1", agent_id="a1", tool_name="t1", arguments={}, status="success"),
            ToolEvent(session_id="s1", agent_id="a1", tool_name="t2", arguments={}, status="success"),
        ]
    ]
    anomalous_traces = [
        [
            ToolEvent(session_id="s2", agent_id="a1", tool_name="t1", arguments={}, status="success"),
            FilesystemEvent(session_id="s2", agent_id="a1", action="read", path="/etc/shadow", status="success"),
        ]
    ]
    
    # Run Benchmark
    runner = BenchmarkRunner(normal_traces, anomalous_traces)
    
    from runtimeverify.runtime.engine import RuntimeEngine
    from runtimeverify.runtime.pipeline import RuntimePipeline
    from runtimeverify.encoder.pipeline import StateEncoderPipeline
    from runtimeverify.encoder.normalizer import DefaultTelemetryNormalizer
    from runtimeverify.encoder.classifier import DefaultResourceClassifier
    from runtimeverify.encoder.enrichers import DefaultContextEnricher
    from runtimeverify.encoder.rules import DefaultRuleEngine
    from runtimeverify.runtime.dispatcher import Dispatcher
    from runtimeverify.policy.engine import PolicyEngine

    encoder = StateEncoderPipeline(
        DefaultTelemetryNormalizer(),
        DefaultResourceClassifier(),
        DefaultContextEnricher(),
        DefaultRuleEngine([])
    )
    pipeline = RuntimePipeline(encoder, Dispatcher([]), PolicyEngine())
    engine = RuntimeEngine(pipeline)
    
    res = runner.evaluate_engine(engine, "test_engine")
    assert res["name"] == "test_engine"
    assert "metrics" in res
    
    # Run Report generation
    summary = ReportGenerator.generate_markdown(res["name"], res["metrics"], res["average_delay"], res["all_step_latencies"])
    assert "test_engine" in summary
    
    comp_summary = ReportGenerator.generate_comparison_table([res])
    assert "test_engine" in comp_summary


# 5. Test Markov Predictor
def test_markov_predictor():
    matrix = ProbabilityMatrix(smoothing=0.01)
    matrix.states = {"START", "READ", "WRITE"}
    matrix.probabilities = {
        "START": {"READ": 0.8, "WRITE": 0.2},
        "READ": {"READ": 0.3, "WRITE": 0.7}
    }
    
    predictor = MarkovPredictor(matrix)
    
    # Predict next state
    preds = predictor.predict_next("START")
    assert len(preds) > 0
    assert preds[0][0] == "READ"
    assert preds[0][1] == 0.8
    
    # Unseen prefix
    preds_unseen = predictor.predict_next("UNSEEN")
    assert len(preds_unseen) == 0

    # Sequence probability
    prob_seq = predictor.sequence_probability(["START", "READ", "WRITE"])
    assert prob_seq == 0.8 * 0.7
    
    log_prob_seq = predictor.sequence_log_probability(["START", "READ", "WRITE"])
    assert log_prob_seq == pytest.approx(math.log(0.8) + math.log(0.7))

# 6. Test EventBus Unsubscribe & Error handling
def test_unsubscribing():
    bus = get_global_manager().bus
    def listener(ev):
        pass
    bus.subscribe(listener, "tool")
    bus.unsubscribe(listener, "tool")
    bus.subscribe(listener)
    bus.unsubscribe(listener)

# 7. Test Decorators
def test_decorators():
    from runtimeverify.telemetry.decorators import observe_tool, observe_llm, span
    from runtimeverify.telemetry.middleware import TelemetryMiddleware
    
    middleware = TelemetryMiddleware(session_id="s_dec", agent_id="a_dec")
    
    @middleware
    def my_agent():
        return "agent_run"
        
    @observe_tool(name="my_tool")
    def my_tool(x):
        return x * 2

    @observe_llm(model="gpt-4")
    def my_llm(prompt):
        return "llm_response"

    assert my_agent() == "agent_run"
    assert my_tool(5) == 10
    assert my_llm("test") == "llm_response"
    
    with span("test_span"):
        pass

# 8. Test Registries
def test_registries():
    from runtimeverify.detector.registry import DetectorRegistry
    from runtimeverify.encoder.registry import EncoderRegistry
    from runtimeverify.runtime.registry import PipelineRegistry
    
    # Encoder Registry
    enc_reg = EncoderRegistry()
    mock_encoder = MagicMock()
    enc_reg.register("test_enc", mock_encoder)
    assert enc_reg.get("test_enc") == mock_encoder
    assert "test_enc" in enc_reg.list_encoders()
    enc_reg.clear()
    
    # Detector Registry
    det_reg = DetectorRegistry()
    mock_detector = MagicMock()
    det_reg.register("test_det", mock_detector)
    assert det_reg.get("test_det") == mock_detector
    assert "test_det" in det_reg.list_detectors()
    det_reg.clear()

    # Runtime Registry (PipelineRegistry)
    reg = PipelineRegistry()
    mock_pipeline = MagicMock()
    reg.register("test_pipe", mock_pipeline)
    assert reg.get("test_pipe") == mock_pipeline
    assert "test_pipe" in reg.list_pipelines()
    reg.clear()

# 9. Test Decorators Error Paths & Async Execution
@pytest.mark.anyio
async def test_decorators_async_and_errors():
    from runtimeverify.telemetry.decorators import observe_tool, observe_llm, span

    @observe_tool
    async def async_tool(x):
        if x < 0:
            raise ValueError("negative tool value")
        return x * 3

    @observe_llm(model="gpt-3")
    async def async_llm(prompt):
        if not prompt:
            raise ValueError("empty prompt")
        return "async_response"

    @observe_tool
    def failing_sync_tool():
        raise RuntimeError("sync tool fail")

    # Async success
    assert await async_tool(3) == 9
    assert await async_llm("test") == "async_response"

    # Async failure
    with pytest.raises(ValueError):
        await async_tool(-1)
    with pytest.raises(ValueError):
        await async_llm("")

    # Sync failure
    with pytest.raises(RuntimeError):
        failing_sync_tool()

    # Span failure
    with pytest.raises(TypeError):
        with span("test_error_span"):
            raise TypeError("span error")

# 10. Test API Error Paths & Training
def test_api_extended():
    from fastapi.testclient import TestClient
    from runtimeverify.api.app import app
    client = TestClient(app)

    # 404 lookups
    assert client.get("/session/non_existent_session").status_code == 404
    assert client.get("/decision/non_existent_decision").status_code == 404

    # Train route
    train_payload = {
        "traces": [
            ["START", "READ", "WRITE", "END"]
        ],
        "smoothing": 0.05
    }
    resp = client.post("/train", json=train_payload)
    assert resp.status_code == 200
    assert "states_vocabulary" in resp.json()

# 11. Test CLI Error Paths
def test_cli_errors(tmp_path):
    from typer.testing import CliRunner
    from runtimeverify.cli import app
    runner = CliRunner()

    # Init twice to trigger force error
    workspace_dir = str(tmp_path / "ws")
    res1 = runner.invoke(app, ["init", workspace_dir])
    assert res1.exit_code == 0
    res2 = runner.invoke(app, ["init", workspace_dir])
    assert res2.exit_code == 2

    # Train non-existent
    res_train = runner.invoke(app, ["train", "non_existent_traces_file_123.json"])
    assert res_train.exit_code == 2

    # Inspect non-existent
    res_inspect = runner.invoke(app, ["inspect", "non_existent_model_123.json"])
    assert res_inspect.exit_code == 4

    # Explain non-existent
    res_explain = runner.invoke(app, ["explain", "READ", "WRITE", "--model", "non_existent_model_123.json"])
    assert res_explain.exit_code == 4

# 12. Test Async Middleware & Telemetry Collectors
@pytest.mark.anyio
async def test_async_middleware_and_collectors():
    from runtimeverify.telemetry.middleware import TelemetryMiddleware
    middleware = TelemetryMiddleware(session_id="s_async_mid", agent_id="a_async_mid")
    
    @middleware
    async def async_agent():
        return "done_async"
        
    assert await async_agent() == "done_async"
    
    # Custom failure async middleware
    @middleware
    async def failing_async_agent():
        raise RuntimeError("fail async agent")
        
    with pytest.raises(RuntimeError):
        await failing_async_agent()
        
    # Collector statements
    collector = get_global_manager().collector
    collector.collect_filesystem("read", "main.py")
    collector.collect_network("http://localhost", "GET")
    collector.collect_memory("var", "prev", "next")



