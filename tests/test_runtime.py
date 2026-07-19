import pytest
from typing import List, Dict, Any
from runtimeverify.events import ToolEvent, FilesystemEvent
from runtimeverify.state.base import StateInterface
from runtimeverify.detector.base import BaseDetector, DetectorMetadata
from runtimeverify.detector.results import DetectorResult, DetectorExplanation
from runtimeverify.encoder import (
    DefaultTelemetryNormalizer,
    DefaultResourceClassifier,
    DefaultContextEnricher,
    DefaultRuleEngine,
    StateEncoderPipeline,
)
from runtimeverify.policy import PolicyEngine
from runtimeverify.runtime import (
    RuntimeState,
    RuntimeLifecycle,
    SessionManager,
    Dispatcher,
    RuntimePipeline,
    RuntimeEngine,
    Decision,
)

# Define a Mock Detector for test assertions
class MockDetector(BaseDetector):
    def __init__(self, name: str = "MockDetector", deviation: float = 0.0, should_fail: bool = False):
        self._name = name
        self._deviation = deviation
        self._should_fail = should_fail
        self.reset_called = False

    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(name=self._name, version="1.0", requires_training=False)

    def fit(self, sequences: List[List[StateInterface]]) -> None:
        pass

    def observe(self, state: StateInterface) -> DetectorResult:
        if self._should_fail:
            raise RuntimeError("Simulation of detector failure")
        return DetectorResult(
            deviation_score=self._deviation,
            confidence=1.0,
            decision="NORMAL" if self._deviation < 10.0 else "ANOMALY",
            explanation=DetectorExplanation(
                detector_name=self._name,
                summary="Normal execution flow matched",
                evidence={"value": state.name}
            )
        )

    def reset(self) -> None:
        self.reset_called = True

    def save(self, path: str) -> None:
        pass

    def load(self, path: str) -> None:
        pass

    def explain(self, result: DetectorResult) -> DetectorExplanation:
        return result.explanation


def test_runtime_lifecycle():
    lifecycle = RuntimeLifecycle()
    assert lifecycle.current == RuntimeState.CREATED
    
    lifecycle.transition_to(RuntimeState.INITIALIZED)
    assert lifecycle.current == RuntimeState.INITIALIZED
    
    lifecycle.transition_to(RuntimeState.RUNNING)
    assert lifecycle.current == RuntimeState.RUNNING
    
    # Test illegal transition (e.g. running back to created)
    with pytest.raises(ValueError):
        lifecycle.transition_to(RuntimeState.CREATED)

def test_session_manager_isolation():
    manager = SessionManager()
    session1 = manager.get_or_create("s1", "agent_a")
    session2 = manager.get_or_create("s2", "agent_b")
    
    assert session1.session_id == "s1"
    assert session2.session_id == "s2"
    
    # Verify separation of arrays
    assert len(session1.history) == 0
    assert len(session2.history) == 0

def test_dispatcher_fault_isolation():
    detector_ok = MockDetector("OkDetector", deviation=2.0)
    detector_fail = MockDetector("FailDetector", should_fail=True)
    
    dispatcher = Dispatcher([detector_ok, detector_fail])
    
    # Create mock ExecutionState
    from runtimeverify.state.hierarchy import StateHierarchy
    from runtimeverify.state.context import StateContext
    from runtimeverify.state.execution import ExecutionState
    
    mock_state = ExecutionState(
        name="TEST_STATE",
        category="tool",
        hierarchy=StateHierarchy(path=["TOOL", "TEST"]),
        context=StateContext(agent_id="a", session_id="s")
    )
    
    results = dispatcher.dispatch(mock_state)
    
    # Assert fault isolated: We got results for both detectors!
    assert "OkDetector" in results
    assert "FailDetector" in results
    
    # OkDetector works
    assert results["OkDetector"].deviation_score == 2.0
    assert results["OkDetector"].decision == "NORMAL"
    
    # FailDetector degraded gracefully to PENDING
    assert results["FailDetector"].decision == "PENDING"
    assert results["FailDetector"].raw_metrics.get("failed") is True

def test_runtime_pipeline_and_engine():
    # Setup state encoder pipeline dependencies
    normalizer = DefaultTelemetryNormalizer()
    classifier = DefaultResourceClassifier()
    enricher = DefaultContextEnricher()
    rule_engine = DefaultRuleEngine([])
    encoder = StateEncoderPipeline(normalizer, classifier, enricher, rule_engine)
    
    # Setup active detectors
    mock_det = MockDetector("TestDetector", deviation=12.0)  # Deviating score trigger
    dispatcher = Dispatcher([mock_det])
    
    # Setup policy engine
    policy_engine = PolicyEngine(threshold=10.0)
    
    # Setup exporter callback
    published_decisions: List[Decision] = []
    def mock_exporter(d: Decision):
        published_decisions.append(d)
        
    pipeline = RuntimePipeline(
        encoder=encoder,
        dispatcher=dispatcher,
        policy_engine=policy_engine,
        exporters=[mock_exporter]
    )
    
    engine = RuntimeEngine(pipeline=pipeline)
    
    # Initial state must call start() before observe()
    event = ToolEvent(
        session_id="session_integration",
        agent_id="agent_integration",
        tool_name="run_system_command",
        arguments={"cmd": "whoami"}
    )
    
    with pytest.raises(RuntimeError):
        engine.observe(event)
        
    # Start and run observe
    engine.start()
    decision = engine.observe(event)
    
    assert isinstance(decision, Decision)
    # The MockDetector has deviation_score = 12.0 which triggers threshold blocker (10.0)
    assert decision.status == "BLOCK"
    assert decision.confidence == 1.0
    assert "threshold_exceeded:TestDetector" in decision.triggered_policies
    
    # Verify publisher exporter triggered
    assert len(published_decisions) == 1
    assert published_decisions[0].session_id == "session_integration"
