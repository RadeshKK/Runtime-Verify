import pytest
from unittest.mock import MagicMock
from runtimeverify.engine.manager import RuntimeEngine
from runtimeverify.encoder.pipeline import EncodingPipeline
from runtimeverify.encoder.implementations import TypeBasedEncoder
from runtimeverify.encoder.models import StateRegistry
from runtimeverify.policy.engine import PolicyEngine
from runtimeverify.detector import DetectorResult
from runtimeverify.detector.interfaces import BaseDetector
from runtimeverify.detector import DetectorMetadata

class MockDetector(BaseDetector):
    """Mock implementation of Detector API for integration testing."""
    def __init__(self, drift_trigger: bool = False):
        self.drift_trigger = drift_trigger

    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(name="Mock", version="1.0")

    def train(self, trace_sequences): pass
    def reset(self): pass

    def update(self, current_state: str) -> DetectorResult:
        if self.drift_trigger:
            return DetectorResult(deviation_score=20.0, decision="DRIFT", evidence={})
        return DetectorResult(deviation_score=0.0, decision="NORMAL", evidence={})

def test_end_to_end_pipeline_flow():
    """Verify the flow: Event -> Encoder -> Detector -> Policy Engine."""
    # Setup
    registry = StateRegistry()
    encoder = TypeBasedEncoder(registry)
    pipeline = EncodingPipeline(encoder)
    
    # Policy: Block if detector says DRIFT
    rules = [{
        "name": "block_drift",
        "trigger": {"detector_decision": "DRIFT"},
        "action": "BLOCK"
    }]
    # We mock the evaluate method because the real one returns "ALLOW" by default
    policy_engine = PolicyEngine(rules)
    policy_engine.evaluate = MagicMock(side_effect=lambda trans, res: "BLOCK" if res.decision == "DRIFT" else "ALLOW")

    # Detector Factory that creates a "normal" detector
    def normal_factory(): return MockDetector(drift_trigger=False)
    
    engine = RuntimeEngine(pipeline, normal_factory, policy_engine)

    event = {
        "trace_id": "trace-123",
        "event_type": "agent_start",
        "payload": {}
    }

    # Test Normal Flow
    action = engine.handle_event(event)
    assert action == "ALLOW"

def test_runtime_engine_blocks_on_drift():
    """Verify that the engine triggers a BLOCK action when the detector detects drift."""
    registry = StateRegistry()
    encoder = TypeBasedEncoder(registry)
    pipeline = EncodingPipeline(encoder)
    
    policy_engine = PolicyEngine([])
    policy_engine.evaluate = MagicMock(side_effect=lambda trans, res: "BLOCK" if res.decision == "DRIFT" else "ALLOW")

    # Detector Factory that creates a "drifting" detector
    def drift_factory(): return MockDetector(drift_trigger=True)
    
    engine = RuntimeEngine(pipeline, drift_factory, policy_engine)

    event = {
        "trace_id": "trace-456",
        "event_type": "tool_call_start",
        "payload": {"tool_name": "execute_shell"}
    }

    action = engine.handle_event(event)
    assert action == "BLOCK"

def test_session_isolation():
    """Verify that different trace_ids maintain separate detector states."""
    registry = StateRegistry()
    encoder = TypeBasedEncoder(registry)
    pipeline = EncodingPipeline(encoder)
    policy_engine = PolicyEngine([])
    
    # Factory returns different behaviors based on a global toggle for test purposes
    # In reality, it just returns a new instance.
    def factory(): return MockDetector()
    
    engine = RuntimeEngine(pipeline, factory, policy_engine)
    
    event1 = {"trace_id": "t1", "event_type": "S1", "payload": {}}
    event2 = {"trace_id": "t2", "event_type": "S2", "payload": {}}
    
    engine.handle_event(event1)
    engine.handle_event(event2)
    
    assert "t1" in engine.sessions
    assert "t2" in engine.sessions
    assert engine.sessions["t1"].current_state.token == "S1"
    assert engine.sessions["t2"].current_state.token == "S2"
