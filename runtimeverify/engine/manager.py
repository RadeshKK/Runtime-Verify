from typing import Dict, Any, Optional
from runtimeverify.telemetry.engine import telemetry_engine
from runtimeverify.encoder.pipeline import EncodingPipeline
from runtimeverify.detector.interfaces import BaseDetector
from runtimeverify.policy.engine import PolicyEngine
from runtimeverify.engine.session import VerificationSession

class RuntimeEngine:
    """
    The central orchestrator that connects telemetry, encoding, detection, and policy.
    """
    def __init__(
        self, 
        encoder_pipeline: EncodingPipeline, 
        detector_factory: Any, 
        policy_engine: PolicyEngine
    ):
        self.encoder_pipeline = encoder_pipeline
        self.detector_factory = detector_factory
        self.policy_engine = policy_engine
        self.sessions: Dict[str, VerificationSession] = {}

    def handle_event(self, event: Dict[str, Any]) -> str:
        """
        Processes a raw telemetry event through the full verification pipeline.
        
        Args:
            event: The raw event dictionary.
            
        Returns:
            The resolved policy action (e.g., 'ALLOW', 'BLOCK').
        """
        trace_id = event.get("trace_id")
        if not trace_id:
            return "ALLOW"

        # 1. Session Management
        if trace_id not in self.sessions:
            # Create a new detector instance for this specific session
            detector = self.detector_factory() 
            self.sessions[trace_id] = VerificationSession(trace_id, detector)
        
        session = self.sessions[trace_id]

        # 2. Semantic Encoding
        symbolic_state = self.encoder_pipeline.process_event(event)
        session.update_state(symbolic_state)

        # 3. Anomaly Detection
        detector_result = session.detector.update(symbolic_state.token)

        # 4. Policy Decisioning
        transition = session.get_transition()
        action = self.policy_engine.evaluate(transition, detector_result)

        return action

    def end_session(self, trace_id: str) -> None:
        """Cleans up session data after agent completion."""
        if trace_id in self.sessions:
            del self.sessions[trace_id]
