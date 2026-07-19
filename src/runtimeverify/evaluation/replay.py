import time
from typing import List, Dict, Any
from runtimeverify.events.base import Event
from runtimeverify.runtime.engine import RuntimeEngine
from runtimeverify.runtime.context import Decision

class SessionReplayer:
    """
    Replays logged or generated event traces through a RuntimeEngine.
    Measures processing speed, latency, and step-level decision delay.
    """
    
    def __init__(self, engine: RuntimeEngine):
        self.engine = engine

    def replay(self, trace: List[Event]) -> Dict[str, Any]:
        """
        Replays the sequence, updating the engine step-by-step.
        
        Args:
            trace: List of Event instances.
            
        Returns:
            A results summary dict with final decisions, step timings, and delay statistics.
        """
        decisions: List[Decision] = []
        step_times: List[float] = []
        
        anomaly_index = -1
        detected_index = -1
        
        # Reset the engine state before replaying to guarantee test isolation
        self.engine.session_manager.clear()
        self.engine.pipeline.dispatcher.reset_detectors()
        
        # Make sure engine is running
        from runtimeverify.runtime.lifecycle import RuntimeState
        if self.engine.lifecycle.current != RuntimeState.RUNNING:
            self.engine.lifecycle.transition_to(RuntimeState.RUNNING)

        total_start = time.perf_counter()
        
        for idx, event in enumerate(trace):
            # Check if this event was injected with an anomaly tag
            if event.metadata.get("is_anomaly") is True and anomaly_index == -1:
                anomaly_index = idx

            step_start = time.perf_counter()
            decision = self.engine.observe(event)
            step_times.append((time.perf_counter() - step_start) * 1000.0)
            
            decisions.append(decision)

            # Check if the policy engine blocked or any detector flagged an anomaly
            is_flagged = (decision.status == "BLOCK") or any(
                res.get("decision") == "ANOMALY" 
                for res in decision.detector_results.values()
            )
            
            if is_flagged and detected_index == -1:
                detected_index = idx

        total_duration_ms = (time.perf_counter() - total_start) * 1000.0
        
        delay = -1
        if anomaly_index != -1 and detected_index != -1:
            delay = max(0, detected_index - anomaly_index)

        return {
            "decisions": decisions,
            "final_decision": decisions[-1] if decisions else None,
            "step_latencies_ms": step_times,
            "avg_step_latency_ms": sum(step_times) / len(step_times) if step_times else 0.0,
            "total_duration_ms": total_duration_ms,
            "anomaly_index": anomaly_index,
            "detected_index": detected_index,
            "detection_delay_steps": delay,
            "anomaly_triggered": detected_index != -1
        }
