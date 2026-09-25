import logging
from typing import Dict, Any, Callable, List, Optional
from runtimeverify.events.base import Event
from runtimeverify.state.execution import ExecutionState
from runtimeverify.encoder.pipeline import StateEncoderPipeline
from runtimeverify.runtime.dispatcher import Dispatcher
from runtimeverify.runtime.context import Decision
from runtimeverify.policy.engine import PolicyEngine


class RuntimePipeline:
    """
    Coordinated sequential execution pipeline representing the core runtime flow.
    Stages: Receive -> Validate -> Encode -> Dispatch -> Policy -> Publish -> Persist.
    Each stage can be overridden/replaced for extensibility.
    """

    def __init__(
        self,
        encoder: StateEncoderPipeline,
        dispatcher: Dispatcher,
        policy_engine: PolicyEngine,
        exporters: Optional[List[Callable[[Decision], None]]] = None,
    ):
        self.encoder = encoder
        self.dispatcher = dispatcher
        self.policy_engine = policy_engine
        self.exporters = exporters or []
        self._logger = logging.getLogger("runtimeverify.runtime.pipeline")

        # Set default stages
        self.receive_stage: Callable[[Any], Event] = self._default_receive
        self.validate_stage: Callable[[Event], Event] = self._default_validate
        self.encode_stage: Callable[[Event], ExecutionState] = self._default_encode
        self.dispatch_stage: Callable[[ExecutionState], Dict[str, Any]] = self._default_dispatch
        self.policy_stage: Callable[[str, str, Dict[str, Any]], Decision] = self._default_policy
        self.publish_stage: Callable[[Decision], None] = self._default_publish
        self.persist_stage: Callable[[Decision], None] = self._default_persist

    def execute(self, raw_payload: Any) -> Decision:
        """Executes the entire runtime pipeline stages sequentially."""
        try:
            # 1. Receive
            event = self.receive_stage(raw_payload)

            # 2. Validate
            event = self.validate_stage(event)

            # 3. Encode
            state = self.encode_stage(event)

            # 4. Dispatch (and Detect)
            detector_results = self.dispatch_stage(state)

            # 5. Policy
            decision = self.policy_stage(event.session_id, event.agent_id, detector_results)

            # 6. Publish
            self.publish_stage(decision)

            # 7. Persist
            self.persist_stage(decision)

            return decision
        except Exception as e:
            self._logger.critical(f"Runtime pipeline failure: {e}", exc_info=True)
            # Default fallback block/pause decision to guarantee fail-safe mode
            return Decision(
                session_id=getattr(raw_payload, "session_id", "unknown_session"),
                agent_id=getattr(raw_payload, "agent_id", "unknown_agent"),
                status="BLOCK",
                confidence=0.0,
                evidence={"pipeline_failure": str(e)},
                triggered_policies=["pipeline_safety_fallback"],
            )

    # --- Default Stage Implementations ---

    def _default_receive(self, raw_payload: Any) -> Event:
        if not isinstance(raw_payload, Event):
            raise TypeError("Raw payload is not an instance of Event.")
        return raw_payload

    def _default_validate(self, event: Event) -> Event:
        if not event.session_id or not event.agent_id:
            raise ValueError("Event is missing session_id or agent_id.")
        return event

    def _default_encode(self, event: Event) -> ExecutionState:
        return self.encoder.encode(event)

    def _default_dispatch(self, state: ExecutionState) -> Dict[str, Any]:
        return self.dispatcher.dispatch(state)

    def _default_policy(self, session_id: str, agent_id: str, detector_results: Dict[str, Any]) -> Decision:
        return self.policy_engine.evaluate(session_id, agent_id, detector_results)

    def _default_publish(self, decision: Decision) -> None:
        for exporter in self.exporters:
            try:
                exporter(decision)
            except Exception as e:
                self._logger.error(f"Exporter failed to publish decision: {e}")

    def _default_persist(self, decision: Decision) -> None:
        # Placeholder for writing trace profiles to local DB or file logs
        pass
