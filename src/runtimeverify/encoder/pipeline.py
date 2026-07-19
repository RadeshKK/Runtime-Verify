import uuid
from typing import Dict, List, Optional
from runtimeverify.events.base import Event
from runtimeverify.state.execution import ExecutionState
from runtimeverify.state.hierarchy import StateHierarchy
from runtimeverify.state.categories import StateCategory
from runtimeverify.state.context import StateContext
from runtimeverify.state.metadata import StateMetadata
from runtimeverify.state.provenance import StateProvenance
from runtimeverify.encoder.base import (
    BaseEncoder,
    TelemetryNormalizer,
    ResourceClassifier,
    ContextEnricher,
    RuleEngine,
)
from runtimeverify.encoder.cache import StateEncoderCache

class StateEncoderPipeline(BaseEncoder):
    """
    State Encoder Pipeline implementing the BaseEncoder interface.
    Coordinates Normalization, Cache checks, Resource Classification, 
    Context Enrichment, and Rule Evaluation stages to produce ExecutionState nodes.
    """
    
    def __init__(
        self,
        normalizer: TelemetryNormalizer,
        classifier: ResourceClassifier,
        enricher: ContextEnricher,
        rule_engine: RuleEngine,
        cache: Optional[StateEncoderCache] = None,
    ):
        self.normalizer = normalizer
        self.classifier = classifier
        self.enricher = enricher
        self.rule_engine = rule_engine
        self.cache = cache or StateEncoderCache()
        
        # In-memory history trackers per session
        self._name_history: Dict[str, List[str]] = {}
        self._state_history: Dict[str, List[ExecutionState]] = {}

    def encode(self, event: Event) -> ExecutionState:
        # 1. Normalize
        normalized = self.normalizer.normalize(event)
        
        # 2. Check cache for resource properties (type, action, status)
        resource_key = f"{normalized.get('type')}:{normalized.get('resource')}:{normalized.get('action')}"
        cached_classification = self.cache.get(resource_key)
        
        if cached_classification is not None:
            classified = cached_classification.copy()
            # Copy runtime trace fields
            classified["event_id"] = normalized["event_id"]
            classified["session_id"] = normalized["session_id"]
            classified["agent_id"] = normalized["agent_id"]
            classified["timestamp"] = normalized["timestamp"]
        else:
            # Classify
            classified = self.classifier.classify(normalized)
            # Store general properties in cache
            cache_props = {
                "type": classified.get("type"),
                "resource": classified.get("resource"),
                "action": classified.get("action"),
                "resource_type": classified.get("resource_type"),
                "risk_level": classified.get("risk_level"),
                "permission_level": classified.get("permission_level"),
            }
            self.cache.set(resource_key, cache_props)

        # 3. Enrich with context history
        session_id = event.session_id
        session_names = self._name_history.get(session_id, [])
        enriched = self.enricher.enrich(classified, session_names)

        # 4. Evaluate rules
        state_name = self.rule_engine.evaluate(enriched)
        
        # Update history names
        session_names.append(state_name)
        self._name_history[session_id] = session_names

        # 5. Build ExecutionState
        hierarchy_path = [enriched.get("type", "generic").upper()] + state_name.split("_")
        hierarchy = StateHierarchy(path=hierarchy_path)
        
        type_str = enriched.get("type", "generic").lower()
        try:
            category = StateCategory(type_str)
        except ValueError:
            category = StateCategory.SYSTEM

        # Find preceding state ID
        previous_states = self._state_history.get(session_id, [])
        prev_id = previous_states[-1].id if previous_states else None
        
        context = StateContext(
            resource_id=str(enriched.get("resource")) if enriched.get("resource") else None,
            resource_type=enriched.get("resource_type"),
            agent_id=event.agent_id,
            session_id=event.session_id,
            previous_state_id=prev_id,
            timestamp=event.timestamp,
        )
        
        # Resolve provenance
        from runtimeverify.encoder.rules import DefaultRuleEngine
        generated_by = "Fallback:ActionResource"
        confidence = 1.0
        
        if isinstance(self.rule_engine, DefaultRuleEngine):
            for rule in self.rule_engine.rules:
                if rule.matches(enriched):
                    generated_by = f"Rule:{rule.target_state}"
                    break
        else:
            generated_by = f"RuleEngine:{self.rule_engine.__class__.__name__}"
            
        evidence = None
        if hasattr(event, "path"):
            evidence = getattr(event, "path")
        elif hasattr(event, "url"):
            evidence = getattr(event, "url")
        elif hasattr(event, "tool_name"):
            evidence = getattr(event, "tool_name")
        elif hasattr(event, "key"):
            evidence = getattr(event, "key")
            
        prov = StateProvenance(
            generated_by=generated_by,
            confidence=confidence,
            evidence=evidence
        )

        metadata = StateMetadata(
            permission_level=enriched.get("permission_level"),
            risk_level=enriched.get("risk_level", "low")
        )

        state = ExecutionState(
            id=str(uuid.uuid4()),
            name=state_name,
            category=category,
            hierarchy=hierarchy,
            context=context,
            metadata=metadata,
            schema_version="1.0",
            encoder_version="1.0",
            provenance=prov,
        )
        
        # Save state reference
        previous_states.append(state)
        self._state_history[session_id] = previous_states
        
        return state

    def clear_session(self, session_id: str) -> None:
        """Clears trace history files for a specific session."""
        self._name_history.pop(session_id, None)
        self._state_history.pop(session_id, None)
