from typing import Dict, Any, List
from runtimeverify.encoder.base import RuleEngine

class Rule:
    """
    A single deterministic matching rule. If all key-value condition pairs match 
    the enriched event schema, resolves to the specified target state.
    """
    def __init__(self, target_state: str, conditions: Dict[str, Any]):
        self.target_state = target_state
        self.conditions = conditions

    def matches(self, enriched_event: Dict[str, Any]) -> bool:
        """Evaluates whether all rule conditions are satisfied by the enriched event."""
        for key, expected_value in self.conditions.items():
            actual_value = enriched_event.get(key)
            if actual_value != expected_value:
                return False
        return True

class DefaultRuleEngine(RuleEngine):
    """
    Deterministic rule evaluator mapping enriched event variables to semantic states.
    If no configured rule matches, falls back to a template-based state name.
    """
    
    def __init__(self, rules: List[Rule]):
        self.rules = rules

    def evaluate(self, enriched_event: Dict[str, Any]) -> str:
        for rule in self.rules:
            if rule.matches(enriched_event):
                return rule.target_state
                
        # Default fallback string construction: {ACTION}_{RESOURCE_TYPE}
        action = str(enriched_event.get("action", "unknown")).upper()
        resource_type = str(enriched_event.get("resource_type", "unknown")).upper()
        return f"{action}_{resource_type}"
