from typing import Dict, Any
from runtimeverify.encoder.base import ContextEnricher

class DefaultContextEnricher(ContextEnricher):
    """
    Enriches the event classification with history and surrounding context sequences, 
    allowing mapping patterns of activity into complex states.
    """
    
    def enrich(self, classified_event: Dict[str, Any], history: list) -> Dict[str, Any]:
        enriched = classified_event.copy()
        
        # Simple sequence pattern matching, e.g. SEARCH -> READ -> SUMMARIZE
        pattern = "standalone"
        if history:
            # history contains list of previous state name strings
            last_state = history[-1]
            action = classified_event.get("action")
            res_type = classified_event.get("resource_type")
            
            if last_state == "SEARCH_DATABASE" and action == "read" and res_type == "general_file":
                pattern = "document_research"
            elif last_state == "READ_SYSTEM_SECRET" and action == "request" and res_type == "external_api":
                pattern = "potential_leak"
                
        enriched["execution_pattern"] = pattern
        enriched["history_summary"] = history[-5:]
        return enriched
