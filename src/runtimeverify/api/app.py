import os
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from runtimeverify.events.base import Event
from runtimeverify.runtime.engine import RuntimeEngine
from runtimeverify.runtime.pipeline import RuntimePipeline
from runtimeverify.runtime.dispatcher import Dispatcher
from runtimeverify.policy.engine import PolicyEngine
from runtimeverify.encoder import (
    DefaultTelemetryNormalizer,
    DefaultResourceClassifier,
    DefaultContextEnricher,
    DefaultRuleEngine,
    StateEncoderPipeline,
)
from runtimeverify.markov.model import MarkovModel
from runtimeverify.sprt import Hypothesis, SPRTEngine

app = FastAPI(title="AI Runtime Verification API", version="0.1.0")

# Shared state
session_db: Dict[str, List[Dict[str, Any]]] = {}
decisions_cache: Dict[str, Dict[str, Any]] = {}
current_model: Optional[MarkovModel] = None
engine: Optional[RuntimeEngine] = None

# Initialize default engine
def initialize_engine(model_path: Optional[str] = None):
    global current_model, engine
    current_model = MarkovModel(smoothing=0.01)
    if model_path and os.path.exists(model_path):
        current_model.load(model_path)
    
    from runtimeverify.encoder.rules import Rule
    rules = [
        # Read-like tools mapped to model READ state
        Rule("READ", {"type": "tool", "resource": "read_source_code"}),
        Rule("READ", {"type": "tool", "resource": "view_file"}),
        Rule("READ", {"type": "tool", "resource": "list_dir"}),
        Rule("READ", {"type": "tool", "resource": "grep_search"}),
        Rule("READ", {"type": "tool", "resource": "read_file"}),
        
        # Write-like tools mapped to model WRITE state
        Rule("WRITE", {"type": "tool", "resource": "write_to_file"}),
        Rule("WRITE", {"type": "tool", "resource": "replace_file_content"}),
        Rule("WRITE", {"type": "tool", "resource": "multi_replace_file_content"}),
        Rule("WRITE", {"type": "tool", "resource": "run_command"}),
        Rule("WRITE", {"type": "tool", "resource": "execute_command"}),
    ]
    normalizer = DefaultTelemetryNormalizer()
    classifier = DefaultResourceClassifier()
    enricher = DefaultContextEnricher()
    rule_engine = DefaultRuleEngine(rules)
    encoder = StateEncoderPipeline(normalizer, classifier, enricher, rule_engine)
    
    # Register SPRT detector
    hyp = Hypothesis(alpha=0.05, beta=0.05, vocabulary_size=10)
    sprt = SPRTEngine(current_model, hyp)
    
    dispatcher = Dispatcher([sprt])
    policy_engine = PolicyEngine(threshold=5.0)
    
    pipeline = RuntimePipeline(encoder, dispatcher, policy_engine)
    engine = RuntimeEngine(pipeline)
    engine.start()

# Initialize default engine
initialize_engine()

# Request schemas
class TrainRequest(BaseModel):
    traces: List[List[str]]
    smoothing: float = 0.01

class BenchmarkRequest(BaseModel):
    normal_traces: List[List[Dict[str, Any]]]
    anomalous_traces: List[List[Dict[str, Any]]]

# --- API Endpoints ---

@app.get("/health")
def health():
    return {"status": "healthy", "engine": engine.lifecycle.current.value if engine else "uninitialized"}


@app.post("/train")
def train_model(payload: TrainRequest):
    global current_model
    try:
        model = MarkovModel(smoothing=payload.smoothing)
        model.train(payload.traces)
        os.makedirs(".runtimeverify/models", exist_ok=True)
        model.save(".runtimeverify/models/default.json")
        
        # Re-initialize the active engine with the newly trained model
        initialize_engine(".runtimeverify/models/default.json")
        return {"status": "success", "states_vocabulary": list(model.trainer.counter.states)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Training error: {e}")


@app.post("/monitor")
def monitor_event(event_dict: Dict[str, Any]):
    global engine
    if not engine:
        raise HTTPException(status_code=500, detail="Runtime Engine not initialized.")
        
    try:
        # Re-construct concrete Event subclasses
        from runtimeverify.events import ToolEvent, FilesystemEvent, NetworkEvent, LLMEvent
        event_id = event_dict.get("id")
        session_id = event_dict.get("session_id")
        agent_id = event_dict.get("agent_id")
        event_type = event_dict.get("type", "generic")
        
        if not session_id or not agent_id:
            raise HTTPException(status_code=400, detail="Missing session_id or agent_id.")

        event_kwargs = {
            "session_id": session_id,
            "agent_id": agent_id,
            "metadata": event_dict.get("metadata", {})
        }
        if event_id is not None:
            event_kwargs["id"] = event_id

        if event_type == "tool":
            event = ToolEvent(
                tool_name=event_dict.get("tool_name") or "unknown_tool",
                arguments=event_dict.get("arguments") or {},
                status=event_dict.get("status", "success"),
                **event_kwargs
            )
        elif event_type == "filesystem":
            event = FilesystemEvent(
                action=event_dict.get("action") or "read",
                path=event_dict.get("path") or "",
                status=event_dict.get("status", "success"),
                **event_kwargs
            )
        elif event_type == "network":
            event = NetworkEvent(
                action=event_dict.get("action") or "connect",
                url=event_dict.get("url") or "",
                method=event_dict.get("method") or "GET",
                status_code=event_dict.get("status_code"),
                **event_kwargs
            )
        elif event_type == "llm":
            event = LLMEvent(
                model=event_dict.get("model") or "gpt-4",
                prompt=event_dict.get("prompt"),
                response=event_dict.get("response"),
                **event_kwargs
            )
        else:
            event = Event(
                type=event_type,
                **event_kwargs
            )

        decision = engine.observe(event)
        
        # Store in caches
        decision_data = decision.model_dump()
        decision_data["event"] = event.model_dump()
        
        decisions_cache[event.id] = decision_data
        if session_id not in session_db:
            session_db[session_id] = []
        session_db[session_id].append({
            "event": event.model_dump(),
            "decision": decision.model_dump()
        })
        
        return decision_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failure: {e}")


@app.get("/session/{session_id}")
def get_session_history(session_id: str):
    if session_id not in session_db:
        raise HTTPException(status_code=404, detail="Session trace history not found.")
    return session_db[session_id]


@app.get("/decision/{decision_id}")
def get_decision(decision_id: str):
    if decision_id not in decisions_cache:
        raise HTTPException(status_code=404, detail="Decision log entry not found.")
    return decisions_cache[decision_id]


@app.get("/recent_decisions")
def get_recent_decisions():
    # Return all decisions, newest first
    return list(decisions_cache.values())


@app.get("/metrics")
def get_metrics():
    # Return aggregated statistical execution records
    total_decisions = len(decisions_cache)
    anomalies = sum(1 for d in decisions_cache.values() if d.get("status") == "BLOCK")
    
    return {
        "total_events_processed": total_decisions,
        "anomalies_detected": anomalies,
        "significance_alpha": 0.05,
        "significance_beta": 0.05,
    }

# Mount static files for HTML Dashboard
dashboard_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard")
if os.path.exists(dashboard_dir):
    app.mount("/", StaticFiles(directory=dashboard_dir, html=True), name="dashboard")
