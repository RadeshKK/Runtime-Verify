from datetime import datetime, timezone
from typing import Dict, Any, List
from pydantic import BaseModel, Field

class ExecutionContext(BaseModel):
    """
    Data model representing the active execution context inside the runtime pipeline.
    Passed through pipeline stages to coordinate processing parameters.
    """
    session_id: str = Field(..., description="Unique ID of the active agent session")
    agent_id: str = Field(..., description="Unique ID of the agent being monitored")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom metadata variables")


class Decision(BaseModel):
    """
    Structured response returned by the runtime pipeline after checking policies.
    Provides auditable evidence and safety classifications rather than a simple boolean flag.
    """
    session_id: str = Field(..., description="The session ID associated with this evaluation")
    agent_id: str = Field(..., description="The agent ID associated with this evaluation")
    status: str = Field(..., description="Mitigation status action determined by policies (e.g., ALLOW, ALERT, BLOCK, PAUSE)")
    confidence: float = Field(default=1.0, description="Aggregated confidence metric across statistical evaluations")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic evidence triggering any deviations")
    detector_results: Dict[str, Any] = Field(default_factory=dict, description="Raw outputs from all executed detectors")
    triggered_policies: List[str] = Field(default_factory=list, description="List of rule/policy names violated")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Evaluation timestamp")
