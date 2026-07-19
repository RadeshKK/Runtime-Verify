from pydantic import BaseModel, Field, ConfigDict
from typing import Dict, List, Optional, Any
from datetime import datetime

class ExperimentConfig(BaseModel):
    """Configuration for a specific evaluation run."""
    model_config = ConfigDict(frozen=True)

    experiment_name: str
    dataset_name: str
    detector_type: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    alpha: float = 0.01
    beta: float = 0.01
    expected_anomaly_index: Optional[int] = None

class MetricResult(BaseModel):
    """Statistical results for a single detector evaluation."""
    model_config = ConfigDict(frozen=True)

    fpr: float = 0.0
    fnr: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    avg_detection_delay: float = 0.0  # Number of steps after anomaly start until detection
    runtime_ms: float = 0.0
    memory_usage_mb: float = 0.0
    throughput_events_per_sec: float = 0.0

class EvaluationReport(BaseModel):
    """Complete report for an evaluation experiment."""
    model_config = ConfigDict(frozen=True)

    timestamp: datetime = Field(default_factory=lambda: datetime.now())
    config: ExperimentConfig
    metrics: MetricResult
    detector_metadata: Dict[str, Any]
