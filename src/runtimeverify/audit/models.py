"""
Data models and typed schemas for Structured Audit Records (Phase 8).
Supports correlation across trace_id, session_id, event_id, and agent_id.
"""

from datetime import datetime, timezone
from enum import Enum
import json
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class AuditRecordType(str, Enum):
    """Categorical taxonomy of verifiable audit records."""

    EVENT = "EVENT"
    POLICY_DECISION = "POLICY_DECISION"
    SEMANTIC_DECISION = "SEMANTIC_DECISION"
    BEHAVIORAL_DECISION = "BEHAVIORAL_DECISION"
    SPRT_STATE_CHANGE = "SPRT_STATE_CHANGE"
    APPROVAL_REQUEST = "APPROVAL_REQUEST"
    APPROVAL_DECISION = "APPROVAL_DECISION"
    EXECUTION_RESULT = "EXECUTION_RESULT"
    ERROR = "ERROR"


class AuditSeverity(str, Enum):
    """Security classification severity levels for audit entries."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    WARNING = "WARNING"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AuditRecord(BaseModel):
    """
    Immutable, structured audit record capturing decisions, state changes, and evidence.
    Guarantees correlation across trace, session, agent, and event dimensions.
    """

    model_config = ConfigDict(frozen=True)

    record_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Globally unique identifier for the audit record",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the audited event",
    )
    record_type: AuditRecordType = Field(..., description="Operational category of the record")
    severity: AuditSeverity = Field(AuditSeverity.INFO, description="Assessed severity level")

    # Correlation IDs
    trace_id: Optional[str] = Field(None, description="Distributed correlation trace ID")
    session_id: Optional[str] = Field(None, description="Agent interaction session identifier")
    event_id: Optional[str] = Field(None, description="Correlated canonical telemetry event ID")
    agent_id: Optional[str] = Field(None, description="Identifier of the autonomous agent")
    span_id: Optional[str] = Field(None, description="Sub-operation span identifier")
    action_id: Optional[str] = Field(None, description="Correlated intercepted action ID")

    # Content & Audit Payload
    summary: str = Field(..., description="Concise human-readable explanation of the record")
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured context (decisions, metrics, inputs, results, errors)",
    )
    environment: Optional[str] = Field(None, description="Target environment (e.g. production, staging, sandbox)")
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extensible contextual attributes (host, framework, process PID)",
    )
    redacted: bool = Field(False, description="Flag indicating if secrets or sensitive credentials were sanitized")
    record_hash: Optional[str] = Field(None, description="Cryptographic SHA-256 hash of this record")
    prev_hash: Optional[str] = Field(None, description="Cryptographic hash of the immediately preceding audit record")

    def compute_hash(self, prev_hash: Optional[str] = None) -> str:
        """Computes the cryptographic SHA-256 record hash."""
        from runtimeverify.security.audit_integrity import AuditIntegrityEngine

        return AuditIntegrityEngine.compute_record_hash(
            record_id=self.record_id,
            timestamp_iso=self.timestamp.isoformat(),
            record_type=self.record_type.value,
            summary=self.summary,
            details=self.details,
            prev_hash=prev_hash or self.prev_hash,
        )

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serializes the record to a standard JSON string."""
        return self.model_dump_json(indent=indent)

    def to_ndjson(self) -> str:
        """Serializes the record as a single-line newline-delimited JSON string."""
        return json.dumps(self.model_dump(mode="json"), separators=(",", ":"))
