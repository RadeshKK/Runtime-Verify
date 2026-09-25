"""
Configuration models for Audit Logging and Retention (Phase 8).
"""

from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class AuditRetentionConfig(BaseModel):
    """
    Configuration parameters governing audit record retention and storage limits.
    """

    model_config = ConfigDict(frozen=True)

    enabled: bool = Field(True, description="Enable structured audit record generation")
    log_path: str = Field(".runtimeverify/audit.log", description="Default file destination for NDJSON audit logs")
    max_age_days: Optional[int] = Field(30, ge=1, description="Maximum age in days before audit records are pruned")
    max_records: Optional[int] = Field(
        100000, ge=100, description="Maximum total records retained before oldest are pruned"
    )
    redaction_enabled: bool = Field(True, description="Enable automatic secret and credential redaction")
    sink_type: str = Field("file", description="Primary audit sink type: 'file', 'memory', 'console'")
