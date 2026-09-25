"""
Structured Audit and Observability package for RuntimeVerify (Phase 8).
Provides tamper-evident audit records, secret redaction, multi-destination sinks,
and retention management.
"""

from runtimeverify.audit.config import AuditRetentionConfig
from runtimeverify.audit.models import AuditRecord, AuditRecordType, AuditSeverity
from runtimeverify.audit.redaction import SecretRedactor, redact_secrets
from runtimeverify.audit.repository import (
    AuditRepository,
    FileAuditRepository,
    MemoryAuditRepository,
)
from runtimeverify.audit.service import (
    AuditService,
    get_default_audit_service,
    set_default_audit_service,
)
from runtimeverify.audit.sinks import (
    AuditSink,
    CompositeAuditSink,
    ConsoleAuditSink,
    FileAuditSink,
    MemoryAuditSink,
    ObjectStorageAuditSink,
    PostgresAuditSink,
    SIEMAuditSink,
)

__all__ = [
    "AuditRecord",
    "AuditRecordType",
    "AuditRepository",
    "AuditRetentionConfig",
    "AuditService",
    "AuditSeverity",
    "AuditSink",
    "CompositeAuditSink",
    "ConsoleAuditSink",
    "FileAuditRepository",
    "FileAuditSink",
    "MemoryAuditRepository",
    "MemoryAuditSink",
    "ObjectStorageAuditSink",
    "PostgresAuditSink",
    "SIEMAuditSink",
    "SecretRedactor",
    "get_default_audit_service",
    "redact_secrets",
    "set_default_audit_service",
]
