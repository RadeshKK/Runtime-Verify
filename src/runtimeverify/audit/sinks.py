"""
Audit Sinks for RuntimeVerify (Phase 8).
Provides vendor-neutral broadcast destinations for structured audit events:
Memory, Local File (NDJSON), Console, and extensible adapters for PostgreSQL, S3, and SIEM.
"""

from abc import ABC, abstractmethod
import logging
from pathlib import Path
import threading
from typing import Callable, List, Optional

from runtimeverify.audit.models import AuditRecord
from runtimeverify.audit.redaction import SecretRedactor

logger = logging.getLogger(__name__)


class AuditSink(ABC):
    """
    Vendor-neutral sink abstraction for persisting or streaming structured audit records.
    """

    def __init__(self, redactor: Optional[SecretRedactor] = None):
        self.redactor = redactor or SecretRedactor()

    @abstractmethod
    def emit(self, record: AuditRecord) -> None:
        """Emits a single sanitized audit record to the destination."""
        pass

    def flush(self) -> None:
        """Flushes buffered records to the persistent backend."""
        pass

    def close(self) -> None:
        """Closes any open resources or network sockets."""
        pass

    def _sanitize(self, record: AuditRecord) -> AuditRecord:
        """Ensures that any record emitted has undergone secret redaction."""
        if record.redacted:
            return record

        sanitized_details, det_mod = self.redactor.redact(record.details)
        sanitized_summary, sum_mod = self.redactor.redact(record.summary)
        sanitized_meta, meta_mod = self.redactor.redact(record.metadata)

        if det_mod or sum_mod or meta_mod:
            # Reconstruct record with sanitized payload and redacted flag
            return AuditRecord(
                record_id=record.record_id,
                timestamp=record.timestamp,
                record_type=record.record_type,
                severity=record.severity,
                trace_id=record.trace_id,
                session_id=record.session_id,
                event_id=record.event_id,
                agent_id=record.agent_id,
                span_id=record.span_id,
                action_id=record.action_id,
                summary=sanitized_summary,
                details=sanitized_details,
                environment=record.environment,
                metadata=sanitized_meta,
                redacted=True,
            )
        return record


class MemoryAuditSink(AuditSink):
    """
    In-memory audit sink suitable for testing, ephemeral debugging, and immediate inspection.
    """

    def __init__(self, redactor: Optional[SecretRedactor] = None):
        super().__init__(redactor=redactor)
        self._lock = threading.Lock()
        self._records: List[AuditRecord] = []

    def emit(self, record: AuditRecord) -> None:
        sanitized = self._sanitize(record)
        with self._lock:
            self._records.append(sanitized)

    @property
    def records(self) -> List[AuditRecord]:
        with self._lock:
            return list(self._records)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()


class FileAuditSink(AuditSink):
    """
    Appends audit records to a local file in Newline-Delimited JSON (NDJSON) format.
    Thread-safe and durable.
    """

    def __init__(
        self,
        file_path: str = ".runtimeverify/audit.log",
        redactor: Optional[SecretRedactor] = None,
        auto_flush: bool = True,
    ):
        super().__init__(redactor=redactor)
        self.file_path = Path(file_path)
        self.auto_flush = auto_flush
        self._lock = threading.Lock()
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, record: AuditRecord) -> None:
        sanitized = self._sanitize(record)
        line = sanitized.to_ndjson() + "\n"
        with self._lock:
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(line)
                if self.auto_flush:
                    f.flush()


class ConsoleAuditSink(AuditSink):
    """
    Streams structured audit logs to standard output or logging handlers.
    """

    def __init__(
        self,
        output_fn: Optional[Callable[[str], None]] = None,
        redactor: Optional[SecretRedactor] = None,
        as_json: bool = True,
    ):
        super().__init__(redactor=redactor)
        self.output_fn = output_fn or print
        self.as_json = as_json

    def emit(self, record: AuditRecord) -> None:
        sanitized = self._sanitize(record)
        if self.as_json:
            self.output_fn(sanitized.to_ndjson())
        else:
            self.output_fn(
                f"[{sanitized.timestamp.isoformat()}] [{sanitized.severity.value}] {sanitized.record_type.value}: {sanitized.summary}"
            )


class CompositeAuditSink(AuditSink):
    """
    Broadcasts audit records to multiple sinks simultaneously.
    """

    def __init__(self, sinks: List[AuditSink], redactor: Optional[SecretRedactor] = None):
        super().__init__(redactor=redactor)
        self.sinks = list(sinks)

    def add_sink(self, sink: AuditSink) -> None:
        self.sinks.append(sink)

    def emit(self, record: AuditRecord) -> None:
        sanitized = self._sanitize(record)
        for sink in self.sinks:
            try:
                sink.emit(sanitized)
            except Exception as e:
                logger.error("Failed to emit audit record to %s: %s", type(sink).__name__, e)

    def flush(self) -> None:
        for sink in self.sinks:
            try:
                sink.flush()
            except Exception as e:
                logger.error("Failed to flush %s: %s", type(sink).__name__, e)

    def close(self) -> None:
        for sink in self.sinks:
            try:
                sink.close()
            except Exception as e:
                logger.error("Failed to close %s: %s", type(sink).__name__, e)


# -------------------------------------------------------------
# Enterprise Backend Adapter Stubs (PostgreSQL, Object Storage, SIEM)
# -------------------------------------------------------------


class PostgresAuditSink(AuditSink):
    """
    Enterprise adapter for streaming audit records to a PostgreSQL database table.
    """

    def __init__(
        self,
        connection_uri: str,
        table_name: str = "runtimeverify_audit_log",
        redactor: Optional[SecretRedactor] = None,
        batch_size: int = 100,
    ):
        super().__init__(redactor=redactor)
        self.connection_uri = connection_uri
        self.table_name = table_name
        self.batch_size = batch_size
        self._buffer: List[AuditRecord] = []
        self._lock = threading.Lock()

    def emit(self, record: AuditRecord) -> None:
        sanitized = self._sanitize(record)
        with self._lock:
            self._buffer.append(sanitized)
            if len(self._buffer) >= self.batch_size:
                self.flush()

    def flush(self) -> None:
        with self._lock:
            if not self._buffer:
                return
            # Flush batch to postgresql table
            logger.debug("Flushing %d audit records to PostgreSQL table '%s'", len(self._buffer), self.table_name)
            self._buffer.clear()


class ObjectStorageAuditSink(AuditSink):
    """
    Enterprise adapter for periodically flushing batched NDJSON chunks to S3/GCS.
    """

    def __init__(
        self,
        bucket_name: str,
        prefix: str = "audit-logs/",
        redactor: Optional[SecretRedactor] = None,
    ):
        super().__init__(redactor=redactor)
        self.bucket_name = bucket_name
        self.prefix = prefix
        self._buffer: List[AuditRecord] = []
        self._lock = threading.Lock()

    def emit(self, record: AuditRecord) -> None:
        sanitized = self._sanitize(record)
        with self._lock:
            self._buffer.append(sanitized)

    def flush(self) -> None:
        with self._lock:
            if not self._buffer:
                return
            logger.debug(
                "Flushing %d audit records to bucket '%s/%s'", len(self._buffer), self.bucket_name, self.prefix
            )
            self._buffer.clear()


class SIEMAuditSink(AuditSink):
    """
    Enterprise adapter for forwarding audit records via HTTP Event Collector (HEC) / Syslog
    to SIEM solutions (Splunk, Elastic, Datadog, Sumo Logic).
    """

    def __init__(
        self,
        endpoint_url: str,
        auth_token: Optional[str] = None,
        redactor: Optional[SecretRedactor] = None,
    ):
        super().__init__(redactor=redactor)
        self.endpoint_url = endpoint_url
        self.auth_token = auth_token

    def emit(self, record: AuditRecord) -> None:
        sanitized = self._sanitize(record)
        # Forward sanitized JSON to SIEM webhook
        logger.debug("Forwarding audit record '%s' to SIEM endpoint '%s'", sanitized.record_id, self.endpoint_url)
