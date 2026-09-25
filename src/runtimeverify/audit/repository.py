"""
Audit Repository and retention enforcement for RuntimeVerify (Phase 8).
Provides structured query capabilities by trace_id, session_id, agent_id, and time range,
along with configurable time-based and volume-based retention pruning.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
import threading
from typing import List, Optional, Tuple

from runtimeverify.audit.models import AuditRecord, AuditRecordType, AuditSeverity

logger = logging.getLogger(__name__)


class AuditRepository(ABC):
    """
    Abstract interface for querying, aggregating, and managing retention of audit records.
    """

    @abstractmethod
    def store(self, record: AuditRecord) -> None:
        """Saves an audit record."""
        pass

    @abstractmethod
    def get(self, record_id: str) -> Optional[AuditRecord]:
        """Fetches an audit record by its unique ID."""
        pass

    @abstractmethod
    def query(
        self,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        event_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        record_type: Optional[AuditRecordType] = None,
        severity: Optional[AuditSeverity] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[AuditRecord]:
        """Queries audit records matching correlation filters."""
        pass

    @abstractmethod
    def count(self) -> int:
        """Returns the total number of stored audit records."""
        pass

    @abstractmethod
    def apply_retention(
        self,
        max_age_days: Optional[int] = None,
        max_records: Optional[int] = None,
    ) -> int:
        """
        Prunes records older than max_age_days or in excess of max_records.
        Returns the number of pruned records.
        """
        pass

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """
        Verifies the cryptographic hash chain integrity of all stored records.
        Returns (is_valid: bool, issues: List[str]).
        """
        from runtimeverify.security.audit_integrity import AuditIntegrityEngine

        records = sorted(self.query(limit=None), key=lambda x: x.timestamp)
        return AuditIntegrityEngine.verify_chain(records)


class MemoryAuditRepository(AuditRepository):
    """
    In-memory audit repository providing multi-dimensional correlation queries.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._records: List[AuditRecord] = []
        self._last_hash: Optional[str] = None

    def store(self, record: AuditRecord) -> None:
        with self._lock:
            to_store = record
            if to_store.record_hash is None:
                prev_h = self._last_hash
                computed_h = to_store.compute_hash(prev_hash=prev_h)
                to_store = to_store.model_copy(update={"record_hash": computed_h, "prev_hash": prev_h})
                self._last_hash = computed_h
            else:
                self._last_hash = to_store.record_hash
            self._records.append(to_store)

    def get(self, record_id: str) -> Optional[AuditRecord]:
        with self._lock:
            for r in self._records:
                if r.record_id == record_id:
                    return r
            return None

    def query(
        self,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        event_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        record_type: Optional[AuditRecordType] = None,
        severity: Optional[AuditSeverity] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[AuditRecord]:
        with self._lock:
            results: List[AuditRecord] = []
            for r in self._records:
                if trace_id is not None and r.trace_id != trace_id:
                    continue
                if session_id is not None and r.session_id != session_id:
                    continue
                if event_id is not None and r.event_id != event_id:
                    continue
                if agent_id is not None and r.agent_id != agent_id:
                    continue
                if record_type is not None and r.record_type != record_type:
                    continue
                if severity is not None and r.severity != severity:
                    continue

                rec_time = r.timestamp if r.timestamp.tzinfo else r.timestamp.replace(tzinfo=timezone.utc)
                if start_time is not None:
                    st_time = start_time if start_time.tzinfo else start_time.replace(tzinfo=timezone.utc)
                    if rec_time < st_time:
                        continue
                if end_time is not None:
                    et_time = end_time if end_time.tzinfo else end_time.replace(tzinfo=timezone.utc)
                    if rec_time > et_time:
                        continue

                results.append(r)

            # Sort newest first
            sorted_res = sorted(results, key=lambda x: x.timestamp, reverse=True)
            if limit is not None:
                return sorted_res[:limit]
            return sorted_res

    def count(self) -> int:
        with self._lock:
            return len(self._records)

    def apply_retention(
        self,
        max_age_days: Optional[int] = None,
        max_records: Optional[int] = None,
    ) -> int:
        with self._lock:
            initial_count = len(self._records)
            now = datetime.now(timezone.utc)

            survivors = list(self._records)

            # 1. Time-based retention pruning
            if max_age_days is not None and max_age_days > 0:
                cutoff = now - timedelta(days=max_age_days)
                survivors = [
                    r
                    for r in survivors
                    if (r.timestamp if r.timestamp.tzinfo else r.timestamp.replace(tzinfo=timezone.utc)) >= cutoff
                ]

            # 2. Volume-based retention pruning (retain newest max_records)
            if max_records is not None and max_records > 0:
                if len(survivors) > max_records:
                    survivors = sorted(survivors, key=lambda x: x.timestamp, reverse=True)[:max_records]

            pruned_count = initial_count - len(survivors)
            self._records = survivors
            return pruned_count


class FileAuditRepository(AuditRepository):
    """
    Durable NDJSON file-backed audit repository.
    """

    def __init__(self, log_path: str = ".runtimeverify/audit.log"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._last_hash: Optional[str] = None

    def _read_records(self) -> List[AuditRecord]:
        if not self.log_path.exists():
            return []
        records = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        records.append(AuditRecord.model_validate(json.loads(line)))
        except Exception as e:
            logger.warning("Error reading audit records from '%s': %s", self.log_path, e)
        return records

    def _write_records(self, records: List[AuditRecord]) -> None:
        temp_path = self.log_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(r.to_ndjson() + "\n")
        temp_path.replace(self.log_path)
        if records and records[-1].record_hash:
            self._last_hash = records[-1].record_hash

    def store(self, record: AuditRecord) -> None:
        with self._lock:
            to_store = record
            if to_store.record_hash is None:
                if self._last_hash is None and self.log_path.exists():
                    existing = self._read_records()
                    if existing and existing[-1].record_hash:
                        self._last_hash = existing[-1].record_hash

                prev_h = self._last_hash
                computed_h = to_store.compute_hash(prev_hash=prev_h)
                to_store = to_store.model_copy(update={"record_hash": computed_h, "prev_hash": prev_h})
                self._last_hash = computed_h
            else:
                self._last_hash = to_store.record_hash

            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(to_store.to_ndjson() + "\n")

    def get(self, record_id: str) -> Optional[AuditRecord]:
        with self._lock:
            for r in self._read_records():
                if r.record_id == record_id:
                    return r
            return None

    def query(
        self,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        event_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        record_type: Optional[AuditRecordType] = None,
        severity: Optional[AuditSeverity] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[AuditRecord]:
        with self._lock:
            records = self._read_records()
            results = []
            for r in records:
                if trace_id is not None and r.trace_id != trace_id:
                    continue
                if session_id is not None and r.session_id != session_id:
                    continue
                if event_id is not None and r.event_id != event_id:
                    continue
                if agent_id is not None and r.agent_id != agent_id:
                    continue
                if record_type is not None and r.record_type != record_type:
                    continue
                if severity is not None and r.severity != severity:
                    continue

                rec_time = r.timestamp if r.timestamp.tzinfo else r.timestamp.replace(tzinfo=timezone.utc)
                if start_time is not None:
                    st_time = start_time if start_time.tzinfo else start_time.replace(tzinfo=timezone.utc)
                    if rec_time < st_time:
                        continue
                if end_time is not None:
                    et_time = end_time if end_time.tzinfo else end_time.replace(tzinfo=timezone.utc)
                    if rec_time > et_time:
                        continue

                results.append(r)

            sorted_res = sorted(results, key=lambda x: x.timestamp, reverse=True)
            if limit is not None:
                return sorted_res[:limit]
            return sorted_res

    def count(self) -> int:
        with self._lock:
            return len(self._read_records())

    def apply_retention(
        self,
        max_age_days: Optional[int] = None,
        max_records: Optional[int] = None,
    ) -> int:
        with self._lock:
            records = self._read_records()
            initial_count = len(records)
            now = datetime.now(timezone.utc)

            survivors = list(records)

            if max_age_days is not None and max_age_days > 0:
                cutoff = now - timedelta(days=max_age_days)
                survivors = [
                    r
                    for r in survivors
                    if (r.timestamp if r.timestamp.tzinfo else r.timestamp.replace(tzinfo=timezone.utc)) >= cutoff
                ]

            if max_records is not None and max_records > 0:
                if len(survivors) > max_records:
                    # Retain newest
                    survivors = sorted(survivors, key=lambda x: x.timestamp, reverse=True)[:max_records]
                    # Keep chronological order in file
                    survivors = sorted(survivors, key=lambda x: x.timestamp)

            pruned = initial_count - len(survivors)
            if pruned > 0:
                self._write_records(survivors)
            return pruned

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """
        Verifies the cryptographic hash chain integrity of all records in the file,
        flagging any unparseable or corrupted lines as tampering violations.
        """
        from runtimeverify.security.audit_integrity import AuditIntegrityEngine

        with self._lock:
            if not self.log_path.exists():
                return True, []
            records = []
            issues = []
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    for line_no, line in enumerate(f, start=1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            records.append(AuditRecord.model_validate(json.loads(line)))
                        except Exception as e:
                            issues.append(f"Line {line_no} contains unparseable or corrupted record: {e}")
            except Exception as e:
                return False, [f"Error accessing file: {e}"]

            if issues:
                return False, issues

            return AuditIntegrityEngine.verify_chain(records)
