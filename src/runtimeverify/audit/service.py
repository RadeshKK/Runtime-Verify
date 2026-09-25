"""
Audit Service for RuntimeVerify (Phase 8).
Provides structured logging for events, policy decisions, semantic signals,
behavioral transitions, SPRT state changes, approval requests, execution results, and errors.
"""

import logging
import threading
from typing import Any, Dict, Optional

from runtimeverify.audit.models import AuditRecord, AuditRecordType, AuditSeverity
from runtimeverify.audit.redaction import SecretRedactor
from runtimeverify.audit.repository import AuditRepository, FileAuditRepository
from runtimeverify.audit.sinks import AuditSink, FileAuditSink

logger = logging.getLogger(__name__)


class AuditService:
    """
    Unified audit logging service.
    Guarantees that all decisions, state transitions, approvals, and errors are
    sanitized of secrets, correlated across traces/sessions, and dispatched to configured sinks.
    """

    def __init__(
        self,
        sink: Optional[AuditSink] = None,
        repository: Optional[AuditRepository] = None,
        redactor: Optional[SecretRedactor] = None,
    ):
        self.redactor = redactor or SecretRedactor()
        self.sink = sink or FileAuditSink(redactor=self.redactor)
        self.repository = repository or (FileAuditRepository() if isinstance(self.sink, FileAuditSink) else None)

    def emit_record(self, record: AuditRecord) -> AuditRecord:
        """Sanitizes and dispatches an audit record to the sink and repository."""
        # Sanitize details, summary, and metadata
        sanitized_details, det_mod = self.redactor.redact(record.details)
        sanitized_summary, sum_mod = self.redactor.redact(record.summary)
        sanitized_meta, meta_mod = self.redactor.redact(record.metadata)

        final_record = AuditRecord(
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
            redacted=record.redacted or det_mod or sum_mod or meta_mod,
        )

        try:
            self.sink.emit(final_record)
        except Exception as e:
            logger.error("Failed to emit audit record to sink: %s", e)

        if self.repository is not None and not isinstance(self.sink, FileAuditSink):
            try:
                self.repository.store(final_record)
            except Exception as e:
                logger.error("Failed to store audit record in repository: %s", e)

        return final_record

    def log_event(
        self,
        summary: str,
        event_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        action_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        environment: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Audits an incoming telemetry or agent action event."""
        record = AuditRecord(
            record_type=AuditRecordType.EVENT,
            severity=severity,
            summary=summary,
            event_id=event_id,
            trace_id=trace_id,
            session_id=session_id,
            agent_id=agent_id,
            action_id=action_id,
            details=details or {},
            environment=environment,
            metadata=metadata or {},
        )
        return self.emit_record(record)

    def log_policy_decision(
        self,
        decision_verdict: str,
        policy_id: str,
        reason: str,
        severity_str: str = "INFO",
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        event_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        action_id: Optional[str] = None,
        matched_rule: Optional[Dict[str, Any]] = None,
        details: Optional[Dict[str, Any]] = None,
        environment: Optional[str] = None,
    ) -> AuditRecord:
        """Audits a deterministic policy engine evaluation."""
        sev = AuditSeverity.INFO
        if severity_str.upper() in AuditSeverity.__members__:
            sev = AuditSeverity[severity_str.upper()]

        d = details or {}
        d.update(
            {
                "decision": decision_verdict,
                "policy_id": policy_id,
                "reason": reason,
                "matched_rule": matched_rule,
            }
        )
        record = AuditRecord(
            record_type=AuditRecordType.POLICY_DECISION,
            severity=sev,
            summary=f"Policy '{policy_id}' evaluated to {decision_verdict}: {reason}",
            trace_id=trace_id,
            session_id=session_id,
            event_id=event_id,
            agent_id=agent_id,
            action_id=action_id,
            details=d,
            environment=environment,
        )
        return self.emit_record(record)

    def log_semantic_decision(
        self,
        engine_name: str,
        decision_signal: str,
        risk_level: str,
        confidence: float,
        explanation: Optional[str] = None,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        action_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        environment: Optional[str] = None,
    ) -> AuditRecord:
        """Audits a semantic model evaluation (e.g. Laya)."""
        sev = AuditSeverity.INFO
        if risk_level.upper() in AuditSeverity.__members__:
            sev = AuditSeverity[risk_level.upper()]

        d = details or {}
        d.update(
            {
                "engine_name": engine_name,
                "decision_signal": decision_signal,
                "risk_level": risk_level,
                "confidence": confidence,
                "explanation": explanation,
            }
        )
        record = AuditRecord(
            record_type=AuditRecordType.SEMANTIC_DECISION,
            severity=sev,
            summary=f"Semantic engine '{engine_name}' assessed {risk_level} risk ({confidence:.2f} conf) -> {decision_signal}",
            trace_id=trace_id,
            session_id=session_id,
            agent_id=agent_id,
            action_id=action_id,
            details=d,
            environment=environment,
        )
        return self.emit_record(record)

    def log_behavioral_decision(
        self,
        from_state: Optional[str],
        to_state: str,
        transition_prob: float,
        is_anomaly: bool,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        action_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        environment: Optional[str] = None,
    ) -> AuditRecord:
        """Audits a Markov state transition probability and anomaly detection decision."""
        sev = AuditSeverity.HIGH if is_anomaly else AuditSeverity.LOW
        d = details or {}
        d.update(
            {
                "from_state": from_state,
                "to_state": to_state,
                "transition_probability": transition_prob,
                "is_anomaly": is_anomaly,
            }
        )
        summary = (
            f"Behavioral Anomaly detected: transition '{from_state}' -> '{to_state}' prob {transition_prob:.4e} below baseline"
            if is_anomaly
            else f"Behavioral Transition: '{from_state}' -> '{to_state}' (P={transition_prob:.4f})"
        )
        record = AuditRecord(
            record_type=AuditRecordType.BEHAVIORAL_DECISION,
            severity=sev,
            summary=summary,
            trace_id=trace_id,
            session_id=session_id,
            agent_id=agent_id,
            action_id=action_id,
            details=d,
            environment=environment,
        )
        return self.emit_record(record)

    def log_sprt_state_change(
        self,
        status: str,
        log_likelihood_ratio: float,
        observation_count: int,
        is_drift: bool,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        environment: Optional[str] = None,
    ) -> AuditRecord:
        """Audits sequential SPRT statistical test status and threshold crossing."""
        sev = AuditSeverity.CRITICAL if is_drift else AuditSeverity.INFO
        d = details or {}
        d.update(
            {
                "sprt_status": status,
                "log_likelihood_ratio": log_likelihood_ratio,
                "observation_count": observation_count,
                "is_drift": is_drift,
            }
        )
        summary = (
            f"SPRT Drift Alert: status '{status}' LLR={log_likelihood_ratio:.4f} crossed Wald threshold at step {observation_count}"
            if is_drift
            else f"SPRT Update: status '{status}' LLR={log_likelihood_ratio:.4f} (step {observation_count})"
        )
        record = AuditRecord(
            record_type=AuditRecordType.SPRT_STATE_CHANGE,
            severity=sev,
            summary=summary,
            trace_id=trace_id,
            session_id=session_id,
            agent_id=agent_id,
            details=d,
            environment=environment,
        )
        return self.emit_record(record)

    def log_approval_request(
        self,
        request_id: str,
        reason: str,
        risk: str,
        expiration_iso: str,
        action_type: str,
        target: str,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        action_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        environment: Optional[str] = None,
    ) -> AuditRecord:
        """Audits a human approval request creation."""
        sev = AuditSeverity.HIGH if risk == "CRITICAL" else AuditSeverity.MEDIUM
        d = details or {}
        d.update(
            {
                "request_id": request_id,
                "reason": reason,
                "risk": risk,
                "expiration": expiration_iso,
                "action_type": action_type,
                "target": target,
            }
        )
        record = AuditRecord(
            record_type=AuditRecordType.APPROVAL_REQUEST,
            severity=sev,
            summary=f"Approval Request '{request_id}' created for {action_type} on '{target}' (Expires: {expiration_iso})",
            trace_id=trace_id,
            session_id=session_id,
            agent_id=agent_id,
            action_id=action_id,
            details=d,
            environment=environment,
        )
        return self.emit_record(record)

    def log_approval_decision(
        self,
        request_id: str,
        verdict: str,
        decided_by: str,
        reason: Optional[str] = None,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        action_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        environment: Optional[str] = None,
    ) -> AuditRecord:
        """Audits a human reviewer's APPROVE or DENY decision."""
        sev = AuditSeverity.INFO if verdict == "APPROVE" else AuditSeverity.HIGH
        d = details or {}
        d.update(
            {
                "request_id": request_id,
                "verdict": verdict,
                "decided_by": decided_by,
                "reason": reason,
            }
        )
        record = AuditRecord(
            record_type=AuditRecordType.APPROVAL_DECISION,
            severity=sev,
            summary=f"Approval Request '{request_id}' decided: {verdict} by {decided_by}",
            trace_id=trace_id,
            session_id=session_id,
            agent_id=agent_id,
            action_id=action_id,
            details=d,
            environment=environment,
        )
        return self.emit_record(record)

    def log_execution_result(
        self,
        action_id: str,
        success: bool,
        output: Any,
        duration_ms: float = 0.0,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        environment: Optional[str] = None,
    ) -> AuditRecord:
        """Audits the execution result of an authorized action."""
        sev = AuditSeverity.INFO if success else AuditSeverity.HIGH
        d = details or {}
        d.update(
            {
                "action_id": action_id,
                "success": success,
                "output": output,
                "duration_ms": duration_ms,
            }
        )
        record = AuditRecord(
            record_type=AuditRecordType.EXECUTION_RESULT,
            severity=sev,
            summary=f"Action '{action_id}' executed: {'SUCCESS' if success else 'FAILED'} in {duration_ms:.2f}ms",
            trace_id=trace_id,
            session_id=session_id,
            agent_id=agent_id,
            action_id=action_id,
            details=d,
            environment=environment,
        )
        return self.emit_record(record)

    def log_error(
        self,
        error_type: str,
        error_message: str,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        action_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.CRITICAL,
        environment: Optional[str] = None,
    ) -> AuditRecord:
        """Audits an interception, security, or evaluation error."""
        d = details or {}
        d.update(
            {
                "error_type": error_type,
                "error_message": error_message,
            }
        )
        record = AuditRecord(
            record_type=AuditRecordType.ERROR,
            severity=severity,
            summary=f"Error [{error_type}]: {error_message}",
            trace_id=trace_id,
            session_id=session_id,
            agent_id=agent_id,
            action_id=action_id,
            details=d,
            environment=environment,
        )
        return self.emit_record(record)


# Global service access
_default_audit_service: Optional[AuditService] = None
_audit_service_lock = threading.Lock()


def get_default_audit_service(log_path: Optional[str] = None) -> AuditService:
    """Returns or initializes the default AuditService instance."""
    global _default_audit_service
    with _audit_service_lock:
        if _default_audit_service is None:
            path = log_path or ".runtimeverify/audit.log"
            sink = FileAuditSink(file_path=path)
            repo = FileAuditRepository(log_path=path)
            _default_audit_service = AuditService(sink=sink, repository=repo)
        return _default_audit_service


def set_default_audit_service(service: AuditService) -> None:
    """Sets the global AuditService instance."""
    global _default_audit_service
    with _audit_service_lock:
        _default_audit_service = service
