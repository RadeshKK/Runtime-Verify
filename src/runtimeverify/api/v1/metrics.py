"""
Prometheus Metrics Endpoint & Telemetry Exporter for RuntimeVerify (Sprint 4).
Exposes real-time agent verification throughput, decision latency, violation counts,
and session health metrics in Prometheus exposition format.
"""

from collections import defaultdict
import threading
from typing import List
from fastapi import APIRouter, Response

router = APIRouter(tags=["Metrics"])


class MetricsCollector:
    """Thread-safe in-process metrics aggregator for RuntimeVerify."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._actions_evaluated: dict[tuple[str, str], int] = defaultdict(int)
        self._decisions: dict[str, int] = defaultdict(int)
        self._security_violations: dict[str, int] = defaultdict(int)
        self._duration_count: int = 0
        self._duration_sum: float = 0.0
        self._active_sessions: int = 0

    def record_action(self, action_type: str, status: str, duration_seconds: float = 0.0) -> None:
        with self._lock:
            self._actions_evaluated[(action_type.lower(), status.upper())] += 1
            if duration_seconds > 0:
                self._duration_count += 1
                self._duration_sum += duration_seconds

    def record_decision(self, decision: str) -> None:
        with self._lock:
            self._decisions[decision.upper()] += 1

    def record_violation(self, severity: str) -> None:
        with self._lock:
            self._security_violations[severity.upper()] += 1

    def set_active_sessions(self, count: int) -> None:
        with self._lock:
            self._active_sessions = max(0, count)

    def generate_prometheus_text(self) -> str:
        """Generates valid Prometheus text exposition format."""
        lines: List[str] = []

        with self._lock:
            # 1. rv_actions_evaluated_total
            lines.append(
                "# HELP rv_actions_evaluated_total Total intercepted actions evaluated by policy and verification engines."
            )
            lines.append("# TYPE rv_actions_evaluated_total counter")
            if not self._actions_evaluated:
                lines.append('rv_actions_evaluated_total{action_type="unknown",status="ALLOW"} 0')
            else:
                for (atype, status), val in sorted(self._actions_evaluated.items()):
                    lines.append(f'rv_actions_evaluated_total{{action_type="{atype}",status="{status}"}} {val}')

            # 2. rv_decisions_total
            lines.append("# HELP rv_decisions_total Total policy and behavioral enforcement decisions.")
            lines.append("# TYPE rv_decisions_total counter")
            for dec in ["ALLOW", "REVIEW", "BLOCK"]:
                lines.append(f'rv_decisions_total{{decision="{dec}"}} {self._decisions[dec]}')

            # 3. rv_security_violations_total
            lines.append("# HELP rv_security_violations_total Total security rule violations detected.")
            lines.append("# TYPE rv_security_violations_total counter")
            for sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                lines.append(f'rv_security_violations_total{{severity="{sev}"}} {self._security_violations[sev]}')

            # 4. rv_active_sessions_count
            lines.append("# HELP rv_active_sessions_count Currently monitored active agent sessions.")
            lines.append("# TYPE rv_active_sessions_count gauge")
            lines.append(f"rv_active_sessions_count {self._active_sessions}")

            # 5. rv_decision_latency_seconds
            lines.append("# HELP rv_decision_latency_seconds Latency of runtime verification decisions in seconds.")
            lines.append("# TYPE rv_decision_latency_seconds summary")
            lines.append(f"rv_decision_latency_seconds_count {self._duration_count}")
            lines.append(f"rv_decision_latency_seconds_sum {self._duration_sum:.6f}")

        return "\n".join(lines) + "\n"


# Global singleton collector
global_metrics = MetricsCollector()


@router.get("/metrics", response_class=Response)
def get_metrics() -> Response:
    """Scrapes Prometheus metrics in standard text exposition format."""
    content = global_metrics.generate_prometheus_text()
    return Response(content=content, media_type="text/plain; version=0.0.4; charset=utf-8")
