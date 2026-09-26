"""
Comprehensive Unit and Integration Tests for RuntimeVerify Attack & Agent Replay.
Verifies TraceLoader, AgentTraceReplayer, What-If Policy Comparisons, and Report Formatting.
"""

import json
from pathlib import Path
import pytest

from runtimeverify.interception.models import ActionType
from runtimeverify.replay import (
    AgentTraceReplayer,
    ReplayFormatter,
    ReplayReport,
    TraceLoader,
)
from rich.console import Console

console = Console()


@pytest.fixture
def traces_dir() -> Path:
    return Path("examples/traces")


@pytest.fixture
def policies_dir() -> Path:
    return Path("examples/policies")


class TestTraceLoader:
    """Verifies heterogeneous format parsing across JSON arrays, NDJSON, and envelopes."""

    def test_load_json_array(self, traces_dir: Path):
        path = traces_dir / "normal_coding_session.json"
        actions, meta = TraceLoader.load(path)
        assert len(actions) == 5
        assert actions[0].action_type == ActionType.FILESYSTEM
        assert actions[0].name == "read"
        assert actions[2].action_type == ActionType.SHELL
        assert actions[4].action_type == ActionType.GIT

    def test_load_ndjson(self, tmp_path: Path):
        ndjson_file = tmp_path / "trace.jsonl"
        lines = [
            json.dumps({"action_type": "filesystem", "operation": "read", "path": "src/main.py"}),
            json.dumps({"action_type": "shell", "command": "pytest"}),
            json.dumps({"action_type": "network", "url": "https://api.github.com"}),
        ]
        ndjson_file.write_text("\n".join(lines), encoding="utf-8")

        actions, meta = TraceLoader.load(ndjson_file)
        assert len(actions) == 3
        assert actions[0].action_type == ActionType.FILESYSTEM
        assert actions[1].action_type == ActionType.SHELL
        assert actions[2].action_type == ActionType.NETWORK

    def test_load_envelope_dict(self):
        envelope = {
            "session_id": "test-envelope-sess",
            "agent_id": "test-agent",
            "events": [
                {"action_type": "filesystem", "path": "test.txt", "operation": "read"},
                {"action_type": "shell", "command": "echo test"},
            ],
        }
        actions, meta = TraceLoader.load(envelope)
        assert len(actions) == 2
        assert meta["session_id"] == "test-envelope-sess"
        assert meta["agent_id"] == "test-agent"
        assert actions[0].session_id == "test-envelope-sess"

    def test_load_tool_calls_transcript(self):
        llm_transcript = [
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "run_bash_command",
                            "arguments": json.dumps({"command": "cat /etc/passwd"}),
                        },
                    }
                ],
            },
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call_2",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": json.dumps({"path": ".env"}),
                        },
                    }
                ],
            },
        ]
        actions, meta = TraceLoader.load(llm_transcript)
        assert len(actions) == 2
        assert actions[0].action_type == ActionType.SHELL
        assert actions[0].target == "cat /etc/passwd"
        assert actions[1].action_type == ActionType.FILESYSTEM
        assert actions[1].target == ".env"

    def test_invalid_trace_raises_error(self, tmp_path: Path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("NOT_VALID_JSON_AT_ALL", encoding="utf-8")
        with pytest.raises(ValueError, match="Failed to parse trace"):
            TraceLoader.load(bad_file)


class TestAgentTraceReplayer:
    """Verifies replay verification logic, defense layers, and what-if diffs."""

    def test_replay_normal_session(self, traces_dir: Path, policies_dir: Path):
        replayer = AgentTraceReplayer(
            policy_path=str(policies_dir / "default.yaml"),
            strategy="hybrid",
        )
        report = replayer.replay(traces_dir / "normal_coding_session.json")

        assert report.summary.overall_verdict == "ALLOW"
        assert report.summary.total_steps == 5
        assert report.summary.allowed_steps == 5
        assert report.summary.blocked_steps == 0
        assert report.summary.first_intervention_step is None

    def test_replay_credential_access_attack(self, traces_dir: Path, policies_dir: Path):
        replayer = AgentTraceReplayer(
            policy_path=str(policies_dir / "default.yaml"),
            strategy="hybrid",
        )
        report = replayer.replay(traces_dir / "credential_access_attack.json")

        assert report.summary.overall_verdict == "BLOCK"
        assert report.summary.blocked_steps >= 1
        assert report.summary.first_intervention_step == 4
        assert report.summary.first_intervention_layer == "Policy"
        assert "credentials" in report.summary.first_intervention_reason.lower()

    def test_replay_destructive_attack(self, traces_dir: Path, policies_dir: Path):
        replayer = AgentTraceReplayer(
            policy_path=str(policies_dir / "default.yaml"),
            strategy="hybrid",
        )
        report = replayer.replay(traces_dir / "destructive_attack.json")

        assert report.summary.overall_verdict == "BLOCK"
        assert report.summary.first_intervention_step == 2
        assert report.summary.first_intervention_layer == "Policy"

    def test_replay_prompt_injection_attack(self, traces_dir: Path, policies_dir: Path):
        replayer = AgentTraceReplayer(
            policy_path=str(policies_dir / "default.yaml"),
            strategy="hybrid",
        )
        report = replayer.replay(traces_dir / "prompt_injection_attack.json")

        assert report.summary.overall_verdict == "BLOCK"
        # Prompt injection is caught at step 2 by the semantic layer!
        assert report.summary.first_intervention_step == 2
        assert report.summary.first_intervention_layer == "Laya Semantic"

    def test_fail_fast_behavior(self, traces_dir: Path, policies_dir: Path):
        replayer = AgentTraceReplayer(
            policy_path=str(policies_dir / "default.yaml"),
            strategy="hybrid",
            fail_fast=True,
        )
        report = replayer.replay(traces_dir / "destructive_attack.json")
        # Step 2 is BLOCK, so fail_fast stops after step 2
        assert report.summary.total_steps == 2
        assert report.steps[-1].final_verdict == "BLOCK"

    def test_what_if_policy_comparison(self, traces_dir: Path, policies_dir: Path):
        replayer = AgentTraceReplayer(
            policy_path=str(policies_dir / "developer.yaml"),
            compare_policy_path=str(policies_dir / "strict.yaml"),
            strategy="hybrid",
        )
        report = replayer.replay(traces_dir / "normal_coding_session.json")

        assert report.comparison is not None
        assert report.comparison.divergent_steps > 0
        assert report.comparison.candidate_blocks >= report.comparison.baseline_blocks
        assert "tightened" in report.comparison.delta_description.lower()

    def test_strategy_variations(self, traces_dir: Path, policies_dir: Path):
        # Rules only strategy
        replayer_rules = AgentTraceReplayer(
            policy_path=str(policies_dir / "default.yaml"),
            strategy="rules",
        )
        rep_rules = replayer_rules.replay(traces_dir / "normal_coding_session.json")
        assert rep_rules.summary.overall_verdict == "ALLOW"

        # Semantic only strategy
        replayer_sem = AgentTraceReplayer(
            policy_path=str(policies_dir / "default.yaml"),
            strategy="semantic",
        )
        rep_sem = replayer_sem.replay(traces_dir / "normal_coding_session.json")
        assert rep_sem.summary.overall_verdict == "ALLOW"


class TestReplayFormatter:
    """Verifies output rendering to Terminal, JSON, and Markdown formats."""

    def test_json_serialization(self, traces_dir: Path, policies_dir: Path):
        replayer = AgentTraceReplayer(policy_path=str(policies_dir / "default.yaml"))
        report = replayer.replay(traces_dir / "normal_coding_session.json")

        data = report.model_dump(mode="json")
        assert "trace_source" in data
        assert "summary" in data
        assert "steps" in data
        assert len(data["steps"]) == 5

    def test_markdown_report_generation(self, traces_dir: Path, policies_dir: Path):
        replayer = AgentTraceReplayer(
            policy_path=str(policies_dir / "developer.yaml"),
            compare_policy_path=str(policies_dir / "strict.yaml"),
        )
        report = replayer.replay(traces_dir / "normal_coding_session.json")

        md = ReplayFormatter.render_markdown(report)
        assert "# Attack & Agent Replay Audit Report" in md
        assert "```mermaid" in md
        assert "What-If Policy Change Analysis" in md
        assert "| Step | Action | Target |" in md

    def test_terminal_render_runs_without_error(self, traces_dir: Path, policies_dir: Path):
        replayer = AgentTraceReplayer(
            policy_path=str(policies_dir / "default.yaml"),
            compare_policy_path=str(policies_dir / "strict.yaml"),
        )
        report = replayer.replay(traces_dir / "credential_access_attack.json")

        # Must execute cleanly without exception
        ReplayFormatter.render_terminal(report, console=console, verbose=True, only_interventions=False)
        ReplayFormatter.render_terminal(report, console=console, verbose=False, only_interventions=True)
