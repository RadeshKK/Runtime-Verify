"""
Integration tests for CLI replay command (`runtimeverify replay trace.json`).
Tests exit codes, flags, JSON output, report generation, and what-if comparisons.
"""

import json
from pathlib import Path
from typer.testing import CliRunner

from runtimeverify.cli import app

runner = CliRunner()


def test_cli_replay_normal_session():
    result = runner.invoke(app, ["replay", "examples/traces/normal_coding_session.json"])
    assert result.exit_code == 0
    assert "RuntimeVerify Attack & Agent Replay" in result.stdout
    assert "ALLOW" in result.stdout


def test_cli_replay_credential_attack_blocks():
    result = runner.invoke(app, ["replay", "examples/traces/credential_access_attack.json"])
    # 2 indicates BLOCK exit code
    assert result.exit_code == 2
    assert "BLOCK" in result.stdout
    assert "credential" in result.stdout.lower()


def test_cli_replay_destructive_attack_blocks():
    result = runner.invoke(app, ["replay", "examples/traces/destructive_attack.json"])
    assert result.exit_code == 2
    assert "BLOCK" in result.stdout
    assert "destructive" in result.stdout.lower()


def test_cli_replay_json_output():
    result = runner.invoke(app, ["replay", "examples/traces/destructive_attack.json", "--json"])
    assert result.exit_code == 2
    data = json.loads(result.stdout)
    assert data["summary"]["overall_verdict"] == "BLOCK"
    assert data["summary"]["total_steps"] == 2
    assert len(data["steps"]) == 2


def test_cli_replay_fail_fast():
    result = runner.invoke(
        app,
        ["replay", "examples/traces/destructive_attack.json", "--fail-fast", "--json"],
    )
    assert result.exit_code == 2
    data = json.loads(result.stdout)
    assert data["summary"]["overall_verdict"] == "BLOCK"
    assert data["steps"][-1]["final_verdict"] == "BLOCK"


def test_cli_replay_what_if_comparison():
    result = runner.invoke(
        app,
        [
            "replay",
            "examples/traces/normal_coding_session.json",
            "--policy",
            "examples/policies/developer.yaml",
            "--compare-policy",
            "examples/policies/strict.yaml",
        ],
    )
    # developer.yaml allows some actions that strict.yaml blocks/reviews
    assert "What-If Policy Comparison" in result.stdout
    assert "Baseline vs Candidate Policy" in result.stdout


def test_cli_replay_generate_report(tmp_path: Path):
    report_out = tmp_path / "replay_audit.md"
    result = runner.invoke(
        app,
        [
            "replay",
            "examples/traces/credential_access_attack.json",
            "--report",
            str(report_out),
        ],
    )
    assert result.exit_code == 2
    assert report_out.exists()
    content = report_out.read_text(encoding="utf-8")
    assert "# Attack & Agent Replay Audit Report" in content
    assert "```mermaid" in content


def test_cli_replay_missing_trace_file():
    result = runner.invoke(app, ["replay", "non_existent_trace.json"])
    assert result.exit_code == 1
    assert "not found" in result.stdout


def test_cli_replay_only_interventions():
    result = runner.invoke(
        app,
        ["replay", "examples/traces/credential_access_attack.json", "--only-interventions"],
    )
    assert result.exit_code == 2
    assert "Step-by-Step Replay Trace" in result.stdout
