"""
Comprehensive integration tests for RuntimeVerify Production CLI (Phase 10).
Tests init, check, run, monitor, policy validate, policy test, events, approvals,
status, benchmark, version, JSON output mode, quiet mode, secret redaction, and exit codes.
"""

import json
import os
from pathlib import Path
from typer.testing import CliRunner

from runtimeverify.cli import app

runner = CliRunner()


# ============================================================================
# 1. Workspace & Information Commands: init, version, status
# ============================================================================


def test_cli_version_formats():
    # Human readable
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "AI Runtime Verification Framework (verify)" in res.stdout

    # Quiet
    res_quiet = runner.invoke(app, ["version", "--quiet"])
    assert res_quiet.exit_code == 0
    assert res_quiet.stdout.strip() == "0.1.0"

    # JSON
    res_json = runner.invoke(app, ["version", "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert data["version"] == "0.1.0"
    assert "python" in data
    assert "platform" in data


def test_cli_init_modes(tmp_path: Path):
    target = str(tmp_path / "ws_test")

    # JSON mode init
    res_json = runner.invoke(app, ["init", target, "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert data["status"] == "success"
    assert os.path.exists(data["config"])
    assert os.path.exists(data["rules"])
    assert os.path.exists(data["policy"])

    # Double init without force -> exit code 2
    res_dup = runner.invoke(app, ["init", target])
    assert res_dup.exit_code == 2

    # Double init with --force -> exit code 0
    res_force = runner.invoke(app, ["init", target, "--force", "--quiet"])
    assert res_force.exit_code == 0


def test_cli_status(tmp_path: Path):
    ws_dir = str(tmp_path / "status_ws")
    runner.invoke(app, ["init", ws_dir])

    # Human status
    res = runner.invoke(app, ["status", "--dir", ws_dir])
    assert res.exit_code == 0
    assert "RuntimeVerify System Status" in res.stdout

    # JSON status
    res_json = runner.invoke(app, ["status", "--dir", ws_dir, "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert data["initialized"] is True
    assert "policy" in data
    assert data["version"] == "0.1.0"

    # Quiet status
    res_quiet = runner.invoke(app, ["status", "--dir", ws_dir, "--quiet"])
    assert res_quiet.exit_code == 0
    assert res_quiet.stdout.strip() == "initialized"


# ============================================================================
# 2. Pre-Execution Inspection: check
# ============================================================================


def test_cli_check_command_allowed():
    # Safe git status check -> exit code 0 (ALLOW)
    res = runner.invoke(app, ["check", "--command", "git status"])
    assert res.exit_code == 0
    assert "Decision: ALLOW" in res.stdout
    assert "Permitted: True" in res.stdout


def test_cli_check_command_blocked():
    # Destructive command -> exit code 2 (BLOCK)
    res = runner.invoke(app, ["check", "--command", "rm -rf /"])
    assert res.exit_code == 2
    assert "Decision: BLOCK" in res.stdout
    assert "block-destructive-rm" in res.stdout


def test_cli_check_file_blocked():
    # AWS credentials access -> exit code 2 (BLOCK)
    res = runner.invoke(app, ["check", "--file", "~/.aws/credentials"])
    assert res.exit_code == 2
    assert "Decision: BLOCK" in res.stdout
    assert "deny-aws-credentials" in res.stdout


def test_cli_check_json_output():
    # Allowed JSON
    res_allow = runner.invoke(app, ["check", "--command", "pytest", "--json"])
    assert res_allow.exit_code == 0
    data_allow = json.loads(res_allow.stdout)
    assert data_allow["decision"] == "ALLOW"
    assert data_allow["execution_permitted"] is True

    # Blocked JSON
    res_block = runner.invoke(app, ["check", "--file", "~/.ssh/id_rsa", "--json"])
    assert res_block.exit_code == 2
    data_block = json.loads(res_block.stdout)
    assert data_block["decision"] == "BLOCK"
    assert data_block["execution_permitted"] is False
    assert data_block["policy_id"] == "deny-ssh-keys"


def test_cli_check_quiet_output():
    res_allow = runner.invoke(app, ["check", "--command", "git status", "--quiet"])
    assert res_allow.exit_code == 0
    assert res_allow.stdout.strip() == "ALLOW"

    res_block = runner.invoke(app, ["check", "--command", "rm -rf /", "--quiet"])
    assert res_block.exit_code == 2
    assert res_block.stdout.strip() == "BLOCK"


def test_cli_check_secret_redaction():
    # Command containing embedded credentials must be redacted in output
    token = "sk-proj-123456789012345678901234567890"
    res = runner.invoke(app, ["check", "--command", f"export OPENAI_API_KEY={token}", "--json"])
    assert token not in res.stdout
    assert "[REDACTED_OPENAI_KEY]" in res.stdout


def test_cli_check_invalid_arguments():
    # Missing both --command, --file, and --type
    res = runner.invoke(app, ["check"])
    assert res.exit_code == 1
    assert "Must provide either --file, --command" in res.stdout


# ============================================================================
# 3. Supervised Process Execution: run
# ============================================================================


def test_cli_run_allowed_command():
    # Safe echo command -> exit code 0
    res = runner.invoke(app, ["run", "--", "python", "-c", "print('safe-agent-output')"])
    assert res.exit_code == 0
    assert "safe-agent-output" in res.stdout


def test_cli_run_allowed_command_json():
    res = runner.invoke(app, ["run", "--json", "--", "python", "-c", "import sys; sys.exit(0)"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["status"] == "ALLOW"
    assert data["returncode"] == 0
    assert data["execution_permitted"] is True


def test_cli_run_blocked_command():
    # Destructive command -> blocked before execution, exit code 2
    res = runner.invoke(app, ["run", "--", "rm", "-rf", "/"])
    assert res.exit_code == 2
    assert "EXECUTION BLOCKED" in res.stdout
    assert "block-destructive-rm" in res.stdout


def test_cli_run_blocked_command_json():
    res = runner.invoke(app, ["run", "--json", "--", "rm", "-rf", "/"])
    assert res.exit_code == 2
    data = json.loads(res.stdout)
    assert data["status"] == "BLOCK"
    assert data["policy_id"] == "block-destructive-rm"
    assert data["execution_permitted"] is False


def test_cli_run_empty_command():
    res = runner.invoke(app, ["run"])
    assert res.exit_code == 1
    assert "No command provided" in res.stdout


# ============================================================================
# 4. Policy Engine: validate & test
# ============================================================================


def test_cli_policy_validate():
    # Valid default policy
    res = runner.invoke(app, ["policy", "validate", "examples/policies/default.yaml"])
    assert res.exit_code == 0
    assert "Policy Set:" in res.stdout
    assert "Policy file is valid" in res.stdout

    # Valid default policy (JSON)
    res_json = runner.invoke(app, ["policy", "validate", "examples/policies/default.yaml", "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert data["valid"] is True
    assert data["rules_count"] >= 5

    # Non-existent policy -> exit code 1
    res_err = runner.invoke(app, ["policy", "validate", "non_existent_policy.yaml"])
    assert res_err.exit_code == 1


def test_cli_policy_test_standard():
    # Built-in test suite evaluation
    res = runner.invoke(app, ["policy", "test", "examples/policies/default.yaml"])
    assert res.exit_code == 0
    assert "All 7 policy test scenarios passed" in res.stdout

    # Built-in test suite (JSON)
    res_json = runner.invoke(app, ["policy", "test", "examples/policies/default.yaml", "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert data["all_passed"] is True
    assert data["passed"] == 7
    assert data["failed"] == 0


def test_cli_policy_test_custom_file(tmp_path: Path):
    test_suite = {
        "tests": [
            {"name": "test-git", "type": "shell", "target": "git status", "expected": "ALLOW"},
            {"name": "test-rm", "type": "shell", "target": "rm -rf /", "expected": "BLOCK"},
        ]
    }
    suite_file = str(tmp_path / "custom_suite.json")
    with open(suite_file, "w") as f:
        json.dump(test_suite, f)

    res = runner.invoke(app, ["policy", "test", "examples/policies/default.yaml", "--test-file", suite_file, "--json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["passed"] == 2
    assert data["all_passed"] is True


# ============================================================================
# 5. Telemetry & Events: events
# ============================================================================


def test_cli_events_list_empty():
    res = runner.invoke(app, ["events", "list"])
    assert res.exit_code == 0


def test_cli_events_default_invokes_list():
    # Top-level `runtimeverify events` should default to listing
    res = runner.invoke(app, ["events"])
    assert res.exit_code == 0


# ============================================================================
# 6. Performance Benchmarking: benchmark
# ============================================================================


def test_cli_benchmark():
    res = runner.invoke(app, ["benchmark", "-n", "50"])
    assert res.exit_code == 0
    assert "RuntimeVerify Performance Benchmark" in res.stdout
    assert "Deterministic" in res.stdout
    assert "Policy Evaluation" in res.stdout

    res_json = runner.invoke(app, ["benchmark", "-n", "50", "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert "policy_benchmark" in data
    assert "redaction_benchmark" in data
    assert data["iterations"] == 50


# ============================================================================
# 7. Approvals & Audit Subcommands
# ============================================================================


def test_cli_approvals_list_json():
    res = runner.invoke(app, ["approvals", "list", "--json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert isinstance(data, list)


def test_cli_audit_list_json():
    res = runner.invoke(app, ["audit", "list", "--json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert isinstance(data, list)
