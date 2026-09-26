# RuntimeVerify Production CLI Reference

The **RuntimeVerify Command Line Interface** (`runtimeverify` or `verify`) equips developers, security engineers, and CI/CD pipelines with real-time pre-execution policy gating, agent process supervision, human-in-the-loop approvals, and structured audit querying.

---

## 1. Global Flags & Conventions

All commands adhere to standardized developer ergonomics:

| Option | Flag | Description |
| :--- | :--- | :--- |
| `--json` | None | Outputs results strictly formatted as single valid JSON (for CI/CD and programmatic pipelines). |
| `--quiet` | `-q` | Minimal output mode (outputs status tokens or exit codes only). |
| `--verbose` | `-v` | Detailed diagnostics (correlation IDs, timestamps, rule evaluation traces). |

### Standard Exit Codes

RuntimeVerify utilizes semantic Unix exit codes to enable seamless integration with shell scripts and CI/CD workflows:

- **`0`**: **Success / Allowed / Valid**. Operation permitted or test succeeded.
- **`1`**: **CLI Error / Validation Failure**. Syntax error, missing argument, or policy test failure.
- **`2`**: **Policy BLOCK**. Action violated active security policy rules and was blocked before execution.
- **`3`**: **REVIEW Required**. Action requires human authorization before execution.
- **`4`**: **Not Found / Unauthorized**. Missing model file or unpermitted approver.

### Secret Redaction Guarantee

> [!SECURITY]
> The CLI automatically scans all console outputs, table cells, and JSON fields with `SecretRedactor`.
> Sensitive parameters, such as OpenAI API keys (`sk-...`), AWS credentials (`AKIA...`), GitHub PATs (`ghp_...`), Bearer tokens, private keys, and passwords, are **never** printed to the terminal or stdout.

---

## 2. Command Reference

### `runtimeverify init`

Initializes a new runtime verification workspace within the current or target directory.

```bash
# Standard initialization
runtimeverify init

# Initialize in a specific directory with overwrite
runtimeverify init ./my-project --force

# Scriptable JSON output
runtimeverify init --json
```

**Created Assets:**
- `.runtimeverify/config.yaml`: Core workspace configuration.
- `.runtimeverify/policy.yaml`: Default security policy ruleset.
- `.runtimeverify/rules.json`: Legacy Markov state mapping rules.
- `.runtimeverify/models/`: Storage directory for behavioral model checkpoints.

---

### `runtimeverify check`

Dry-run evaluation of an intended agent action before execution occurs.

```bash
# Check shell command
runtimeverify check --command "git status"

# Check destructive shell command (exits with code 2)
runtimeverify check --command "rm -rf /"

# Check sensitive file read (exits with code 2)
runtimeverify check --file ~/.aws/credentials
runtimeverify check --file ~/.ssh/id_rsa

# Programmatic evaluation for CI/CD
runtimeverify check --command "npm install" --json

# Quiet evaluation for bash conditionals
if runtimeverify check --command "$CMD" -q; then
    eval "$CMD"
fi
```

**JSON Output Format:**
```json
{
  "decision": "BLOCK",
  "status": "BLOCK",
  "execution_permitted": false,
  "action_type": "filesystem",
  "target": "~/.aws/credentials",
  "policy_id": "deny-aws-credentials",
  "severity": "CRITICAL",
  "reason": "Direct reading of AWS credential files is prohibited.",
  "mode": "enforce",
  "agent_id": "cli-agent",
  "session_id": "cli-session",
  "timestamp": "2026-09-25T13:50:00Z"
}
```

---

### `runtimeverify run`

Supervises execution of an agent process or shell command, evaluating security policies before spawning the subprocess.

```bash
# Supervise execution of an arbitrary agent script
runtimeverify run -- python agent.py

# Specify active policy file and agent identity
runtimeverify run --policy examples/policies/default.yaml --agent coding-agent -- python -m pytest

# Blocked command halts execution with exit code 2 before child process spawns
runtimeverify run -- rm -rf /

# Capture JSON execution telemetry
runtimeverify run --json -- echo "hello"
```

**JSON Output Format:**
```json
{
  "status": "ALLOW",
  "execution_permitted": true,
  "command": "python -m pytest",
  "returncode": 0,
  "duration_ms": 142.5,
  "session_id": "sess-a1b2c3d4e5f6",
  "agent_id": "coding-agent",
  "mode": "enforce"
}
```

---

### `runtimeverify monitor`

Real-time terminal monitor observing active agent actions or replaying telemetry traces.

```bash
# Monitor all recent actions
runtimeverify monitor

# Filter by agent identity
runtimeverify monitor --agent coding-agent

# Replay a session trace against active security policies
runtimeverify monitor --trace traces/session_01.json

# Emit replay report as JSON
runtimeverify monitor --trace traces/session_01.json --json
```

---

### `runtimeverify replay`

Replays recorded agent execution traces through multi-layer verification (Policy, Laya, Markov/SPRT) and simulates what-if policy comparisons.

```bash
# Replay a recorded agent trace against active policies
runtimeverify replay examples/traces/credential_access_attack.json

# What-If policy comparison: evaluate impact of tightening policy
runtimeverify replay examples/traces/normal_coding_session.json \
  --policy examples/policies/developer.yaml \
  --compare-policy examples/policies/strict.yaml

# Halt immediately on first blocked action
runtimeverify replay examples/traces/destructive_attack.json --fail-fast

# Emit structured JSON audit for CI/CD gates
runtimeverify replay examples/traces/exfiltration_attack.json --json

# Generate executive Markdown audit report
runtimeverify replay examples/traces/prompt_injection_attack.json --report replay_audit.md
```

Detailed documentation: [`docs/cli/replay.md`](replay.md)

---

### `runtimeverify policy validate`

Validates policy YAML syntax, schema conformity, and regex patterns.

```bash
# Validate default policy
runtimeverify policy validate

# Validate custom policy file
runtimeverify policy validate my_policy.yaml

# CI/CD validation mode
runtimeverify policy validate my_policy.yaml --json
```

**JSON Output Format:**
```json
{
  "valid": true,
  "path": "examples/policies/default.yaml",
  "name": "default-security-policy",
  "version": "1.0",
  "rules_count": 9,
  "conflict_resolution": "PRIORITY_WINS",
  "default_decision": "ALLOW"
}
```

---

### `runtimeverify policy test`

Executes automated regression testing on a security policy using built-in or custom test suites.

```bash
# Test policy against standard security benchmark suite
runtimeverify policy test examples/policies/default.yaml

# Test policy against custom test scenarios
runtimeverify policy test my_policy.yaml --test-file test_scenarios.yaml

# Machine-readable test report for CI/CD gates
runtimeverify policy test my_policy.yaml --json
```

**Test Suite Scenarios Schema (`test_scenarios.yaml`):**
```yaml
tests:
  - name: "Allow Git Status"
    type: "shell"
    target: "git status"
    expected: "ALLOW"
  - name: "Block Destructive rm"
    type: "shell"
    target: "rm -rf /"
    expected: "BLOCK"
  - name: "Deny SSH Key Access"
    type: "filesystem"
    target: "~/.ssh/id_rsa"
    expected: "BLOCK"
```

---

### `runtimeverify events`

Queries and inspects canonical runtime telemetry events recorded by agent sessions.

```bash
# List recent canonical telemetry events
runtimeverify events
runtimeverify events list

# Filter events by agent and limit
runtimeverify events list --agent coding-agent --limit 10

# Filter by event type
runtimeverify events list --type SHELL_COMMAND

# Show full event payload by ID
runtimeverify events show 550e8400-e29b-41d4-a716-446655440000

# JSON output
runtimeverify events list --json
```

---

### `runtimeverify approvals`

Manages human-in-the-loop authorization requests when high-risk actions enter the `REVIEW` state.

```bash
# List all pending approval requests
runtimeverify approvals list --status PENDING

# Show full evidentiary dossier for an approval request
runtimeverify approvals show <request-id>

# Approve an action
runtimeverify approvals approve <request-id> --user lead-engineer --reason "Verified safe migration script"

# Deny an action
runtimeverify approvals deny <request-id> --user secops --reason "Unauthorized external network destination"

# JSON output
runtimeverify approvals list --json
```

---

### `runtimeverify audit`

Queries and prunes the structured, tamper-evident audit trail.

```bash
# List audit records
runtimeverify audit list --limit 25

# Filter by correlation IDs
runtimeverify audit list --session custom-sess-01 --agent worker-agent

# Show full audit record with redacted details
runtimeverify audit show <record-id>

# Apply retention policy
runtimeverify audit prune --max-age-days 30 --max-records 10000
```

---

### `runtimeverify status`

Provides a complete diagnostic overview of the current workspace, active policies, audit volume, and optional semantic engines.

```bash
# Human readable report
runtimeverify status

# Scriptable JSON report
runtimeverify status --json

# One-word health check
runtimeverify status --quiet
```

---

### `runtimeverify benchmark`

Runs high-throughput microbenchmarks evaluating deterministic policy matching speed and secret redaction latency.

```bash
# Run 1,000 benchmark iterations
runtimeverify benchmark

# Run 10,000 iterations with JSON metrics
runtimeverify benchmark --iterations 10000 --json
```

**JSON Output Format:**
```json
{
  "iterations": 10000,
  "policy_benchmark": {
    "total_duration_sec": 0.0432,
    "throughput_ops_per_sec": 231481.5,
    "mean_latency_us": 4.32
  },
  "redaction_benchmark": {
    "total_duration_sec": 0.0298,
    "throughput_ops_per_sec": 335570.5,
    "mean_latency_us": 2.98
  }
}
```

---

### `runtimeverify version`

Displays framework version, Python runtime, and host OS platform information.

```bash
# Human readable
runtimeverify version

# Scriptable JSON
runtimeverify version --json

# Raw version token
runtimeverify version --quiet
```
