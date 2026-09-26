# Attack & Agent Replay (`runtimeverify replay`)

The **Attack & Agent Replay Engine** enables security researchers, platform teams, and agent developers to take historical agent execution traces and answer two fundamental questions:

1. **"What would RuntimeVerify have done?"** — Evaluates recorded telemetry step-by-step against multi-tier security defenses: deterministic policies, Laya semantic risk classification, and Markov/SPRT sequential anomaly detection.
2. **"What happens if I change the policy, model, or version?"** — Performs automated **what-if policy comparisons**, highlighting divergent decisions, tightened protections, and earlier intervention points without touching running production agents.

---

## Architecture Concept

```
                 Recorded Agent Trace (.json, .jsonl, LLM transcripts)
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │    Agent Replay Engine    │
                        └─────────────┬─────────────┘
                                      │
                  ┌───────────────────┼───────────────────┐
                  ▼                   ▼                   ▼
           Deterministic            Laya               Markov
           Security Policy         Semantic          SPRT Drift
                  │                   │                   │
                  └───────────────────┼───────────────────┘
                                      ▼
                          Synthesized Verification
                                      │
                                      ▼
                            ALLOW / REVIEW / BLOCK
```

---

## 1. Quickstart

### Basic Trace Replay

```bash
# Replay an agent trace against default active policies
runtimeverify replay examples/traces/credential_access_attack.json
```

Output:

```text
╭────────────────── RuntimeVerify Attack & Agent Replay ──────────────────╮
│ Trace Source: examples/traces/credential_access_attack.json             │
│ Session ID: replay-session  |  Agent ID: replay-agent                   │
│ Policy: examples/policies/default.yaml                                  │
│ Strategy: HYBRID  |  Overall Verdict: BLOCK                             │
╰─────────────────────────────────────────────────────────────────────────╯
Step-by-Step Replay Trace (4 of 4 steps displayed)
┌───┬────────────────┬──────────────────────┬──────────────┬───────────────┬─────────────┬─────────┬─────────┐
│ # │ Action         │ Target               │ Policy Layer │ Laya Semantic │ Markov/SPRT │ Verdict │ Latency │
├───┼────────────────┼──────────────────────┼──────────────┼───────────────┼─────────────┼─────────┼─────────┤
│ 1 │ filesystem:read│ src/app.py           │ ALLOW        │ SAFE          │ NORMAL      │ ALLOW   │ 1.37ms  │
│ 2 │ filesystem:writ│ src/app.py           │ ALLOW        │ SAFE          │ NORMAL      │ ALLOW   │ 0.60ms  │
│ 3 │ shell:execute  │ pytest tests/        │ ALLOW        │ SAFE          │ NORMAL      │ ALLOW   │ 0.89ms  │
│ 4 │ filesystem:read│ ~/.aws/credentials   │ BLOCK        │ CRITICAL      │ DRIFT (H1)  │ BLOCK   │ 0.50ms  │
└───┴────────────────┴──────────────────────┴──────────────┴───────────────┴─────────────┴─────────┴─────────┘
╭───────────────────────────── Replay Summary ────────────────────────────╮
│ Total Evaluated Steps: 4  (3 ALLOW | 0 REVIEW | 1 BLOCK)                │
│ Layer Activations: Policy rules: 1 | Laya flags: 1 | Markov/SPRT: 1     │
│ Verification Latency: Mean: 0.840ms | Peak: 1.374ms | Total: 3.48ms     │
│ First Security Intervention: Step 4 triggered by Policy (deny-aws-creds)│
│   Reason: Access to cloud credentials is strictly prohibited.           │
╰─────────────────────────────────────────────────────────────────────────╯
```

---

## 2. What-If Policy Comparison

Simulate policy tuning or measure the impact of stricter compliance guardrails across past agent runs:

```bash
runtimeverify replay examples/traces/normal_coding_session.json \
  --policy examples/policies/developer.yaml \
  --compare-policy examples/policies/strict.yaml
```

Output:

```text
What-If Policy Comparison: Baseline vs Candidate Policy
┌──────┬──────────────────────┬──────────────────┬──────────────────┬───────────────────────────┐
│ Step │ Target               │ Baseline Verdict │ Candidate Verdict│ Impact / Delta            │
├──────┼──────────────────────┼──────────────────┼──────────────────┼───────────────────────────┤
│    2 │ src/main.py          │      ALLOW       │      REVIEW      │ ALLOW -> REVIEW           │
│    4 │ git status           │      REVIEW      │      BLOCK       │ REVIEW -> BLOCK           │
│    5 │ main                 │      REVIEW      │      BLOCK       │ REVIEW -> BLOCK           │
└──────┴──────────────────────┴──────────────────┴──────────────────┴───────────────────────────┘
╭──────────────────────── Policy Change Assessment ───────────────────────╮
│ What-If Impact Analysis: Candidate policy tightened security: 2 actions │
│ newly BLOCKED. Baseline Blocks: 0 | Candidate Blocks: 2 | Divergent: 3  │
╰─────────────────────────────────────────────────────────────────────────╯
```

---

## 3. CLI Command Options

```text
Usage: runtimeverify replay [OPTIONS] TRACE_FILE

Arguments:
  TRACE_FILE                     Path to recorded agent trace (.json, .jsonl) [required]

Options:
  -p, --policy TEXT              Baseline policy YAML path [default: examples/policies/default.yaml]
  --compare-policy, --diff TEXT  Candidate policy YAML to evaluate what-if impact
  -s, --strategy TEXT            Strategy: hybrid, rules, semantic, markov, rules_markov [default: hybrid]
  -m, --model TEXT               Path to custom Markov behavioral model JSON
  --alpha FLOAT                  SPRT false-alarm limit [default: 0.05]
  --beta FLOAT                   SPRT missed-attack limit [default: 0.05]
  --fail-fast                    Halt replay immediately upon first BLOCK decision
  --only-interventions           Display only steps resulting in REVIEW or BLOCK
  --json                         Output replay report as structured JSON
  -r, --report TEXT              Save full Markdown audit report to file
  -q, --quiet                    Quiet mode (emits exit code only)
  -v, --verbose                  Verbose diagnostic output
```

### Exit Codes

| Code | Meaning |
| :--- | :--- |
| **`0`** | **ALLOW**: All actions in trace satisfied verification constraints. |
| **`2`** | **BLOCK**: At least one action in trace was blocked by security controls. |
| **`3`** | **REVIEW**: At least one action required human authorization (none blocked). |
| **`1`** | **Error**: Trace file not found, invalid JSON syntax, or bad configuration. |

---

## 4. Supported Trace Formats

The `TraceLoader` automatically recognizes and normalizes:

1. **JSON Array of Actions / Events**:
   ```json
   [
     {"action_type": "filesystem", "name": "read", "target": "src/app.py"},
     {"action_type": "shell", "name": "execute", "target": "pytest"}
   ]
   ```

2. **JSON Lines (NDJSON)**:
   ```jsonl
   {"action_type": "filesystem", "operation": "read", "path": "src/app.py"}
   {"action_type": "shell", "command": "pytest"}
   ```

3. **Envelope Traces**:
   ```json
   {
     "session_id": "sess-42",
     "agent_id": "coding-agent",
     "events": [ ... ]
   }
   ```

4. **LLM Function / Tool-Call Transcripts** (OpenAI / Anthropic):
   ```json
   [
     {
       "role": "assistant",
       "tool_calls": [
         {
           "id": "call_1",
           "type": "function",
           "function": {
             "name": "run_command",
             "arguments": "{\"command\": \"cat ~/.aws/credentials\"}"
           }
         }
       ]
     }
   ]
   ```

---

## 5. Python SDK Usage

```python
from runtimeverify.replay import AgentTraceReplayer, TraceLoader

# Initialize replayer with custom policies or what-if comparison
replayer = AgentTraceReplayer(
    policy_path="examples/policies/default.yaml",
    compare_policy_path="examples/policies/strict.yaml",
    strategy="hybrid",
)

# Execute replay
report = replayer.replay("examples/traces/credential_access_attack.json")

print(f"Overall Verdict: {report.summary.overall_verdict}")
print(f"First Intervention: Step {report.summary.first_intervention_step} ({report.summary.first_intervention_layer})")
print(f"Mean Latency: {report.summary.avg_latency_ms:.3f} ms")

if report.comparison:
    print(f"Policy Delta: {report.comparison.delta_description}")
```
