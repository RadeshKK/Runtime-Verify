# 🛡️ RuntimeVerify

[![CI](https://github.com/RadeshKK/Runtime-Verify/actions/workflows/ci.yml/badge.svg)](https://github.com/RadeshKK/Runtime-Verify/actions/workflows/ci.yml)
[![Release](https://github.com/RadeshKK/Runtime-Verify/actions/workflows/release.yml/badge.svg)](https://github.com/RadeshKK/Runtime-Verify/actions/workflows/release.yml)
[![PyPI Version](https://img.shields.io/badge/pypi-0.1.0-blue.svg)](https://pypi.org/project/runtimeverify/)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://pypi.org/project/runtimeverify/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security Audit](https://img.shields.io/badge/security-pip--audit%20clean-brightgreen.svg)](https://github.com/RadeshKK/Runtime-Verify/actions)
[![Type Checked: MyPy](https://img.shields.io/badge/type--check-mypy%20passed-blue.svg)](https://github.com/python/mypy)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Tests Passing](https://img.shields.io/badge/tests-413%20passed-brightgreen.svg)](https://github.com/RadeshKK/Runtime-Verify/actions)

**Vendor-neutral statistical runtime verification, deterministic policy governance, and behavioral security for single and multi-agent autonomous AI systems.**

RuntimeVerify protects host infrastructure and enterprise environments against autonomous agent misbehavior, prompt injection exploits, credential exfiltration, destructive shell operations, unauthorized multi-agent delegations, and SSRF attacks by enforcing pre-execution action gating before tool dispatch.

---

## 🌟 Key Capabilities

- **⚡ Lightweight Base Package**: Zero heavyweight ML or server frameworks required for the core SDK, CLI, and policy engine.
- **🛑 Deterministic Policy Governance**: Strict path canonicalization, command pipeline decomposition, and network metadata/IMDS blocking.
- **🧠 Semantic Intent Classification**: Evaluates tool calls against declared task scopes with zero-shot semantic classifiers.
- **📈 Behavioral Markov Modeling**: Models agent state transition sequences ($S_{t-1} \to S_t$) to detect sudden behavioral shifts.
- **🔬 Statistical Sequential Testing (SPRT)**: Wald's Sequential Probability Ratio Test accumulates log-likelihood ratios to identify subtle multi-event drift without false alarms.
- **🤝 Multi-Agent Swarm Topology Verification (Phase 17)**: Governs complex agent topologies (`planner` $\to$ `coder` $\to$ `tester` $\to$ `executor`), detecting abnormal handoffs, rogue delegations, and cross-agent privilege escalation.
- **🏢 Enterprise Architecture & Multi-Tenancy (Phase 18)**: Multi-tenant boundary isolation (`Tenant`, `Organization`, `Project`, `Environment`), hierarchical RBAC, Keycloak/OIDC-compatible auth abstractions, and policy set versioning.
- **⏸️ Dual-Control Human Approvals**: Pauses high-risk actions (`REVIEW`) and enforces single-use cryptographic challenge tokens to eliminate replay attacks.
- **🔒 Tamper-Evident Audit Trails**: SHA-256 hash-chained sequential audit logging ($H_i = \text{SHA-256}(\dots \parallel H_{i-1})$) with automated secret redaction for API keys, private keys, and JWTs.
- **🖥️ SOC Operations Console**: Dark Cyber cockpit with interactive SVG multi-agent DAG visualizer, Wald SPRT phase space workbench, and instant threat simulator presets.

---

## 📦 Installation

RuntimeVerify provides modular dependency groups so developers only install what they need:

### Base Package (Recommended for Agents & CLI)
Includes the Python SDK, CLI, Deterministic Policy Engine, Markov behavioral model, SPRT verification, and Security Hardening layer:
```bash
pip install runtimeverify
```

### Optional Extras
```bash
# REST API Server & OpenAPI documentation (v1)
pip install "runtimeverify[api]"

# Web Security Operations Dashboard & static UI
pip install "runtimeverify[dashboard]"

# Laya Semantic Decision Engine integration
pip install "runtimeverify[laya]"

# Development, testing, and linting suite
pip install "runtimeverify[dev]"

# Complete bundle (API + Dashboard + Semantic + Core)
pip install "runtimeverify[all]"
```

---

## 🚀 Quickstart

### 1. Initialize Workspace & Configuration
Initialize local configuration and baseline directories:
```bash
runtimeverify init
```
This generates `.runtimeverify/config.yaml` with secure default policies, audit sinks, and verification parameters.

---

### 2. Your First Security Policy
Create a declarative YAML policy in `policies/default.yaml` defining what actions are permitted, held for human review, or blocked:

```yaml
version: "1.0"
conflict_resolution: most_restrictive
policies:
  # 1. Block access to cloud credentials
  - id: block-cloud-credentials
    name: Protect Cloud Credentials
    description: Prevents reading AWS, SSH, or environment credentials
    decision: BLOCK
    severity: CRITICAL
    match:
      event_type: filesystem.read
      path:
        any_of:
          - "~/.aws/*"
          - "~/.ssh/*"
          - "**/.env*"

  # 2. Block destructive shell operations
  - id: block-destructive-commands
    name: Block Destructive Shell
    description: Prevents destructive deletion commands
    decision: BLOCK
    severity: CRITICAL
    match:
      event_type: shell.command
      command:
        destructive: true

  # 3. Require human approval for production deployments
  - id: review-production-deploy
    name: Review Production Deployments
    description: Pauses external deployment commands for human authorization
    decision: REVIEW
    severity: HIGH
    match:
      event_type: shell.command
      command:
        contains: "kubectl apply"
```

Validate your policy file using the CLI:
```bash
runtimeverify policy validate policies/default.yaml
```

---

### 3. Your First Monitored Agent
Integrate RuntimeVerify into your autonomous AI agent with minimal code changes using `runtimeverify.session`:

```python
import runtimeverify
from runtimeverify.interception.exceptions import ExecutionBlockedError

# Wrap agent execution in a monitored session
with runtimeverify.session(agent_id="coding-assistant") as session:

    # 1. Safe Action: Reading project code is evaluated and permitted
    safe_read = {
        "path": "src/main.py",
        "operation": "read",
    }
    
    # Dry-run check or direct execution
    decision = session.check(safe_read)
    print(f"Read permitted: {decision.execution_permitted}")  # True
    
    result = session.execute(safe_read)
    print(f"Executed: {result.success}")

    # 2. Dangerous Action: Reading credentials triggers deterministic block
    credential_read = {
        "path": "~/.aws/credentials",
        "operation": "read",
    }
    
    try:
        session.execute(credential_read)
    except ExecutionBlockedError as e:
        print(f"\n[BLOCKED] Action intercepted by RuntimeVerify!")
        print(f"Policy:   {e.policy_id}")
        print(f"Severity: {e.severity}")
        print(f"Reason:   {e.reason}")
```

---

### 4. Multi-Agent Swarm Verification (Phase 17)
Enforce topological delegation rules across coordinated agent fleets (`planner` $\to$ `coder` $\to$ `tester` $\to$ `executor`):

```python
from runtimeverify.multiagent import (
    AgentRole,
    AgentTopology,
    DelegationPolicy,
    MultiAgentVerifier,
)

# Define legitimate swarm topology
topology = AgentTopology()
topology.add_agent("planner", AgentRole.PLANNER)
topology.add_agent("coder", AgentRole.CODER, parent_id="planner")
topology.add_agent("tester", AgentRole.TESTER, parent_id="planner")
topology.add_agent("executor", AgentRole.EXECUTOR, parent_id="tester")

# Allow coder -> tester handoff, but disallow coder -> executor bypass
topology.allow_delegation("planner", "coder")
topology.allow_delegation("coder", "tester")
topology.allow_delegation("tester", "executor")

verifier = MultiAgentVerifier(topology)

# Legitimate handoff: ALLOW
decision = verifier.verify_delegation(from_agent="coder", to_agent="tester")
assert decision.permitted is True

# Rogue privilege bypass: BLOCK
bypass_decision = verifier.verify_delegation(from_agent="coder", to_agent="executor")
assert bypass_decision.permitted is False
print(f"Bypass Intercepted: {bypass_decision.reason}")
```

---

### 5. CLI Dry-Run & Threat Inspection
Inspect and test actions directly from your terminal using `runtimeverify check`:

```bash
# Permitted: Benign git status check
runtimeverify check --command "git status"

# Blocked: Attempted destructive deletion
runtimeverify check --command "rm -rf /var/data"

# Blocked: Attempted path traversal to cloud credentials
runtimeverify check --file "~/.aws/../.aws/credentials"

# Blocked: Attempted SSRF to AWS EC2 Instance Metadata Service
runtimeverify check --url "http://169.254.169.254/latest/meta-data"
```

---

### 6. Attack & Agent Replay (`runtimeverify replay`)
Replay historical agent execution traces to ask **"What would RuntimeVerify have done?"** or evaluate **"What happens if I change the policy?"**:

```bash
# Replay an attack trace through Policy + Laya + Markov/SPRT defenses
runtimeverify replay examples/traces/credential_access_attack.json

# What-If policy comparison: evaluate impact of tightening policy
runtimeverify replay examples/traces/normal_coding_session.json \
  --policy examples/policies/developer.yaml \
  --compare-policy examples/policies/strict.yaml
```

---

## 💻 CLI Commands Overview

| Command | Description | Example |
|---|---|---|
| `runtimeverify init` | Initialize local workspace and `.runtimeverify/config.yaml` | `runtimeverify init` |
| `runtimeverify check` | Test an action or command against active policies | `runtimeverify check --command "git status"` |
| `runtimeverify replay` | Replay recorded agent traces through multi-layer verification & what-if analysis | `runtimeverify replay trace.json` |
| `runtimeverify run` | Supervise an agent process under runtime enforcement | `runtimeverify run --policy policy.yaml -- python agent.py` |
| `runtimeverify monitor` | Stream real-time events and decisions for an agent | `runtimeverify monitor --agent coding-agent` |
| `runtimeverify policy` | Validate or test policy files | `runtimeverify policy validate policy.yaml` |
| `runtimeverify approvals` | List, approve, or deny actions held for human review | `runtimeverify approvals list` |
| `runtimeverify events` | Query structured audit events and correlation trails | `runtimeverify events --limit 20` |
| `runtimeverify benchmark` | Run security verification benchmarks across threat scenarios | `runtimeverify benchmark --security` |
| `runtimeverify version` | Display version and build information | `runtimeverify version` |

---

## 🏛️ Verification Hierarchy & Architecture

```
                             EVENT DISPATCH
                                   |
                                   v
+-------------------------------------------------------------------+
| LAYER 1: Hard Deterministic Policy Engine                         |
| - Zero-latency, zero-LLM rule matching                            |
| - Path canonicalization & traversal rejection                     |
| - Command pipeline decomposition & dangerous construct scanner    |
| - SSRF / IMDS / Private IP validation                             |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| LAYER 2: Multi-Agent Swarm Topology Guard (Phase 17)              |
| - Topological graph validation (DAG invariants)                   |
| - Delegation & handoff authorization                              |
| - Cross-agent privilege escalation interception                   |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| LAYER 3: Semantic Decision Engine                                 |
| - Zero-shot classification & intent compliance                    |
| - Scope drift & prompt-injection heuristics                       |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| LAYER 4: Behavioral Markov Model                                  |
| - State transition tracking (S_{t-1} -> S_t)                      |
| - Transition anomaly detection against historical baselines       |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| LAYER 5: Wald's SPRT (Sequential Probability Ratio Test)          |
| - Multi-event sequential hypothesis testing                       |
| - Log-likelihood ratio accumulation & dynamic stopping boundaries |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| HYBRID DECISION SYNTHESIS                                         |
| Priority: BLOCK > REVIEW > ALLOW                                  |
+---------------------------------+---------------------------------+
              |                   |                   |
              v                   v                   v
            ALLOW              REVIEW               BLOCK
         (Execute)        (Human Signoff)      (Halt & Alert)
```

---

## 🖥️ Operations Dashboard (SOC Console)

RuntimeVerify includes a production-grade, dark-mode Security Operations Center dashboard built to enterprise design standards:

```bash
# Launch the API server and dashboard
uv run uvicorn runtimeverify.api.app:app --port 8000
```
Open **`http://localhost:8000/`** to access:
- **Topology DAG Canvas**: Interactive SVG representation of the active multi-agent swarm with 1-click bypass attack simulation.
- **SPRT Phase Space Workbench**: Real-time visualization of Wald decision boundaries ($A=+2.944, B=-2.944$) and dynamic drift step injection.
- **Enterprise Scope Bar**: Instant tenant, environment (`PROD`/`STAGING`/`DEV`), and RBAC context switching.
- **Cryptographic Audit Verifier**: 1-click SHA-256 hash-chain verification ensuring 100% untampered block continuity.
- **Interactive Threat Simulator**: Real-time execution against live backend gating endpoints.

---

## 📁 Repository Examples

Ready-to-run examples are available in the [`examples/`](examples/) directory:

- [`examples/quickstart_agent.py`](examples/quickstart_agent.py): Autonomous coding agent session with allowed actions and blocked credential access.
- [`examples/first_policy_demo.py`](examples/first_policy_demo.py): Custom YAML policy loading, rule validation, and policy evaluation.
- [`examples/human_approval_flow.py`](examples/human_approval_flow.py): Human-in-the-loop approval workflow with single-use challenge token verification and replay defense.
- [`examples/policies/`](examples/policies/): Production-ready policy templates (`default.yaml`, `developer.yaml`, `strict.yaml`).

---

## 🛡️ Operational Scope & Boundary Declaration

> [!IMPORTANT]
> RuntimeVerify is an **application-layer runtime verification and interception framework**, not an operating system kernel sandbox (such as Linux namespaces, cgroups, `seccomp`, `bubblewrap`, or `gVisor`).
>
> RuntimeVerify validates, gates, and audits agent tool calls before dispatch. For untrusted, hostile, or multi-tenant agent execution, RuntimeVerify should be deployed *inside* an isolated container or microVM runtime.

For detailed security specifications, see:
- [**Threat Model**](docs/security/threat-model.md): Comprehensive analysis across 13 threat vectors.
- [**Security Model**](docs/security/security-model.md): Defense-in-depth architecture, guarantees, and non-goals.
- [**Enterprise Architecture**](docs/architecture/enterprise-architecture.md): Tenant isolation, RBAC, and OIDC/Keycloak models.
- [**Production Readiness Review**](docs/release/production-readiness.md): Production readiness audit across 16 dimensions.
- [**Vulnerability Reporting Policy**](SECURITY.md): Responsible disclosure channels and SLAs.

---

## 🛠️ Development, Testing & Releases

We welcome contributions! Please review our development guidelines before opening a pull request:

- [**Contributing Guide**](CONTRIBUTING.md): Environment setup, PR quality gates, coding standards, and test integrity rules.
- [**Release Procedures**](docs/release.md): SemVer release workflows, PyPI Trusted Publishing, SHA-256 artifact verification, and rollback procedures.

### Local Quality Verification

```bash
# Code style and formatting
uv run ruff format --check src/ tests/ examples/
uv run ruff check src/ tests/ examples/

# Type checking
uv run mypy src/

# Test suite (all 413 unit, integration, and security tests)
uv run pytest --cov=runtimeverify tests/

# Dependency security audit
uv run pip-audit
```

---

## 📜 License

RuntimeVerify is licensed under the [MIT License](LICENSE).
Copyright (c) 2026 RuntimeVerify Contributors.
