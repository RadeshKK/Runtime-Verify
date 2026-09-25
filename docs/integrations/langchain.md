# LangChain & LangGraph Integration

RuntimeVerify provides first-class support for [LangChain](https://github.com/langchain-ai/langchain) and LangGraph via public, officially supported callback and tool interceptor interfaces.

> [!IMPORTANT]
> The integration does **not** monkey-patch private runtime internals. It leverages LangChain's public `BaseCallbackHandler` lifecycle events and explicit tool wrappers.

---

## 1. `RuntimeVerifyCallbackHandler`

`RuntimeVerifyCallbackHandler` integrates into LangChain's callback system to inspect, evaluate, and gate tool invocations and LLM requests in real time.

### Public Lifecycle Hooks Supported

| Hook | Description | Security Action |
| :--- | :--- | :--- |
| `on_tool_start` | Triggered before a tool begins running. | Evaluates policy. Raises `ExecutionBlockedError` if `BLOCK`. |
| `on_tool_end` | Triggered upon tool completion. | Logs execution result and output telemetry to audit sink. |
| `on_tool_error` | Triggered when a tool raises an exception. | Logs error details to audit repository. |
| `on_agent_action` | Triggered when the agent decides an action. | Audits agent action step and rationale log. |
| `on_llm_start` | Triggered before prompt submission. | Records prompt count, target model, and session context. |
| `on_llm_end` | Triggered when LLM generation finishes. | Records response telemetry and latency. |

### Integration Example: LangChain AgentExecutor

```python
import runtimeverify
from runtimeverify.integrations.langchain import RuntimeVerifyCallbackHandler
from langchain_community.agent_toolkits import create_react_agent
# Or standard LangChain AgentExecutor

# 1. Start a scoped session
with runtimeverify.session(agent_id="analyst-agent", environment="production") as session:
    # 2. Instantiate the callback handler
    handler = RuntimeVerifyCallbackHandler(
        session=session,
        fail_closed=True,  # Blocks execution if evaluation encounters an unexpected failure
    )

    # 3. Pass handler into LangChain invoke config
    response = agent_executor.invoke(
        {"input": "Read the secrets in ~/.ssh/id_rsa"},
        config={"callbacks": [handler]},
    )
```

If the agent attempts to execute an action violating configured security policies (e.g. `deny-ssh-keys`), `on_tool_start` raises `ExecutionBlockedError`, immediately terminating execution before the tool runs.

---

## 2. Tool Guarding with `guard_langchain_tool`

In addition to callbacks, you can explicitly guard individual LangChain tools (`BaseTool` subclasses or custom callables):

```python
from langchain_community.tools import ShellTool
import runtimeverify
from runtimeverify.integrations.langchain import guard_langchain_tool

with runtimeverify.session(agent_id="terminal-agent") as session:
    raw_shell = ShellTool()

    # Wrap the tool with runtime verification
    guarded_shell = guard_langchain_tool(raw_shell, session=session)

    # Calling run/invoke evaluates deterministic policies first
    # Permitted command:
    output = guarded_shell.run("git status")

    # Blocked command (raises ExecutionBlockedError):
    guarded_shell.run("rm -rf /")
```

---

## 3. Enforcement vs Observe Mode

- **Enforce Mode (`mode=InterceptionMode.ENFORCE`)**:
  - `on_tool_start` halts execution on `BLOCK` decisions by raising `ExecutionBlockedError`.
  - Guarantees zero side effects on unauthorized operations.
- **Observe Mode (`mode=InterceptionMode.OBSERVE`)**:
  - Tool calls are evaluated and logged with their security classification (`ALLOW`, `REVIEW`, `BLOCK`), but execution is **not** halted.
  - Ideal for auditing baseline agent behavior and profiling production traffic before enforcing restrictive policies.

---

## 4. Audit & Telemetry Correlation

Every LangChain event processed by `RuntimeVerifyCallbackHandler` retains the active session correlation identifiers:
- `session_id`: Unique identifier spanning the agent task.
- `agent_id`: Logical agent identifier (e.g., `analyst-agent`).
- `trace_id`: Distributed trace identifier across multi-agent handoffs.
- `environment`: Tier designation (`development`, `staging`, `production`).

All records are automatically written to the configured `AuditSink` (in-memory, file, SIEM, or database).
