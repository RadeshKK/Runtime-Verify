# Telemetry & Collection SDK

This document describes how telemetry is generated, intercepted, structured, and exported within the `runtimeverify` framework.

---

## 📋 The Telemetry Event Model

The foundation of runtime verification is structured, high-fidelity telemetry. The framework collects event traces from the agent's runtime. Every telemetry event is structured as a JSON-compatible record:

```json
{
  "trace_id": "93843fb-cc34-4968-b615-7f63cafeb43a",
  "event_id": "evt_01j1xyz",
  "timestamp": "2026-07-19T19:05:42.123Z",
  "event_type": "tool_call_start",
  "source": "coder_agent",
  "payload": {
    "tool_name": "execute_command",
    "arguments_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "metadata": {
      "command": "git commit -m 'update docs'"
    }
  }
}
```

### Supported Event Types

The SDK standardizes agent behavior into the following core event types:

| Event Type | Emitted When | Payload Metadata |
| :--- | :--- | :--- |
| `agent_start` | Agent run initializes | Agent name, system instructions hash, session configs |
| `agent_step_start` | A plan, thought, or reasoning step begins | Step name, model parameters |
| `agent_step_end` | Agent reasoning step completes | Token counts, duration, raw model response summary |
| `tool_call_start` | Agent initiates tool execution | Tool name, argument hashes, parameter names |
| `tool_call_end` | Tool execution finishes | Status (success/error), execution duration, output hash |
| `agent_error` | An unhandled exception occurs | Exception class, error message, stack trace |
| `agent_end` | Agent finalizes its execution loop | Final output signature, total run latency, total tokens |

---

## 🛠️ SDK Instrumentation APIs

`runtimeverify` provides multiple helper methods to trace applications with minimal code footprint.

### 1. Function Decorators
Ideal for standalone Python agent loops and custom tool functions.

```python
from runtimeverify.telemetry import trace_agent, trace_tool

@trace_tool(name="execute_python_script")
def run_python(code: str) -> str:
    # Tool logic here
    return "success"

@trace_agent(name="code_writer")
def run_agent_loop(prompt: str):
    # Agent orchestrations
    run_python("print('hello')")
```

### 2. Context Managers
Useful when tracing specific code blocks within a larger function.

```python
from runtimeverify.telemetry import start_trace

with start_trace(trace_id="session_123") as tracer:
    # Perform agent actions
    tracer.log_event("custom_state_change", {"state": "analyzing_results"})
```

### 3. Middleware & Integrations
We provide native integrations for popular orchestrator frameworks:
- **LangGraph:** Graph listener interceptors to monitor transitions between node tasks.
- **PydanticAI:** Standard instrumentation handlers.
- **CrewAI / AutoGen:** Task-level callback handlers.

---

## 📤 Telemetry Exporters

Exporters manage the lifecycle and destination of emitted telemetry events. The `TelemetryEngine` can register multiple exporters:

### `InMemoryExporter`
Stores events in a local thread-safe list. Typically used in:
- Synchronous inline runtime verification.
- Unit testing behavior models and detectors.

### `JSONFileExporter`
Appends telemetry events to a file on disk. 
* **Primary Use Case:** Gathering large datasets of "normal agent behavior" during staging or evaluation runs. These logs are later used to train Markov transition tables and statistical threshold limits offline.

### `ConsoleExporter`
Outputs stylized telemetry logs to standard output using the `rich` library. Useful for real-time debugging during agent development.

### `OTLPExporter` (Planned)
Translates agent event schemas into standard OpenTelemetry traces, pushing them to centralized platforms like Jaeger, OpenTelemetry Collector, or Datadog.
