# Semantic State Encoding

This document describes how raw, high-dimensional telemetry traces are mapped into discrete state representations suited for statistical verification.

---

## 🧭 Why Do We Encode States?

AI agent trace logs contain a rich set of information: tool arguments, response payloads, plan descriptions, and dynamic execution timing. However, this raw data is too high-dimensional and variable to feed directly into classic statistical detectors (such as Markov Chains or Sequential Probability Ratio Tests).

**State Encoding** is the process of mapping a raw telemetry event $e_t$ to a discrete symbolic state $s_t$ from a predefined vocabulary (or alphabet) $\Sigma$:

$$E = (e_1, e_2, \dots, e_t) \xrightarrow{\text{StateEncoder}} S = (s_1, s_2, \dots, s_t) \quad \text{where } s_i \in \Sigma$$

This simplification reduces noise, highlights the behavioral structure (transitions), and makes probabilistic modeling computationally lightweight and statistically sound.

---

## 🛠️ Supported Encoding Strategies

`runtimeverify` provides three primary encoders out of the box:

### 1. `TypeBasedEncoder` (Simplest)
Maps events based entirely on the `event_type` and, in the case of tool calls, the `tool_name`.
* **Example Mapping Rules:**
  - `agent_start` $\rightarrow$ `START`
  - `agent_step_start` $\rightarrow$ `THINK`
  - `tool_call_start` with `tool_name="read_file"` $\rightarrow$ `READ_FILE`
  - `tool_call_start` with `tool_name="write_file"` $\rightarrow$ `WRITE_FILE`
  - `agent_error` $\rightarrow$ `ERROR`
* **Best For:** Tracking logical loops and broad tool-usage flows.

### 2. `ContextAwareEncoder`
Inspects event arguments, return values, or execution context to assign more specific states.
* **Example Mapping Logic:**
  * If a `tool_call_start` for `write_file` targets a sensitive file like `.env` or `/etc/hosts`, it encodes as `SENSITIVE_WRITE`.
  * If it targets a temp file in `workspace/scratch/`, it encodes as `TEMPORARY_WRITE`.
* **Best For:** Finer grain safety policies where the *arguments* of tool usage are critical to distinguishing normal behavior from exploit attempts.

### 3. `RegexStateEncoder`
Uses regular expressions applied to planning thoughts, error messages, or shell commands to bucket execution steps into symbolic bins.
* **Best For:** Identifying state changes based on agent command-line usage or textual log strings.

---

## 💻 Developer API: `BaseStateEncoder`

All encoders inherit from the `BaseStateEncoder` interface located in [runtimeverify/encoder/](file:///D:/runtime-verify/runtimeverify/encoder/):

```python
from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseStateEncoder(ABC):
    """Abstract Base Class for encoding telemetry events into symbolic states."""
    
    @abstractmethod
    def encode(self, event: Dict[str, Any]) -> str:
        """
        Processes a raw telemetry event and returns its discrete symbolic state.
        
        Args:
            event: A telemetry event dict.
            
        Returns:
            A string token representing the encoded state (e.g., 'TOOL_EXEC').
        """
        pass
```

---

## ⚙️ Configuration Example

Below is a configuration file defining a state encoding schema:

```yaml
encoder:
  type: "ContextAwareEncoder"
  rules:
    - event_type: "agent_start"
      target_state: "INIT"
    
    - event_type: "tool_call_start"
      conditions:
        tool_name: "execute_command"
        arguments:
          command: "^(git|uv|python|pytest)\\s"
      target_state: "SAFE_SHELL"

    - event_type: "tool_call_start"
      conditions:
        tool_name: "execute_command"
      target_state: "UNTRUSTED_SHELL"

    - event_type: "agent_error"
      target_state: "FAIL"
```
