# Policy Engine & Guardrails

This document describes the design, configuration schema, and mitigation actions of the `runtimeverify` Policy Engine.

---

## 🎯 Role of the Policy Engine

While the **Detector** evaluates *how anomalous* an agent's behavior is, the **Policy Engine** decides *what to do* about it. 

The Policy Engine ingests the output of the Detector (`DetectorResult`), along with the current transition context, and matches them against a declarative set of safety policies. By separating statistical detection from rule enforcement, we allow security and operations teams to dynamically adjust thresholds and mitigation strategies without re-training models.

---

## 🛡️ Policy Rule Types

The Policy Engine supports two classes of evaluation rules:

### 1. Probabilistic Threshold Rules
These rules monitor statistical deviation metrics (such as the SPRT log-likelihood ratio $\Lambda_t$) returned by the Detector.
* **Example:** *"If the cumulative log-likelihood ratio exceeds $12.0$ (signifying extremely high confidence of a behavioral shift), intercept and pause execution."*

### 2. Invariant & Temporal Rules
In addition to statistical anomalies, the Policy Engine can enforce absolute boundary conditions or temporal sequences (similar to Linear Temporal Logic - LTL).
* **Example:** *"An agent must never transition from a state of reading sensitive environment secrets (`SENSITIVE_READ`) directly to calling an external web request (`API_FETCH`) without an intervening user verification step (`USER_APPROVAL`)."*

---

## 🚦 Action Mitigations

When a rule is triggered, the Policy Engine can enforce several response types:

| Action | Latency Impact | Description |
| :--- | :--- | :--- |
| **`ALLOW`** | Zero | The event is logged, and the agent continues execution. Used for passive logging. |
| **`ALERT`** | Negligible | The agent continues execution, but a high-priority webhook or event is fired to operations alerts (Slack, Prometheus). |
| **`BLOCK`** | Low | The engine raises a `PolicyViolationError` that blocks the current tool invocation or agent step, forcing the orchestrator to handle the error or halt. |
| **`PAUSE`** | High (Interrupts) | The execution thread is blocked. The runtime suspends execution and requests manual confirmation from a human supervisor via the CLI or a web dashboard. |
| **`FALLBACK`** | Low | The engine swaps the current execution context (e.g., replaces the system prompt with a restricted prompt, or disables file-writing tools) and resumes. |

---

## 💻 Developer API: `PolicyEngine`

The policy interface is located in [runtimeverify/policy/](file:///D:/runtime-verify/runtimeverify/policy/):

```python
from typing import Dict, Any
from runtimeverify.detector import DetectorResult

class PolicyViolationError(Exception):
    """Exception raised when a policy action is set to BLOCK."""
    pass

class PolicyEngine:
    def __init__(self, rules: List[Dict[str, Any]]):
        self.rules = rules

    def evaluate(self, transition: Dict[str, str], detector_result: DetectorResult) -> str:
        """
        Evaluate rules against the current transition and detector results.
        
        Args:
            transition: Dict containing 'from_state' and 'to_state'.
            detector_result: The result payload from the statistical detector.
            
        Returns:
            The resolved action string (e.g., "BLOCK", "PAUSE", "ALLOW").
        """
        # Rule evaluation logic here
        return "ALLOW"
```

---

## ⚙️ Configuration Schema

Policies are declared via YAML configuration files:

```yaml
policy:
  global_action: "ALLOW"
  rules:
    # 1. Block extremely anomalous behavior
    - name: "strict_drift_prevention"
      trigger:
        detector_decision: "DRIFT"
        min_deviation_score: 15.0
      action: "BLOCK"

    # 2. Require approval for elevated sequence changes
    - name: "warning_drift_investigation"
      trigger:
        min_deviation_score: 8.0
      action: "PAUSE"

    # 3. Structural invariant constraint
    - name: "secret_leak_protection"
      trigger:
        transition:
          from_state: "READ_SECRETS"
          to_state: "API_FETCH"
      action: "BLOCK"
```
