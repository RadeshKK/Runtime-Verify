# RuntimeVerify: Statistical Runtime Verification for AI Agents

`runtimeverify` is a high-performance, non-intrusive framework designed to monitor AI agents in real-time. It transforms raw telemetry streams into symbolic state sequences and applies sequential statistical tests to detect behavioral drift and policy violations before they result in catastrophic failures.

## 🚀 Core Concept

Unlike traditional guardrails that rely on LLM-based "critics" (which are slow and expensive), `runtimeverify` uses **Classical Statistical Process Control (SPC)**. It treats an AI agent's execution as a stochastic process, learning the "normal" transition probabilities between behavioral states and triggering alerts when the agent's trajectory deviates significantly from the learned baseline.

---

## 🛠️ Technical Architecture

### The Verification Pipeline

The system operates as a linear pipeline that transforms raw data into a binary decision (`ALLOW` / `BLOCK`):

1. **Telemetry Interception**: High-fidelity events are captured via the `Telemetry SDK` (using decorators and middleware).
2. **Semantic Encoding**: Raw events are mapped to a finite alphabet of symbolic states $\Sigma$ (e.g., `READ_SENSITIVE_FILE`, `SHELL_EXEC`).
3. **Probabilistic Detection**: A first-order Markov Model estimates the probability of the current transition $P(s_t | s_{t-1})$.
4. **Statistical Accumulation**: The **Sequential Probability Ratio Test (SPRT)** accumulates log-likelihood ratios over time to distinguish between the null hypothesis $H_0$ (normal) and the alternative $H_1$ (drifted).
5. **Policy Enforcement**: The `Policy Engine` maps the statistical result to a mitigation action.

### 🧪 Technical Deep Dive

#### 1. From Raw Event to Symbolic State
The `Semantic State Encoder` reduces the dimensionality of agent logs. A raw event contains noise (timestamps, UUIDs, specific file paths). The encoder applies a rule-set to extract the **intent** or **category**.
* **Raw Event:** `{ "type": "tool_call", "tool": "write_file", "path": "/etc/shadow", "content": "..." }`
* **Encoded State:** `SENSITIVE_WRITE`
This allows the Markov model to operate on a finite set of tokens rather than an infinite set of unique strings.

#### 2. Mathematical Foundation: SPRT
The heart of the detector is the **Wald's Sequential Probability Ratio Test**. Instead of making a decision based on a single transition, we maintain a cumulative log-likelihood ratio $\Lambda_t$:

$$\Lambda_t = \Lambda_{t-1} + \ln \frac{P(s_t \mid s_{t-1}; H_1)}{P(s_t \mid s_{t-1}; H_0)}$$

**Numerical Stability Measures:**
To prevent floating-point underflow or $\ln(0)$ errors (which occur when a transition is never seen during training), the framework implements:
* **Probability Flooring:** Every probability is clamped to a minimum value $\epsilon$ (e.g., $1e-10$).
* **Log-Domain Computation:** Calculations are performed in the log-space to maintain precision over long execution sequences.

**Decision Boundaries:**
- $\Lambda_t \ge \ln(\frac{1 - \beta}{\alpha}) \implies$ **Reject $H_0$** (Anomaly Detected)
- $\Lambda_t \le \ln(\frac{\beta}{1 - \alpha}) \implies$ **Accept $H_0$** (Reset Accumulator)
- Otherwise $\implies$ **Continue Sampling**

---

## 📦 Package Overview

| Package | Responsibility | Key Components |
| :--- | :--- | :--- |
| `telemetry` | Event capture and propagation | `EventBus`, `trace_tool`, `TelemetryEngine` |
| `encoder` | Semantic mapping & caching | `EncodingPipeline`, `ContextAwareEncoder` |
| `detector` | Statistical modeling | `MarkovBehaviorModel`, `SPRTDetector` |
| `engine` | Orchestration & session mgmt | `RuntimeEngine`, `VerificationSession` |
| `policy` | Rule-based mitigation | `PolicyEngine`, `PolicyViolationError` |
| `evaluation`| Benchmarking & metrics | `BenchmarkRunner`, `MetricsCalculator` |
| `cli` | Developer interface | `train`, `benchmark`, `observe` |

---

## 👩‍💻 Developer's Guide to Extension

`runtimeverify` is designed to be extensible via Abstract Base Classes (ABCs).

### Implementing a Custom Detector
To add a new statistical method (e.g., a CUSUM detector), inherit from `BaseDetector`:
```python
from runtimeverify.detector.interfaces import BaseDetector
from runtimeverify.detector import DetectorResult

class MyCustomDetector(BaseDetector):
    def train(self, trace_sequences):
        # Implement training logic here
        pass

    def update(self, current_state: str) -> DetectorResult:
        # Implement your statistical test here
        return DetectorResult(deviation_score=0.5, decision="NORMAL", evidence={})

    def reset(self):
        # Reset internal counters
        pass
```

### Adding Encoding Rules
Custom state mappings can be added to the `ContextAwareEncoder` via YAML configuration without changing the code:
```yaml
- event_type: "tool_call_start"
  conditions:
    tool_name: "web_search"
    query_contains: "competitor"
  target_state: "COMPETITOR_RESEARCH"
```

---

## 🚀 Getting Started

### Installation
```bash
pip install .
```

### Training a Model
Collect a set of "golden" traces (JSON files) where the agent behaves correctly:
```bash
runtimeverify train ./data/golden_traces/ --output behavior_model.json
```

### Benchmarking a Detector
Evaluate the model against a labeled dataset to calculate FPR and FNR:
```bash
runtimeverify benchmark ./data/test_set.json behavior_model.json --config eval_config.yaml
```

### Live Observation
Monitor a live telemetry stream:
```bash
runtimeverify observe --model behavior_model.json --stream agent_logs.jsonl
```

---

## 📊 Performance Metrics

The framework is optimized for low-latency inline guardrails. In benchmark tests, the pipeline achieves:
- **Encoding Latency**: $< 0.5\text{ms}$
- **Detection Overhead**: $\approx 1\text{ms}$ per transition.
- **Memory Footprint**: $\mathcal{O}(|\Sigma|^2)$ where $|\Sigma|$ is the size of the state alphabet.

## 🗺️ Roadmap
- [ ] **HMM Integration**: Moving beyond first-order Markov chains to Hidden Markov Models for latent goal tracking.
- [ ] **OTLP Export**: Native support for OpenTelemetry for enterprise observability.
- [ ] **LTL Policies**: Support for Linear Temporal Logic to define complex forbidden sequences (e.g., $S_1 \rightarrow \text{not } S_2 \rightarrow S_3$).
