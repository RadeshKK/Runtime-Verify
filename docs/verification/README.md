# Phase 6: Hybrid Runtime Verification Engine

RuntimeVerify provides an industry-grade, vendor-neutral hybrid verification pipeline for autonomous AI agents. The engine synthesizes:

1. **Deterministic Security Policies** (`PolicyEvaluator` / YAML policies)
2. **Semantic Decision Engines** (Laya router / intent classification)
3. **Behavioral Anomaly Detection** (`MarkovModel` / sequence probabilities)
4. **Sequential Statistical Verification** (`SPRTEngine` / Wald's SPRT)

Rather than simply averaging or weighting heuristic risk scores, RuntimeVerify uses an **explicit, deterministic decision precedence hierarchy**. Every decision produces full, tamper-evident audit evidence and directly answers the 5 mandatory compliance and audit questions.

---

## 1. Pipeline Architecture

```
                       INCOMING ACTION / EVENT
                                  │
         ┌────────────────────────┴────────────────────────┐
         │                                                 │
         ▼                                                 ▼
   Deterministic                                     Semantic Engine
   Policy Engine                                    (Laya / Intent)
   [ALLOW / REVIEW / BLOCK]                         [ALLOW / REVIEW / BLOCK]
         │                                                 │
         └────────────────────────┬────────────────────────┘
                                  │
                                  ▼
                       Behavioral Markov Model
                       P(s_t | s_{t-1})
                                  │
                                  ▼
                       Sequential SPRT Engine
                       Wald's SPRT (H0 vs H1)
                                  │
                                  ▼
                   Hybrid Decision Strategy Engine
                   (Strict 8-Tier Precedence)
                                  │
               ┌──────────────────┼──────────────────┐
               ▼                  ▼                  ▼
             ALLOW              REVIEW             BLOCK
```

---

## 2. Decision Precedence Hierarchy

The synthesis engine enforces strict precedence where hard security rules and critical risks unconditionally override permissive baselines:

| Tier | Signal / Subsystem | Condition | Verdict | Resulting Action |
|:---:|:---|:---|:---:|:---:|
| **1** | **Deterministic Policy** | Policy evaluated to `BLOCK` | `BLOCK` | `BLOCK` |
| **2** | **Semantic Classifier** | Semantic risk is `CRITICAL` (Confidence $\ge$ `semantic_min_confidence`) | `BLOCK` | `BLOCK` |
| **3** | **Deterministic Policy** | Policy evaluated to `REVIEW` (escalated to `BLOCK` if semantic says `BLOCK`) | `REVIEW` / `BLOCK` | `HOLD_FOR_APPROVAL` / `BLOCK` |
| **4** | **Statistical SPRT Drift** | Cumulative LLR crosses upper threshold (`ACCEPT_H1` / `REJECT_H0`) | `REVIEW` | `HOLD_FOR_APPROVAL` |
| **5** | **Semantic Classifier** | Semantic risk is `HIGH` or signal is `REVIEW` (Confidence $\ge$ `semantic_min_confidence`) | `REVIEW` | `HOLD_FOR_APPROVAL` |
| **6** | **Combined Risk** | Moderate semantic risk (`MEDIUM`) + Rare Markov transition ($P < \text{threshold}$) | `REVIEW` | `HOLD_FOR_APPROVAL` |
| **7** | **Markov Anomaly** | Single transition probability $P < \text{markov_anomaly_prob_threshold}$ | `REVIEW` | `HOLD_FOR_APPROVAL` |
| **8** | **Benign Baseline** | No policy matches, low semantic risk, normal sequence probability | `ALLOW` | `EXECUTE` |

### Conflict Resolution Principles
- **BLOCK overrides REVIEW**: A deterministic or high-confidence semantic `BLOCK` can never be relaxed by a benign Markov probability or neutral signal.
- **REVIEW overrides ALLOW**: If an action is held for human review by a deterministic policy, semantic risk detector, Markov anomaly, or SPRT drift, it cannot be auto-executed.
- **No Score Averaging**: Probabilities and risk categories are not mashed into an arbitrary floating-point average. Each control maintains clear, accountable ownership of its decision.
- **Multi-Signal Correlation**: Sub-threshold risks (e.g., a `MEDIUM` risk semantic intent paired with a statistically anomalous Markov transition) escalate into a `REVIEW` verdict.

---

## 3. Five-Question Audit & Explainability Contract

Every [`VerificationResult`](file:///D:/runtime-verify/src/runtimeverify/verification/models.py) includes a structured [`DecisionExplanation`](file:///D:/runtime-verify/src/runtimeverify/verification/models.py) answering five core questions:

1. **WHAT happened?**
   - Synthesizes the agent identity, operation type, target resource, and environment context.
2. **WHY was it suspicious?**
   - Explains the underlying trigger (e.g. prohibited regex pattern, high-risk intent classification, statistically rare transition, sequential trajectory drift).
3. **WHICH controls triggered?**
   - Explicit list of control IDs (e.g. `["policy:deny-ssh-keys"]`, `["semantic:laya:critical"]`, `["sprt:wald_upper_threshold"]`).
4. **WHETHER the behavior deviated from baseline?**
   - Boolean flag indicating whether the Markov or SPRT statistical engine detected an anomaly or drift.
5. **WHAT action was taken?**
   - Runtime outcome: `EXECUTE`, `HOLD_FOR_APPROVAL`, or `BLOCK`.

---

## 4. Configuration & Thresholds Reference

All parameters are transparently configured through [`VerificationEngineConfig`](file:///D:/runtime-verify/src/runtimeverify/verification/models.py) with zero hardcoded magic numbers:

```python
from runtimeverify.verification import VerificationEngineConfig

config = VerificationEngineConfig(
    # Deterministic controls
    policy_block_enabled=True,
    policy_review_enabled=True,

    # Semantic thresholds
    semantic_min_confidence=0.60,
    semantic_critical_escalates_to="BLOCK",
    semantic_high_escalates_to="REVIEW",
    semantic_noul_review_threshold=0.75,

    # Markov behavioral thresholds
    markov_anomaly_prob_threshold=1e-4,
    markov_anomaly_escalates_to="REVIEW",

    # SPRT statistical thresholds
    sprt_drift_escalates_to="REVIEW",
    sprt_alpha=0.05,
    sprt_beta=0.05,

    # Correlation & safety
    combined_risk_escalation=True,
    fail_closed=True,
)
```

---

## 5. Structured Output Example

```json
{
  "verification_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "decision": "BLOCK",
  "risk_level": "CRITICAL",
  "confidence": 1.0,
  "reason": "Deterministic security policy violation: Access to SSH private keys is prohibited.",
  "explanation": {
    "what_happened": "Agent 'code-assistant-01' attempted filesystem action targeting '/root/.ssh/id_rsa'. (Environment: production)",
    "why_suspicious": "Explicitly forbidden by deterministic rule 'deny-ssh-keys': Access to SSH private keys is prohibited.",
    "which_controls_triggered": [
      "policy:deny-ssh-keys"
    ],
    "behavioral_deviation": false,
    "action_taken": "BLOCK",
    "summary": "[BLOCK] Deterministic security policy violation: Access to SSH private keys is prohibited."
  },
  "evidence": [
    {
      "source": "DETERMINISTIC_POLICY",
      "source_name": "policy_evaluator",
      "severity": "CRITICAL",
      "title": "Policy Triggered: deny-ssh-keys",
      "description": "Access to SSH private keys is prohibited.",
      "data": {
        "decision": "BLOCK",
        "policy_id": "deny-ssh-keys",
        "severity": "CRITICAL",
        "matched_rule": {
          "id": "deny-ssh-keys",
          "severity": "CRITICAL"
        }
      }
    }
  ],
  "policy_matches": [
    {
      "id": "deny-ssh-keys",
      "severity": "CRITICAL"
    }
  ],
  "agent_id": "code-assistant-01",
  "session_id": "sess-production-104",
  "environment": "production",
  "action_type": "filesystem",
  "target": "/root/.ssh/id_rsa",
  "latency_ms": 1.42
}
```

---

## 6. Programmatic Usage

### Direct Engine Verification
```python
from runtimeverify.interception import Action
from runtimeverify.verification import VerificationEngine, VerificationEngineConfig

engine = VerificationEngine(
    config=VerificationEngineConfig(),
    policy_evaluator=evaluator,
    semantic_engine=laya_engine,
    markov_adapter=markov_adapter,
    sprt_engine=sprt_engine,
)

action = Action.shell(
    command="git push origin main",
    session_id="session-123",
    agent_id="agent-007",
)

result = engine.verify(action)
print(result.decision)       # "REVIEW"
print(result.explanation)    # 5-question audit breakdown
```

### Full Runtime Interception Integration
```python
from runtimeverify.interception import RuntimeActionInterceptor, InterceptionMode

interceptor = RuntimeActionInterceptor(
    mode=InterceptionMode.ENFORCE,
    policy_evaluator=evaluator,
    semantic_engine=laya_engine,
    behavioral_adapter=markov_adapter,
    sprt_engine=sprt_engine,
)

decision, result = interceptor.intercept(action)
# decision.verification_result contains full audit trail & 5-question explanation
```
