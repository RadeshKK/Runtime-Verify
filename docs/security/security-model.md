# RuntimeVerify Security Model

**Document Version:** 1.0  
**Phase:** 14 (Security Hardening)  
**Classification:** Architecture & Security Specification  

---

## 1. Executive Summary

RuntimeVerify is a multi-tier runtime security verification and governance engine designed for autonomous AI agents.

As AI agents transition from stateless conversational assistants to agentic workflows possessing tool execution capabilities (filesystem access, shell command dispatch, network communication, database access), traditional perimeter security becomes insufficient. RuntimeVerify intercepts, analyzes, decides, and audits agent actions at runtime before host execution takes place.

---

## 2. Core Security Philosophy & Invariants

RuntimeVerify operates on five fundamental architectural principles:

1. **Defense in Depth**: No single verification layer is trusted exclusively. Hard deterministic policies, semantic classification, behavioral Markov transition modeling, and statistical sequential tests operate concurrently.
2. **Explicit Decision Strategies**: Disparate signals are never averaged into ambiguous composite scores. Decisions are synthesized via deterministic priority hierarchies: `BLOCK > REVIEW > ALLOW`.
3. **Fail-Closed by Default**: When ambiguous or high-risk actions encounter timeouts, evaluation failures, or unparseable inputs, RuntimeVerify fails closed and halts execution.
4. **Zero-Secret Observability**: Secrets, tokens, and private keys are redacted at the ingestion boundary before any telemetry is evaluated, displayed, logged, or persisted.
5. **Non-Repudiation & Cryptographic Traceability**: Every evaluation, decision, and human operator approval is recorded in a cryptographically hash-chained audit log.

---

## 3. Defense-in-Depth Hierarchy

The verification pipeline executes four progressive layers of analysis for every canonical event:

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
| LAYER 2: Semantic Decision Engine                                 |
| - NLI zero-shot classification / embeddings distance               |
| - Intent and declared scope compliance                            |
| - Risk scoring and anomaly classification                         |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| LAYER 3: Behavioral Markov Model                                  |
| - State transition probability tracking                           |
| - Transition anomaly detection against historical baselines       |
| - Graph deviation measurement                                     |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| LAYER 4: Wald's SPRT (Sequential Probability Ratio Test)          |
| - Multi-event sequential hypothesis testing                       |
| - Log-likelihood ratio accumulation                               |
| - Dynamic stopping boundaries (A, B) for persistent drift         |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
| SYNTHESIS: Hybrid Decision Engine                                 |
| Resolves outcomes to ALLOW, REVIEW, or BLOCK                      |
+---------------------------------+---------------------------------+
                                  |
              +-------------------+-------------------+
              |                   |                   |
              v                   v                   v
            ALLOW              REVIEW               BLOCK
         (Execute)        (Human Approval)     (Halt & Alert)
```

### Layer Details

1. **Deterministic Policy Engine (`runtimeverify.policy`)**:
   - Evaluates deterministic rules against canonical events.
   - Enforces path containment (`SecurePathNormalizer`), extracts compound shell subcommands (`CommandPipelineParser`), and blocks cloud metadata endpoints (`NetworkDestinationValidator`).
   - If any rule renders a `BLOCK`, the pipeline terminates immediately without waiting for semantic classifiers.

2. **Semantic Decision Engine (`runtimeverify.semantic`)**:
   - Assesses intent, context, and semantic alignment with declared task goals.
   - Computes semantic risk scores and detects prompt injection indicators.

3. **Behavioral Markov Model (`runtimeverify.behavioral`)**:
   - Tracks state sequences ($S_{t-1} \to S_t$) across tool invocations.
   - Identifies statistically improbable state transitions that deviate from pre-established agent baselines.

4. **Sequential Probability Ratio Test (`runtimeverify.sprt`)**:
   - Detects low-and-slow behavioral drift across multiple sequential events.
   - Uses log-likelihood ratio accumulation between nominal ($H_0$) and adversarial ($H_1$) hypotheses.

---

## 4. Human Approval Workflow & Challenge Token Security

When the decision engine renders a `REVIEW` verdict, execution is paused and an approval request is generated:

1. **Challenge Token Generation**: A 256-bit URL-safe token is generated using `secrets.token_urlsafe(32)`.
2. **Replay Protection**: The token is bound exclusively to the specific `request_id`.
3. **Linear State Transition**: The ticket transitions from `PENDING` to `APPROVED` or `DENIED`. Once transitioned, any subsequent decision attempt is rejected with `DuplicateApprovalError`.
4. **Timing-Attack Resistance**: Token verification utilizes constant-time comparison (`hmac.compare_digest`).

---

## 5. Audit Trail & Cryptographic Chain of Custody

All system activity produces structured `AuditRecord` objects with SHA-256 hash chaining:

$$H_i = \text{SHA-256}\left(\text{record\_id} \parallel \text{timestamp} \parallel \text{type} \parallel \text{summary} \parallel \text{canonical\_details} \parallel H_{i-1}\right)$$

- **Genesis Anchor**: The initial record links to a well-known `GENESIS` hash ($0^{64}$).
- **Tamper Evidence**: Modification of any record, payload tampering, line deletion, or sequence reordering invalidates subsequent record hashes.
- **Repository Verification**: Both memory and file repositories provide `verify_integrity()`, ensuring continuous auditability for compliance and forensics.

---

## 6. What RuntimeVerify Guarantees

- **Deterministic Rule Enforcement**: If a rule forbids a path, command, or network destination, that action is blocked deterministically before execution.
- **Explainability**: Every decision returns structured evidence explaining *WHAT* happened, *WHY* it was suspicious, *WHICH* controls triggered, and *WHAT* action was taken.
- **Cryptographic Audit Integrity**: All events and decisions are hash-chained; tampering is mathematically detectable.
- **Secret Redaction**: Credentials, tokens, and private keys are scrubbed before persistence or transmission.
- **Approval Non-Replayability**: Approved tickets cannot be reused to authorize subsequent actions.

---

## 7. Explicit Non-Goals & Architectural Boundaries

> [!CAUTION]
> **No Kernel Isolation or Hardware Sandboxing Claim:**  
> RuntimeVerify is NOT an operating system sandbox or hypervisor.
> 
> - RuntimeVerify does **not** manage Linux kernel namespaces, cgroups, `seccomp` filters, or chroot environments.
> - RuntimeVerify does **not** provide hardware virtualization, container isolation (Docker/Podman), or microVM execution (Firecracker/gVisor).
> - If an agent process is granted raw root access, direct kernel syscall execution, or unmonitored sub-processes outside the SDK/interceptor hooks, RuntimeVerify cannot prevent direct OS exploitation.
> 
> **Recommended Deployment Architecture:**  
> Deploy RuntimeVerify as the **policy and verification governor** *inside* an isolated container or microVM (e.g. gVisor, Docker with non-root user, or Firecracker), creating an layered defense against both behavioral misbehavior and OS-level compromise.
