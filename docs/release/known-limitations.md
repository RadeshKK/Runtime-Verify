# Known Limitations and Operational Constraints

**Version:** 1.0.0  
**Status:** Official Technical Disclosure  
**Target Platform:** RuntimeVerify  

---

## 1. Scope & Purpose

RuntimeVerify is designed to provide real-time behavioral verification, statistical anomaly detection, and deterministic policy enforcement for autonomous AI agents. To ensure operational safety and prevent architectural misunderstandings, this document formally specifies the platform's known technical boundaries, performance trade-offs, and non-goals.

---

## 2. Technical Limitations & Operational Boundaries

### 1. Verification vs. OS Kernel Sandboxing

- **Architecture Principle**: RuntimeVerify is an **application-layer runtime verification and policy enforcement framework**. It intercepts agent function calls, tool invocations, and command lines before execution.
- **Operational Reality**: RuntimeVerify is **not** an operating-system-level sandbox (such as Linux `seccomp-bpf`, `cgroups`, Docker container isolation, or a hypervisor like Firecracker/gVisor).
- **Boundary**: If an autonomous agent process executes native binary code, memory corruption exploits, or direct kernel syscalls that bypass the Python runtime interceptors, RuntimeVerify cannot block them at the kernel level.
- **Mitigation**: Deploy RuntimeVerify alongside container isolation (Docker/Kubernetes non-root containers with read-only root filesystems and restricted Linux capabilities).

---

### 2. Node-Local In-Memory State Tracking

- **Architecture Principle**: By default, `SessionManager`, `SPRTEngine`, `ApprovalStore`, and `PartitionedStore` maintain operational state in thread-safe, in-process memory structures to guarantee sub-millisecond verification latency (< 0.5 ms).
- **Operational Reality**: In multi-instance cluster deployments (e.g. running 5 Kubernetes pods behind an ingress load balancer), session state is local to each pod.
- **Boundary**: If successive requests from the same agent session are routed across different pods without sticky sessions, Markov transition histories and SPRT likelihood ratios will not be synchronized across nodes.
- **Mitigation**: Configure ingress session stickiness (e.g., cookie-based or header-based routing on `X-Session-ID`) or deploy the forthcoming Redis distributed state adapter for cluster deployments.

---

### 3. Semantic Engine Classification Latency

- **Architecture Principle**: Deterministic policy evaluation and Markov/SPRT statistical checks execute in microseconds. However, zero-shot LLM semantic intent classification (the `Laya` semantic engine) requires model inference.
- **Operational Reality**: Invoking local or remote LLM semantic classifiers synchronously on the critical path of an agent tool call adds between **50 ms and 300 ms** of latency per action.
- **Boundary**: In ultra-high-throughput automated pipelines (> 1,000 actions/sec), synchronous semantic classification creates an operational bottleneck.
- **Mitigation**:
  1. Rely on deterministic policy rules and Markov transitions for high-frequency actions.
  2. Configure `Laya` semantic evaluation asynchronously or restrict it to `MEDIUM` and `HIGH` risk action tiers.

---

### 4. Markov Model Baseline Warmup (Cold Start)

- **Architecture Principle**: The Wald Sequential Probability Ratio Test (SPRT) continuously tests whether an agent's transition sequence conforms to a benign null hypothesis ($H_0$) or an adversarial alternative hypothesis ($H_1$).
- **Operational Reality**: If an agent workload has no empirical baseline training traces (cold start), transition probabilities rely heavily on Laplace or absolute smoothing ($p_0 = 0.05$).
- **Boundary**: During the cold-start phase, the model cannot distinguish between a novel benign development action and an anomaly until sufficient baseline traces have been fitted via `TopologyLearner` or `MarkovModel.train()`.
- **Mitigation**: Run new agent configurations in `MONITOR` mode for at least 50–100 benign sessions to accumulate baseline state distributions before enabling strict `ENFORCE` mode.

---

### 5. Shell Parsing Edge Cases in Fallback Mode

- **Architecture Principle**: [`CommandPipelineParser`](file:///D:/runtime-verify/src/runtimeverify/security/commands.py) decomposes compound shell commands (`;`, `&&`, `||`, `|`, `&`, newlines, `$(cmd)`, `` `cmd` ``, and environment overrides) and scans for dangerous operations before shell execution.
- **Operational Reality**: Shell interpreters (`bash`, `zsh`, `cmd.exe`, `powershell`) have complex, platform-dependent parameter expansion syntax (e.g. variable substring expansion `${var:0:2}`, backslash escape chains, or Windows caret `^` escapes).
- **Boundary**: A sufficiently sophisticated obfuscation payload designed specifically to exploit shell interpreter parsing bugs could evade static regex decomposition if executed under `shell=True`.
- **Mitigation**: The CLI and runtime default to `shell=False` execution with explicit argument vectors. Fallback to `shell=True` only occurs for shell built-ins after passing strict construct checks.

---

### 6. Audit Trail Storage Scalability

- **Architecture Principle**: Audit trails maintain cryptographic SHA-256 hash chains (`prev_hash`) to guarantee tamper-evident verification.
- **Operational Reality**: The default in-memory and file-based audit sinks (`JsonFileAuditSink`, `SQLiteStorageBackend`) are optimized for single-node deployments and developer workstations.
- **Boundary**: In enterprise swarms generating millions of events per hour, local SQLite file locking and in-memory audit arrays can experience disk I/O contention and memory growth.
- **Mitigation**: For enterprise-scale telemetry, configure an external logging sink (e.g., Elasticsearch, Splunk, or Kafka stream) via `EnterpriseAuditManager` and export sealed audit blocks periodically.

---

### 7. Approval Timeout Handling

- **Architecture Principle**: Approvals specify an automatic expiration window (`auto_timeout_seconds`, default 300s) after which unapproved actions are rejected or blocked.
- **Operational Reality**: Expiration evaluation in `EnterpriseApprovalManager` and `ApprovalStore` is evaluated lazily upon request retrieval or state query, rather than by an internal background timer thread.
- **Boundary**: If no client queries the status of an expired ticket, the status transition to `EXPIRED` is deferred until the next lookup.
- **Mitigation**: When integrating with active workflow queues, configure an external heartbeat or cron query to poll `/api/v1/approvals` periodically.

---

### 8. High-Session Concurrency SPRT Cleanup

- **Architecture Principle**: `SPRTEngine` tracks cumulative log-likelihood ratios per session ID and purges sessions whose last access exceeds `session_ttl`.
- **Operational Reality**: Session purging currently iterates over the session index upon new observations.
- **Boundary**: Under extreme concurrency (e.g. > 50,000 active concurrent agent sessions), the linear scan during session cleanup can cause microsecond latency spikes.
- **Mitigation**: Tune `session_ttl` to match agent task lifetimes (e.g., 600s instead of 3600s) and invoke `reset_session()` explicitly at agent termination.
