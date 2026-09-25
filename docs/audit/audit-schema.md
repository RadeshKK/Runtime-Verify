# Structured Audit Record Schema Specification

`RuntimeVerify` Phase 8 defines a vendor-neutral, tamper-evident, correlated schema for logging, querying, and auditing every agent action, policy evaluation, behavioral verification, human approval, and system execution.

---

## 1. Schema Overview

Each audit entry is serialized as an immutable JSON/NDJSON object adhering to strict semantic typing and correlation constraints.

```json
{
  "record_id": "00000000-0000-0000-0000-000000000001",
  "timestamp": "2026-09-25T13:30:00.000000Z",
  "record_type": "POLICY_DECISION",
  "severity": "CRITICAL",
  "trace_id": "tr-948194",
  "session_id": "sess-alpha-001",
  "event_id": "ev-3829104",
  "agent_id": "dev-agent-07",
  "span_id": "span-1",
  "action_id": "act-582910",
  "summary": "Policy 'deny-ssh-keys' evaluated to BLOCK: Access to private SSH keys is strictly prohibited.",
  "details": {
    "decision": "BLOCK",
    "policy_id": "deny-ssh-keys",
    "reason": "Access to private SSH keys is strictly prohibited.",
    "matched_rule": {
      "id": "deny-ssh-keys",
      "severity": "CRITICAL"
    }
  },
  "environment": "production",
  "metadata": {},
  "redacted": true
}
```

---

## 2. Core Fields Specification

| Field Name | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `record_id` | `string` (UUIDv4) | Yes | Globally unique identifier for this audit record. |
| `timestamp` | `string` (ISO 8601 UTC) | Yes | Exact UTC timestamp with microsecond resolution. |
| `record_type` | `AuditRecordType` (Enum) | Yes | Operational category of the audit entry. |
| `severity` | `AuditSeverity` (Enum) | Yes | Assessed risk / operational severity level. |
| `trace_id` | `string` | No | Distributed tracing correlation ID across upstream services. |
| `session_id` | `string` | No | Stateful agent interaction session identifier. |
| `event_id` | `string` | No | Correlated canonical runtime telemetry event ID. |
| `agent_id` | `string` | No | Autonomous agent identifier generating the action. |
| `span_id` | `string` | No | Sub-operation execution span identifier. |
| `action_id` | `string` | No | Intercepted agent action identifier. |
| `summary` | `string` | Yes | Human-readable explanation of the record outcome. |
| `details` | `object` | Yes | Typed operational payload specific to the record type. |
| `environment` | `string` | No | Execution environment (`production`, `staging`, `dev`). |
| `metadata` | `object` | No | Arbitrary contextual key-value pairs (sanitized). |
| `redacted` | `boolean` | Yes | Boolean flag indicating whether secret redaction scrubbed values. |

---

## 3. Enumerations

### 3.1 `AuditRecordType`

| Value | Description |
| :--- | :--- |
| `EVENT` | Canonical runtime telemetry event observed. |
| `POLICY_DECISION` | Deterministic policy evaluation verdict (`ALLOW`, `REVIEW`, `BLOCK`). |
| `SEMANTIC_DECISION` | Semantic verification model output (e.g. Laya). |
| `BEHAVIORAL_DECISION` | Markov state transition probability and anomaly detection result. |
| `SPRT_STATE_CHANGE` | Sequential Probability Ratio Test state transition or drift alert. |
| `APPROVAL_REQUEST` | Creation of a human approval authorization ticket. |
| `APPROVAL_DECISION` | Human reviewer verdict (`APPROVE`, `DENY`). |
| `EXECUTION_RESULT` | Post-interception authorized action execution outcome. |
| `ERROR` | Security exception, policy failure, or execution error. |

### 3.2 `AuditSeverity`

| Value | Usage |
| :--- | :--- |
| `CRITICAL` | Blocked malicious actions, credential access attempts, SPRT anomaly triggers. |
| `HIGH` | High-risk actions requiring human authorization, permission failures. |
| `WARNING` | Anomaly warnings, unusual parameters, approaching rate limits. |
| `MEDIUM` | Standard reviews, moderate risk classification. |
| `LOW` | Benign operational events, safe policy matches. |
| `INFO` | Routine events, allowed read-only actions, telemetry pulses. |

---

## 4. Secret Redaction Guarantees

RuntimeVerify strictly enforces **zero secret exposure** in persistent logs and SIEM feeds.

Before any record is written to disk or transmitted to a sink:
1. **Key-Name Inspection**: Any dictionary key matching sensitive substrings (e.g. `password`, `token`, `secret`, `api_key`, `private_key`, `auth`, `credentials`) has its value replaced with `[REDACTED]`.
2. **Value Pattern Scanning**: String values in payloads, summaries, and metadata are scanned against regular expressions matching:
   - OpenAI API Keys (`sk-...`, `sk-proj-...`) -> `[REDACTED_OPENAI_KEY]`
   - AWS Access Key IDs (`AKIA...`, `ASIA...`) -> `[REDACTED_AWS_KEY_ID]`
   - GitHub Access Tokens (`ghp_...`, `github_pat_...`) -> `[REDACTED_GITHUB_TOKEN]`
   - Bearer Tokens (`Authorization: Bearer ...`) -> `Bearer [REDACTED_BEARER_TOKEN]`
   - Private Keys (`-----BEGIN RSA/EC PRIVATE KEY-----...`) -> `[REDACTED_PRIVATE_KEY]`
   - Database Connection URIs (`postgres://user:pass@host/db`) -> `postgres://user:[REDACTED_PASSWORD]@host/db`
3. **Tamper-Evident Audit Flag**: Whenever any secret pattern is redacted, `redacted = true` is permanently set on the audit record.

---

## 5. Correlation Semantics

Audit records form a connected graph linking upstream intents to downstream execution results:

```
[Trace ID: tr-101]
       |
       +---> [EVENT] (action_id: act-1) Intercepted shell command 'rm -rf /'
       |        |
       |        +---> [POLICY_DECISION] Rule 'block-destructive-rm' -> BLOCK
       |        |
       |        +---> [ERROR] ExecutionBlockedError: Prohibited destructive command
       |
[Trace ID: tr-102]
       |
       +---> [EVENT] (action_id: act-2) Intercepted git push 'origin/main'
                |
                +---> [POLICY_DECISION] Rule 'review-git-push' -> REVIEW
                |
                +---> [APPROVAL_REQUEST] Ticket 'req-9812' created
                |        |
                |        +---> [APPROVAL_DECISION] Decided 'APPROVE' by 'secops-lead'
                |
                +---> [EXECUTION_RESULT] Git push succeeded in 420ms
```
