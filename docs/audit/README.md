# Phase 8: Audit and Observability

`RuntimeVerify` provides an enterprise-grade, tamper-evident audit and observability architecture. Every runtime action, deterministic policy evaluation, semantic model classification, behavioral Markov transition, sequential SPRT drift state, human authorization ticket, and execution outcome is immutably recorded, correlated across distributed traces, and sanitized of raw secrets.

---

## 1. Architecture

```
                    AGENT ACTION / CANONICAL EVENT
                                  |
                                  v
                    +---------------------------+
                    | RuntimeActionInterceptor  |
                    +---------------------------+
                                  |
               +------------------+------------------+
               |                  |                  |
               v                  v                  v
         Policy Engine     Semantic Engine    Behavioral Engine
               |                  |                  |
               +------------------+------------------+
                                  |
                                  v
                         AuditService Emit
                                  |
                                  v
                      +-----------------------+
                      |    SecretRedactor     |  (Scrub keys, tokens, passwords)
                      +-----------------------+
                                  |
         +------------------------+------------------------+
         |                        |                        |
         v                        v                        v
   Local NDJSON File       PostgreSQL DB            SIEM / Splunk / S3
   (AuditRepository)      (PostgresAuditSink)         (SIEMAuditSink)
```

---

## 2. Pluggable Sinks (`AuditSink`)

The audit subsystem decouples logging from storage via the [`AuditSink`](file:///D:/runtime-verify/src/runtimeverify/audit/sinks.py) abstract base class:

| Sink Implementation | Description | Use Case |
| :--- | :--- | :--- |
| [`FileAuditSink`](file:///D:/runtime-verify/src/runtimeverify/audit/sinks.py) | High-performance NDJSON append-only file logger. | Local CLI, edge nodes, container sidecars. |
| [`MemoryAuditSink`](file:///D:/runtime-verify/src/runtimeverify/audit/sinks.py) | In-memory record buffer with thread-safe access. | Testing, lightweight in-process inspection. |
| [`ConsoleAuditSink`](file:///D:/runtime-verify/src/runtimeverify/audit/sinks.py) | Human-readable terminal output. | Development mode, debug logs. |
| [`CompositeAuditSink`](file:///D:/runtime-verify/src/runtimeverify/audit/sinks.py) | Fan-out dispatcher to multiple sinks simultaneously. | Multi-destination enterprise topologies. |
| [`PostgresAuditSink`](file:///D:/runtime-verify/src/runtimeverify/audit/sinks.py) | Batched table streaming to PostgreSQL. | Centralized relational enterprise storage. |
| [`ObjectStorageAuditSink`](file:///D:/runtime-verify/src/runtimeverify/audit/sinks.py) | Batched NDJSON chunk flusher for S3/GCS. | Long-term compliance cold archiving. |
| [`SIEMAuditSink`](file:///D:/runtime-verify/src/runtimeverify/audit/sinks.py) | HTTP Event Collector (HEC) / Syslog forwarder. | Splunk, Datadog, Elastic, Sumo Logic. |

---

## 3. Secret Redaction (`SecretRedactor`)

Security audit logs must **never leak raw credentials**. The [`SecretRedactor`](file:///D:/runtime-verify/src/runtimeverify/audit/redaction.py) automatically cleanses all records:

- **Key-based scrubbing**: Dictionary keys matching `password`, `token`, `secret`, `api_key`, `private_key`, `auth`, `credentials` are replaced with `[REDACTED]`.
- **Regex pattern scrubbing**:
  - OpenAI keys: `sk-proj-abc...` -> `[REDACTED_OPENAI_KEY]`
  - AWS Access Key IDs: `AKIA...` -> `[REDACTED_AWS_KEY_ID]`
  - GitHub Tokens: `ghp_...` -> `[REDACTED_GITHUB_TOKEN]`
  - Bearer headers: `Authorization: Bearer ...` -> `Bearer [REDACTED_BEARER_TOKEN]`
  - RSA / EC private keys: `-----BEGIN RSA PRIVATE KEY-----...` -> `[REDACTED_PRIVATE_KEY]`
  - Database URLs: `postgres://user:pass@host/db` -> `postgres://user:[REDACTED_PASSWORD]@host/db`
- **Tamper-evident flag**: Whenever redaction occurs, `record.redacted = True` is permanently stamped.

---

## 4. Retention Management (`AuditRepository`)

The [`AuditRepository`](file:///D:/runtime-verify/src/runtimeverify/audit/repository.py) interface provides query and pruning operations:

- **Age-based retention**: Prune records older than $N$ days (`max_age_days`).
- **Volume-based retention**: Retain only the newest $M$ records (`max_records`), discarding older excess items.
- **Multidimensional filtering**: Query by `trace_id`, `session_id`, `event_id`, `agent_id`, `record_type`, `severity`, or time window.

---

## 5. CLI Usage

The RuntimeVerify CLI provides first-class commands for inspecting and managing audit logs:

### 5.1 List Audit Records
```bash
# List the latest 50 audit records
runtimeverify audit list

# Filter by agent and record type
runtimeverify audit list --agent dev-agent-01 --type POLICY_DECISION

# Filter by severity and custom store
runtimeverify audit list --severity CRITICAL --store /var/log/runtimeverify/audit.ndjson
```

### 5.2 Show Detailed Record
```bash
# Inspect record by full UUID or prefix
runtimeverify audit show 00000000-0000-0000-0000-000000000001
runtimeverify audit show 00000000
```

### 5.3 Enforce Retention Pruning
```bash
# Prune records older than 30 days
runtimeverify audit prune --max-age-days 30

# Cap audit log to 10,000 newest entries
runtimeverify audit prune --max-records 10000 --store .runtimeverify/audit.log
```

---

## 6. Programmatic Integration

```python
from runtimeverify.audit import (
    AuditService,
    FileAuditSink,
    FileAuditRepository,
    SecretRedactor,
)
from runtimeverify.interception import (
    Action,
    InterceptionMode,
    RuntimeActionInterceptor,
)
from runtimeverify.policy.loader import load_policy_from_yaml
from runtimeverify.policy.evaluator import PolicyEvaluator

# Initialize storage and audit service
sink = FileAuditSink(file_path=".runtimeverify/audit.log")
repo = FileAuditRepository(log_path=".runtimeverify/audit.log")
audit_service = AuditService(sink=sink, repository=repo)

# Wire into RuntimeActionInterceptor
policy_set = load_policy_from_yaml("examples/policies/default.yaml")
evaluator = PolicyEvaluator(policy_set=policy_set)

interceptor = RuntimeActionInterceptor(
    policy_evaluator=evaluator,
    mode=InterceptionMode.ENFORCE,
    audit_service=audit_service,
)

# Actions are automatically intercepted and audited with full correlation
action = Action.shell(
    command="rm -rf /",
    agent_id="agent-01",
    session_id="sess-alpha",
)
```
