# Phase 7: Human Approval Workflow

RuntimeVerify provides an industry-grade, human-in-the-loop (HITL) approval framework allowing autonomous agents to pause high-risk actions and request human authorization before execution.

---

## 1. Approval Architecture & Execution Flow

```
                      INCOMING ACTION
                             │
                             ▼
                    RuntimeVerify Interceptor
                             │
                   Decision == REVIEW?
                    ┌────────┴────────┐
                    │ YES             │ NO
                    ▼                 ▼
          Create ApprovalRequest    ALLOW / BLOCK
                    │
                    ▼
            ApprovalProvider
        (CLI, API, or Custom)
                    │
         ┌──────────┴──────────┐
         │ Awaiting Review     │ Timeout / Expired
         ▼                     ▼
       Human              Default Policy
  [APPROVE / DENY]         [FAIL-CLOSED]
         │                     │
         └──────────┬──────────┘
                    │
         ┌──────────┴──────────┐
         ▼                     ▼
     APPROVE                 DENY
   (EXECUTE)               (BLOCK)
```

---

## 2. Core Components

1. **[`ApprovalRequest`](file:///D:/runtime-verify/src/runtimeverify/approvals/models.py)**:
   Structured request holding action details, agent identity, risk severity, triggering policies/heuristics, evidentiary records, and an absolute UTC expiration deadline.
2. **[`ApprovalDecision`](file:///D:/runtime-verify/src/runtimeverify/approvals/models.py)**:
   Auditable, immutable decision record containing the verdict (`APPROVE` or `DENY`), reviewer identity, reasoning, timestamp, and optional cryptographic signature.
3. **[`ApprovalStore`](file:///D:/runtime-verify/src/runtimeverify/approvals/store.py)**:
   Thread-safe registry with optional JSON persistence, strictly enforcing linear state progression (`PENDING` $\rightarrow$ `APPROVED` | `DENIED` | `EXPIRED`), replay rejection, and audit logging.
4. **[`ApprovalProvider`](file:///D:/runtime-verify/src/runtimeverify/approvals/provider.py)**:
   Abstract provider interface implemented by [`CLIApprovalProvider`](file:///D:/runtime-verify/src/runtimeverify/approvals/cli_provider.py) and [`APIApprovalProvider`](file:///D:/runtime-verify/src/runtimeverify/approvals/api_provider.py).

---

## 3. Data Schema: ApprovalRequest

```json
{
  "request_id": "84fc80a6-c988-466d-96e0-2bf090c29377",
  "event_id": "ev-00912",
  "action_id": "act-shell-push-44",
  "agent_id": "deploy-bot",
  "session_id": "sess-prod-99",
  "action": {
    "action_type": "git",
    "target": "origin/main",
    "operation": "push"
  },
  "risk": "HIGH",
  "reason": "Deterministic policy requires human review: review-git-push",
  "evidence": [
    {
      "source": "DETERMINISTIC_POLICY",
      "severity": "HIGH",
      "title": "Policy Triggered: review-git-push",
      "description": "Direct pushes to main branch require operator sign-off."
    }
  ],
  "created_at": "2026-09-25T13:15:00Z",
  "expiration": "2026-09-25T13:16:00Z",
  "timeout_seconds": 60.0,
  "timeout_behavior": "DENY",
  "status": "PENDING"
}
```

---

## 4. CLI Commands

### List Requests
```bash
runtimeverify approvals list
runtimeverify approvals list --status PENDING
```

### Approve a Request
```bash
runtimeverify approvals approve <request-id> --user alice --reason "Verified release artifacts"
```

### Deny a Request
```bash
runtimeverify approvals deny <request-id> --user bob --reason "Disallowed branch modification"
```

### Inspect Details & Evidence
```bash
runtimeverify approvals show <request-id>
```

---

## 5. REST API Endpoints

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/api/v1/approvals` | List all or filtered approval requests |
| `GET` | `/api/v1/approvals/{id}` | Retrieve request details |
| `POST` | `/api/v1/approvals/{id}/approve` | Approve a pending request |
| `POST` | `/api/v1/approvals/{id}/deny` | Deny a pending request |
| `GET` | `/api/v1/approvals/{id}/audit` | Retrieve full immutable audit history |

---

## 6. Programmatic Usage

### Wiring into Live Runtime Interceptor
```python
from runtimeverify.approvals import CLIApprovalProvider, get_default_approval_store
from runtimeverify.interception import Action, InterceptionMode, RuntimeActionInterceptor

# 1. Initialize approval provider (queued or interactive)
provider = CLIApprovalProvider(
    store=get_default_approval_store(),
    interactive=False, # Wait for operator CLI approval
)

# 2. Attach to interceptor
interceptor = RuntimeActionInterceptor(
    mode=InterceptionMode.ENFORCE,
    approval_provider=provider,
    approval_timeout=60.0,     # Pause for up to 60s
    approval_fail_closed=True, # Fail closed on timeout
)

# 3. Intercept high-risk action
action = Action.git(operation="push", branch="main")
decision, result = interceptor.intercept(action)
# Pauses for human decision; if approved, executes and returns result!
```
