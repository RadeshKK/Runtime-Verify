# Security Model & Threat Guarantees: Human Approval Workflow

RuntimeVerify’s human approval workflow is designed for high-assurance environments where autonomous agent actions must be strictly bounded, deterministic, and resistant to tampering, replay, and unauthorized overrides.

---

## 1. Threat Assumptions & Adversary Model

We consider an adversary who may attempt to:
1. **Replay Past Approvals**: Resubmit previously granted approval tokens or decisions to authorize unapproved, repeated, or modified actions.
2. **Bypass Fail-Closed Controls**: Starve, delay, or disconnect reviewer communication channels in order to trigger permissive fallback execution (fail-open bypass).
3. **Approve Stale / Expired Requests**: Authorize an action long after environmental preconditions, repository states, or threat levels have changed.
4. **Spoof Approver Identities**: Submit approval decisions under fabricated or unauthorized user identities.
5. **Tamper with Audit Logs**: Erase or alter recorded rejection, denial, or approval logs to conceal malicious activity.

---

## 2. Security Invariants & Defenses

### Invariant 1: Linear, Non-Reversible Lifecycle (Replay Protection)
Every [`ApprovalRequest`](file:///D:/runtime-verify/src/runtimeverify/approvals/models.py) transitions strictly through a one-way directed graph:

```
                  ┌──────────────┐
                  │   PENDING    │
                  └──────┬───────┘
          ┌──────────────┼──────────────┐
          │              │              │
          ▼              ▼              ▼
    ┌───────────┐  ┌───────────┐  ┌───────────┐
    │ APPROVED  │  │  DENIED   │  │  EXPIRED  │
    └───────────┘  └───────────┘  └───────────┘
```

- **Replay Defense**: Once a request reaches `APPROVED`, `DENIED`, or `EXPIRED`, its state is immutable. Any subsequent attempt to record another decision raises [`DuplicateApprovalError`](file:///D:/runtime-verify/src/runtimeverify/approvals/exceptions.py) and logs a `REPLAY_ATTEMPT_REJECTED` security audit event.
- A decision cannot be overturned, re-applied to another action ID, or transferred to another agent session.

### Invariant 2: Time-Bounded Validity & Fail-Closed Expiration
- Every request carries an absolute UTC `expiration` timestamp computed at creation:
  $$\text{expiration} = \text{created\_at} + \text{timeout\_seconds}$$
- If the deadline elapses without explicit operator authorization, the request automatically transitions to `EXPIRED`.
- Attempting to authorize an expired request is rejected with [`ApprovalExpiredError`](file:///D:/runtime-verify/src/runtimeverify/approvals/exceptions.py).
- **Default Timeout Policy**: For all protected actions, the interceptor defaults to `ApprovalTimeoutBehavior.DENY` (fail-closed). Network failures or reviewer unavailability result in execution blockage, not permission.

### Invariant 3: Explicit Approver Authorization Boundaries
- When `authorized_approvers` is configured on [`ApprovalProvider`](file:///D:/runtime-verify/src/runtimeverify/approvals/provider.py) or [`ApprovalStore`](file:///D:/runtime-verify/src/runtimeverify/approvals/store.py), incoming decisions are checked against the allowed set:
  $$\text{decided\_by} \in \text{authorized\_approvers}$$
- Decisions from unauthorized identities are rejected immediately with [`UnauthorizedApproverError`](file:///D:/runtime-verify/src/runtimeverify/approvals/exceptions.py) and flagged as `UNAUTHORIZED_DECISION_ATTEMPT` in audit logs.

### Invariant 4: Contextual Binding & Tamper Evidence
- An approval decision is cryptographically tied to the exact request attributes:
  - `request_id`
  - `action_id`
  - `action` payload (target, parameters)
  - `risk` rating
  - `evidence` snapshot
- Approving `request_id` grants permission **only** to that specific invocation. An agent cannot substitute parameters (e.g. changing `git push origin dev` to `git push origin main`) without generating a new canonical event and triggering a new approval request.

### Invariant 5: Append-Only Immutable Audit Trail
- Every lifecycle event ([`ApprovalAuditEntry`](file:///D:/runtime-verify/src/runtimeverify/approvals/models.py)) is appended to an internal audit trail:
  - `REQUEST_CREATED`
  - `DECISION_RECORDED`
  - `EXPIRED`
  - `REPLAY_ATTEMPT_REJECTED`
  - `UNAUTHORIZED_DECISION_ATTEMPT`
- The audit records are exposed via CLI (`runtimeverify approvals show`) and REST API (`GET /api/v1/approvals/{id}/audit`).
