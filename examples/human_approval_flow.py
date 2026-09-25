"""
Human Approval Workflow Example for RuntimeVerify (Phase 15).

Demonstrates:
1. An action held for human review when triggering a REVIEW policy.
2. Generating a cryptographic approval challenge token.
3. Submitting an approval decision via ApprovalStore / ApprovalProvider.
4. Demonstrating that replay attacks (re-submitting decisions) are rejected.
"""

from datetime import datetime, timedelta, timezone

from runtimeverify.approvals.models import (
    ApprovalRequest,
    ApprovalDecision,
    ApprovalDecisionType,
)
from runtimeverify.approvals.store import ApprovalStore
from runtimeverify.approvals.exceptions import DuplicateApprovalError, UnauthorizedApproverError


def run_approval_demo():
    print("=== Human Approval Workflow Demo ===")
    store = ApprovalStore()

    # 1. An action triggers REVIEW policy and creates an ApprovalRequest
    req = ApprovalRequest(
        request_id="req-prod-db-migration",
        agent_id="db-migration-bot",
        action={"operation": "drop_table", "table": "users_backup_2025"},
        risk="HIGH",
        reason="Agent requested schema modification in production environment",
        expiration=datetime.now(timezone.utc) + timedelta(minutes=15),
    )
    created_req = store.create_request(req)

    print(f"Created Approval Ticket: {created_req.request_id}")
    print(f"  Agent:   {created_req.agent_id}")
    print(f"  Risk:    {created_req.risk}")
    print(f"  Reason:  {created_req.reason}")
    print(f"  Status:  {created_req.status.value}")
    print(f"  Token:   {created_req.approval_token[:16]}... (cryptographic challenge)\n")

    # 2. Operator attempts approval with an INVALID token -> Rejected
    print("[Operator Action 1] Attempting decision with an invalid token...")
    bad_decision = ApprovalDecision(
        request_id=created_req.request_id,
        decision=ApprovalDecisionType.APPROVE,
        decided_by="security-lead@company.com",
        approval_token="forged-or-incorrect-token",
    )
    try:
        store.record_decision(created_req.request_id, bad_decision)
        print("  ERROR: Invalid token was accepted!")
    except UnauthorizedApproverError as e:
        print(f"  [BLOCKED] Rejected invalid token: {e}\n")

    # 3. Authorized operator submits APPROVE verdict with VALID token
    print("[Operator Action 2] Authorized operator reviews and approves action...")
    valid_decision = ApprovalDecision(
        request_id=created_req.request_id,
        decision=ApprovalDecisionType.APPROVE,
        decided_by="security-lead@company.com",
        reason="Verified maintenance window ticket #4920",
        approval_token=created_req.approval_token,
    )
    finalized_req = store.record_decision(created_req.request_id, valid_decision)
    print(f"  [SUCCESS] Request status updated to: {finalized_req.status.value}")
    print(f"  Decided By: {finalized_req.decision.decided_by}")
    print(f"  Note:       {finalized_req.decision.reason}\n")

    # 4. Attempt Replay Attack: re-submitting decision on finalized ticket -> Rejected
    print("[Attacker Action] Attempting replay of finalized approval ticket...")
    replay_decision = ApprovalDecision(
        request_id=created_req.request_id,
        decision=ApprovalDecisionType.DENY,
        decided_by="malicious-actor@outside.com",
        approval_token=created_req.approval_token,
    )
    try:
        store.record_decision(created_req.request_id, replay_decision)
        print("  ERROR: Replayed approval was accepted!")
    except DuplicateApprovalError as e:
        print(f"  [BLOCKED] Replay attack prevented: {e}")

    print("\nHuman approval lifecycle demonstration completed successfully.")


if __name__ == "__main__":
    run_approval_demo()
