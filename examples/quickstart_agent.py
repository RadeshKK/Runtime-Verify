"""
Quickstart Example: Monitored Autonomous Agent with RuntimeVerify (Phase 15).

Demonstrates:
1. Initializing an AgentSession using runtimeverify.session().
2. Executing safe, permitted actions (filesystem reads, status commands).
3. Intercepting and blocking an anomalous / prohibited action (reading credentials).
4. Inspecting structured decision evidence and risk scoring.
"""

import sys
import runtimeverify
from runtimeverify.interception.exceptions import ExecutionBlockedError


def run_monitored_agent():
    print(f"=== RuntimeVerify v{runtimeverify.__version__} Quickstart ===")
    print("Initializing monitored session for agent: 'coding-assistant'...\n")

    # Wrap the agent session in a RuntimeVerify context manager
    with runtimeverify.session(agent_id="coding-assistant") as session:
        # -------------------------------------------------------------
        # 1. Permitted Action: Reading normal project code
        # -------------------------------------------------------------
        safe_action = {
            "path": "/workspace/src/app.py",
            "operation": "read",
        }

        print("[Agent Step 1] Evaluating read on project source code...")
        decision = session.check(safe_action)
        print(f"  Decision Permitted: {decision.execution_permitted}")
        print(f"  Status:             {decision.status}")
        print(f"  Reason:             {decision.reason}")

        result = session.execute(safe_action)
        print(f"  Execution Success:  {result.success}\n")

        # -------------------------------------------------------------
        # 2. Permitted Action: Running standard git status command
        # -------------------------------------------------------------
        git_action = {
            "command": "git status",
        }

        print("[Agent Step 2] Requesting execution of 'git status'...")
        decision = session.check(git_action)
        print(f"  Status:             {decision.status}")
        result = session.execute(git_action)
        print(f"  Execution Success:  {result.success}\n")

        # -------------------------------------------------------------
        # 3. Blocked Action: Attempting to access sensitive credentials
        # -------------------------------------------------------------
        suspicious_action = {
            "path": "~/.aws/credentials",
            "operation": "read",
        }

        print("[Agent Step 3] Agent attempts reading cloud credentials: '~/.aws/credentials'...")
        try:
            session.execute(suspicious_action)
            print("  ERROR: Action should have been blocked!")
            sys.exit(1)
        except ExecutionBlockedError as e:
            print("  [SUCCESS] Action was intercepted and BLOCKED by RuntimeVerify!")
            print(f"  Policy ID:  {e.policy_id}")
            print(f"  Severity:   {e.severity}")
            print(f"  Reason:     {e.reason}")

    print("\nSession successfully completed with full audit trail.")


if __name__ == "__main__":
    run_monitored_agent()
