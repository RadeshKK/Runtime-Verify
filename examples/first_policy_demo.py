"""
Custom Security Policy Example for RuntimeVerify (Phase 15).

Demonstrates:
1. Writing a custom policy YAML definition.
2. Validating the policy structure and rules.
3. Loading the policy into a PolicyEvaluator.
4. Testing actions against the policy rules.
"""

from pathlib import Path
import tempfile

from runtimeverify.policy.evaluator import PolicyEvaluator
from runtimeverify.policy.loader import load_policy_from_yaml
from runtimeverify.events.canonical import (
    FilesystemReadEvent,
    ShellCommandEvent,
    NetworkRequestEvent,
)


def run_policy_demo():
    print("=== Custom Security Policy Demo ===")

    # Define custom policy configuration
    custom_policy_yaml = """
version: "1.0"
conflict_resolution: most_restrictive
policies:
  - id: block-env-file
    name: Protect Environment Files
    description: Prevents agents from reading .env or sensitive config files
    decision: BLOCK
    severity: HIGH
    match:
      event_type: filesystem.read
      path:
        glob: "**/.env*"

  - id: block-destructive-shell
    name: Prevent Destructive Shell
    description: Blocks dangerous deletion and format commands
    decision: BLOCK
    severity: CRITICAL
    match:
      event_type: shell.command
      command:
        destructive: true

  - id: review-production-curl
    name: Review Production Network Calls
    description: Pauses external production API calls for human review
    decision: REVIEW
    severity: MEDIUM
    match:
      event_type: network.request
      network:
        domains:
          - "api.production.internal"
"""

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(custom_policy_yaml)
        policy_path = f.name

    try:
        # 1. Load and validate policy set
        print(f"Loading custom policy from: {policy_path}...")
        policy_set = load_policy_from_yaml(policy_path)
        print(f"Successfully loaded {len(policy_set.policies)} policies.")
        for p in policy_set.policies:
            print(f"  - [{p.decision.value}] {p.id} ({p.severity.value}): {p.name}")

        evaluator = PolicyEvaluator(policy_set)

        # 2. Test Safe Event: Reading application code
        safe_event = FilesystemReadEvent(
            session_id="demo-session",
            agent_id="test-agent",
            path="/app/src/main.py",
        )
        dec = evaluator.evaluate(safe_event)
        print("\n[Test 1] Reading '/app/src/main.py':")
        print(f"  Decision: {dec.decision.value} (Permitted: {dec.decision.value == 'ALLOW'})")

        # 3. Test Blocked Event: Reading .env secret file
        env_event = FilesystemReadEvent(
            session_id="demo-session",
            agent_id="test-agent",
            path="/app/.env.production",
        )
        dec = evaluator.evaluate(env_event)
        print("\n[Test 2] Reading '/app/.env.production':")
        print(f"  Decision:  {dec.decision.value}")
        print(f"  Policy ID: {dec.policy_id}")
        print(f"  Reason:    {dec.reason}")

        # 4. Test Destructive Shell Event
        rm_event = ShellCommandEvent(
            session_id="demo-session",
            agent_id="test-agent",
            command="rm -rf /var/data",
        )
        dec = evaluator.evaluate(rm_event)
        print("\n[Test 3] Executing 'rm -rf /var/data':")
        print(f"  Decision:  {dec.decision.value}")
        print(f"  Policy ID: {dec.policy_id}")
        print(f"  Reason:    {dec.reason}")

        # 5. Test Review Event: Production API network call
        net_event = NetworkRequestEvent(
            session_id="demo-session",
            agent_id="test-agent",
            url="https://api.production.internal/v1/deploy",
        )
        dec = evaluator.evaluate(net_event)
        print("\n[Test 4] Calling 'https://api.production.internal/v1/deploy':")
        print(f"  Decision:  {dec.decision.value} (Requires Human Review)")
        print(f"  Policy ID: {dec.policy_id}")

    finally:
        Path(policy_path).unlink(missing_ok=True)

    print("\nCustom policy evaluation demonstration completed successfully.")


if __name__ == "__main__":
    run_policy_demo()
