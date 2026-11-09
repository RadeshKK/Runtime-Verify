"""
Unit & Integration Tests for Sprint 2:
1. Unified Interception Contract & Fail-Closed Gating (SDK, LangGraph, CrewAI, PydanticAI)
2. Temporal Policy Invariants (Prerequisite actions & forbidden prior event sequences)
"""

import pytest

from runtimeverify.interception.contract import (
    InterceptionFailureMode,
    UnifiedInterceptionContract,
)
from runtimeverify.interception.exceptions import (
    ExecutionBlockedError,
    SecurityFailClosedError,
)
from runtimeverify.interception.models import (
    Action,
    ActionType,
    ExecutionContext,
    InterceptionDecision,
    InterceptionMode,
)
from runtimeverify.integrations.crewai import CrewAIAdapter
from runtimeverify.integrations.langgraph import LangGraphAdapter
from runtimeverify.integrations.pydanticai import PydanticAIAdapter
from runtimeverify.policy.evaluator import PolicyEvaluator
from runtimeverify.policy.models import (
    Policy,
    PolicyDecisionType,
    PolicyMatchCriteria,
    PolicySeverity,
    TemporalPolicyCriteria,
)


class MockSession:
    def __init__(self, allow: bool = True, raise_error: bool = False):
        self.allow = allow
        self.raise_error = raise_error
        self.agent_id = "test-agent"
        self.session_id = "test-session"

    def check(self, action: Action) -> InterceptionDecision:
        if self.raise_error:
            raise RuntimeError("Underlying verification engine unreachable")
        status = "ALLOW" if self.allow else "BLOCK"
        return InterceptionDecision(
            action_id=action.action_id,
            mode=InterceptionMode.ENFORCE,
            status=status,
            execution_permitted=self.allow,
            effective_action="EXECUTE" if self.allow else "BLOCK",
            reason="Mock decision",
            policy_id="mock-policy",
            severity="CRITICAL",
        )


class TestUnifiedInterceptionContract:
    def test_gating_allows_permitted_action(self):
        session = MockSession(allow=True)
        contract = UnifiedInterceptionContract(session=session)
        action = Action(
            action_id="act-1",
            action_type=ActionType.TOOL,
            name="calculate",
            target="calculator",
            params={"expression": "2+2"},
            context=ExecutionContext(session_id="test-session", agent_id="test-agent"),
        )
        dec = contract.gate_action(action)
        assert dec.execution_permitted is True

    def test_gating_blocks_denied_action(self):
        session = MockSession(allow=False)
        contract = UnifiedInterceptionContract(session=session)
        action = Action(
            action_id="act-block",
            action_type=ActionType.TOOL,
            name="delete_all",
            target="rm_rf",
            params={"path": "/"},
            context=ExecutionContext(session_id="test-session", agent_id="test-agent"),
        )
        with pytest.raises(ExecutionBlockedError) as exc_info:
            contract.gate_action(action)
        assert exc_info.value.action_id == "act-block"

    def test_fail_closed_on_unhandled_verifier_outage(self):
        session = MockSession(raise_error=True)
        contract = UnifiedInterceptionContract(
            session=session,
            failure_mode=InterceptionFailureMode.FAIL_CLOSED,
        )
        action = Action(
            action_id="act-fail-closed",
            action_type=ActionType.TOOL,
            name="send",
            target="send_email",
            params={"to": "user@example.com"},
            context=ExecutionContext(session_id="test-session", agent_id="test-agent"),
        )
        with pytest.raises(SecurityFailClosedError) as exc_info:
            contract.gate_action(action)
        assert "FAIL_CLOSED" in str(exc_info.value)

    def test_fail_open_opt_in(self):
        session = MockSession(raise_error=True)
        contract = UnifiedInterceptionContract(
            session=session,
            failure_mode=InterceptionFailureMode.FAIL_OPEN,
        )
        action = Action(
            action_id="act-fail-open",
            action_type=ActionType.TOOL,
            name="read",
            target="read_log",
            params={},
            context=ExecutionContext(session_id="test-session", agent_id="test-agent"),
        )
        dec = contract.gate_action(action)
        assert dec.status == "ALLOW"
        assert "FAIL_OPEN" in dec.reason

    def test_wrap_tool_decorator(self):
        session = MockSession(allow=False)
        contract = UnifiedInterceptionContract(session=session)

        called = False

        @contract.wrap_tool
        def dangerous_action(x: int) -> int:
            nonlocal called
            called = True
            return x * 2

        with pytest.raises(ExecutionBlockedError):
            dangerous_action(5)
        assert called is False


class TestFrameworkAdaptersFailClosed:
    def test_langgraph_instrument_node_blocks(self):
        session = MockSession(allow=False)
        called = False

        def test_node(state: dict) -> dict:
            nonlocal called
            called = True
            return {"status": "done"}

        instrumented = LangGraphAdapter.instrument_node("test_node", test_node, session=session)

        with pytest.raises(ExecutionBlockedError):
            instrumented({"input": "hello"})
        assert called is False

    def test_crewai_instrument_tool_blocks(self):
        session = MockSession(allow=False)
        called = False

        def deploy_tool(cluster: str) -> str:
            nonlocal called
            called = True
            return f"Deployed to {cluster}"

        guarded = CrewAIAdapter.instrument_tool(deploy_tool, session=session)
        with pytest.raises(ExecutionBlockedError):
            guarded("production-k8s")
        assert called is False

    def test_pydanticai_instrument_tool_blocks(self):
        session = MockSession(allow=False)
        called = False

        def query_database(q: str) -> list:
            nonlocal called
            called = True
            return ["row1"]

        guarded = PydanticAIAdapter.instrument_tool(query_database, session=session)
        with pytest.raises(ExecutionBlockedError):
            guarded("DROP TABLE users;")
        assert called is False


class TestTemporalPolicyInvariants:
    def test_temporal_prerequisite_missing_triggers_block(self):
        """Action 'git push' requires prior 'pytest' action. If missing, rule matches to BLOCK."""
        temporal = TemporalPolicyCriteria(requires_prior_actions=["pytest"])
        policy = Policy(
            id="require-tests-before-push",
            decision=PolicyDecisionType.BLOCK,
            severity=PolicySeverity.HIGH,
            match=PolicyMatchCriteria(
                event_types=["shell.command"],
                temporal=temporal,
            ),
            reason="Blocked: Git push requires prior pytest execution",
        )
        evaluator = PolicyEvaluator()
        evaluator.policy_set.policies.append(policy)

        # Action: git push with NO prior history -> Must BLOCK
        action = Action.shell(command="git push origin main", session_id="s1", agent_id="agent-1")
        event = action.to_canonical_event()
        decision = evaluator.evaluate(event, session_history=[])
        assert decision.decision == PolicyDecisionType.BLOCK
        assert "Missing required prerequisite action" in decision.reason

    def test_temporal_prerequisite_satisfied_allows(self):
        """Action 'git push' requires prior 'pytest' action. If present in history, ALLOW."""
        temporal = TemporalPolicyCriteria(requires_prior_actions=["pytest"])
        policy = Policy(
            id="require-tests-before-push",
            decision=PolicyDecisionType.BLOCK,
            severity=PolicySeverity.HIGH,
            match=PolicyMatchCriteria(
                event_types=["shell.command"],
                temporal=temporal,
            ),
            reason="Blocked: Git push requires prior pytest execution",
        )
        evaluator = PolicyEvaluator()
        evaluator.policy_set.policies.append(policy)

        # Action: git push with 'pytest' in prior history -> Policy rule does NOT match -> Default ALLOW
        action = Action.shell(command="git push origin main", session_id="s1", agent_id="agent-1")
        event = action.to_canonical_event()
        history = ["pytest tests/"]
        decision = evaluator.evaluate(event, session_history=history)
        assert decision.decision == PolicyDecisionType.ALLOW

    def test_temporal_forbidden_prior_action_triggers_block(self):
        """Exfiltration invariant: If credential was read earlier, network egress is BLOCKED."""
        temporal = TemporalPolicyCriteria(forbidden_prior_actions=["credential.read", ".aws/credentials"])
        policy = Policy(
            id="prevent-exfil-after-credential-read",
            decision=PolicyDecisionType.BLOCK,
            severity=PolicySeverity.CRITICAL,
            match=PolicyMatchCriteria(
                event_types=["network.request"],
                temporal=temporal,
            ),
            reason="Exfiltration violation: Network egress forbidden after credential access",
        )
        evaluator = PolicyEvaluator()
        evaluator.policy_set.policies.append(policy)

        # Egress action with prior credential read in history -> BLOCKED
        action = Action.network(url="https://attacker.site/leak", session_id="s-leak", agent_id="agent-1")
        event = action.to_canonical_event()
        history = ["read ~/.aws/credentials"]
        decision = evaluator.evaluate(event, session_history=history)
        assert decision.decision == PolicyDecisionType.BLOCK
        assert "Forbidden prior action" in decision.reason
