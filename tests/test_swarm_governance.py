"""
Unit & Integration Tests for Sprint 3:
1. Cryptographic Signed Delegation Tickets & Swarm Provenance
2. MultiAgentVerifier Delegation Verification & Anomaly Handling
3. MCP Tool-to-Role RBAC Governance & Dual-Control Elevation
4. Bounded Session State & LRU/TTL Memory Eviction
"""

from datetime import datetime, timedelta, timezone

from runtimeverify.events.canonical import AgentDelegationEvent
from runtimeverify.interception.mcp_governance import (
    MCPGovernanceDecisionType,
    MCPGovernanceEngine,
    MCPRolePolicy,
)
from runtimeverify.multiagent.models import (
    DelegationTicket,
    MultiAgentAnomalyType,
)
from runtimeverify.multiagent.verifier import MultiAgentVerifier
from runtimeverify.runtime.session import SessionManager
from runtimeverify.state import ExecutionState, StateCategory, StateContext, StateHierarchy


class TestSignedDelegationTickets:
    def test_ticket_signing_and_verification(self):
        secret = "swarm-secret-key-32chars-min-len!"
        ticket = DelegationTicket(
            parent_agent="lead-orchestrator",
            child_agent="sub-researcher",
            session_id="session-swarm-1",
            scope=["web_search", "doc_read"],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        signed = ticket.sign(secret)
        assert signed.signature != ""
        assert signed.verify_signature(secret) is True
        assert signed.verify_signature("wrong-key") is False

    def test_ticket_tamper_detection(self):
        secret = "swarm-secret-key-32chars-min-len!"
        ticket = DelegationTicket(
            parent_agent="lead-orchestrator",
            child_agent="sub-researcher",
            session_id="session-swarm-1",
            scope=["web_search"],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        ).sign(secret)

        # Attempt to tamper with scope (privilege escalation attempt)
        tampered_data = ticket.model_dump()
        tampered_data["scope"] = ["*"]
        tampered = DelegationTicket(**tampered_data)
        assert tampered.verify_signature(secret) is False

    def test_ticket_expiration(self):
        ticket = DelegationTicket(
            parent_agent="lead-orchestrator",
            child_agent="sub-researcher",
            session_id="session-swarm-1",
            scope=["*"],
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),
        )
        assert ticket.is_expired() is True

    def test_ticket_scope_allowance(self):
        ticket = DelegationTicket(
            parent_agent="lead-orchestrator",
            child_agent="sub-coder",
            session_id="session-swarm-1",
            scope=["fs:read_*", "git:status"],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        assert ticket.allows_action("fs:read_file") is True
        assert ticket.allows_action("git:status") is True
        assert ticket.allows_action("fs:write_file") is False
        assert ticket.allows_action("shell:execute") is False


class TestMultiAgentVerifierDelegation:
    def test_verifier_delegation_allow(self):
        secret = "shared-swarm-secret"
        verifier = MultiAgentVerifier(delegation_secrets={"lead-agent": secret})
        ticket = DelegationTicket(
            parent_agent="lead-agent",
            child_agent="worker-agent",
            session_id="sess-1",
            scope=["compute_*"],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        ).sign(secret)

        decision = verifier.verify_delegation(ticket, action="compute_hash")
        assert decision.decision == "ALLOW"
        assert decision.risk_level == "LOW"

    def test_verifier_delegation_signature_mismatch_blocks(self):
        verifier = MultiAgentVerifier(delegation_secrets={"lead-agent": "key1"})
        ticket = DelegationTicket(
            parent_agent="lead-agent",
            child_agent="worker-agent",
            session_id="sess-1",
            scope=["*"],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        ).sign("forged-key")

        decision = verifier.verify_delegation(ticket)
        assert decision.decision == "BLOCK"
        assert decision.risk_level == "CRITICAL"
        assert any(a.anomaly_type == MultiAgentAnomalyType.UNEXPECTED_DELEGATION for a in decision.anomalies)

    def test_verifier_delegation_scope_exceeded_blocks(self):
        secret = "shared-swarm-secret"
        verifier = MultiAgentVerifier(delegation_secrets={"lead-agent": secret})
        ticket = DelegationTicket(
            parent_agent="lead-agent",
            child_agent="worker-agent",
            session_id="sess-1",
            scope=["read_only_*"],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        ).sign(secret)

        decision = verifier.verify_delegation(ticket, action="write_database")
        assert decision.decision == "BLOCK"
        assert decision.risk_level == "CRITICAL"
        assert any(a.anomaly_type == MultiAgentAnomalyType.PRIVILEGE_ESCALATION for a in decision.anomalies)

    def test_verify_event_with_delegation_ticket(self):
        secret = "shared-swarm-secret"
        verifier = MultiAgentVerifier(delegation_secrets={"lead-agent": secret})
        ticket = DelegationTicket(
            parent_agent="lead-agent",
            child_agent="worker-agent",
            session_id="sess-1",
            scope=["safe_tool"],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        ).sign(secret)

        event = AgentDelegationEvent.create_agent_delegation(
            session_id="sess-1",
            agent_id="lead-agent",
            delegate_agent_id="worker-agent",
            subtask="data processing",
            delegation_ticket=ticket,
        )

        decision = verifier.verify_event(event)
        # Ticket is valid, then topology validation proceeds
        assert decision is not None


class TestMCPGovernance:
    def test_researcher_allowed_and_denied_tools(self):
        engine = MCPGovernanceEngine()
        # Allowed tool
        dec_allow = engine.evaluate(
            agent_id="agent-r1",
            agent_role="researcher",
            tool_name="web_search",
        )
        assert dec_allow.decision == MCPGovernanceDecisionType.ALLOW

        # Denied tool
        dec_deny = engine.evaluate(
            agent_id="agent-r1",
            agent_role="researcher",
            tool_name="fs:write_file",
        )
        assert dec_deny.decision == MCPGovernanceDecisionType.BLOCK
        assert "explicitly denied" in dec_deny.reason

    def test_coder_elevation_requirement(self):
        engine = MCPGovernanceEngine()
        # Normal git diff is allowed
        dec_diff = engine.evaluate(
            agent_id="agent-c1",
            agent_role="coder",
            tool_name="git:diff",
        )
        assert dec_diff.decision == MCPGovernanceDecisionType.ALLOW

        # Git push requires human review
        dec_push = engine.evaluate(
            agent_id="agent-c1",
            agent_role="coder",
            tool_name="git:push_feature",
        )
        assert dec_push.decision == MCPGovernanceDecisionType.REVIEW
        assert "dual-control" in dec_push.reason

    def test_custom_role_policy_registration(self):
        engine = MCPGovernanceEngine()
        custom_policy = MCPRolePolicy(
            role="auditor",
            allowed_tools=["audit:*", "log:*"],
            denied_tools=["*:write", "*:delete"],
        )
        engine.register_role_policy(custom_policy)

        dec = engine.evaluate(
            agent_id="auditor-1",
            agent_role="auditor",
            tool_name="audit:verify_chain",
        )
        assert dec.decision == MCPGovernanceDecisionType.ALLOW


class TestBoundedSessionState:
    def test_session_manager_bounds_history(self):
        manager = SessionManager(max_sessions=10, max_history=5)
        session = manager.get_or_create("s1", "a1")
        hierarchy = StateHierarchy(path=["TOOL", "EXECUTE"])
        context = StateContext(agent_id="a1", session_id="s1")
        for i in range(10):
            st = ExecutionState(
                name=f"state_{i}",
                category=StateCategory.TOOL,
                hierarchy=hierarchy,
                context=context,
            )
            manager.update_state("s1", st)

        assert len(session.history) == 5
        assert session.history[-1].name == "state_9"

    def test_session_manager_lru_eviction(self):
        manager = SessionManager(max_sessions=3, max_history=5)
        manager.get_or_create("s1", "a1")
        manager.get_or_create("s2", "a2")
        manager.get_or_create("s3", "a3")
        assert set(manager.list_sessions()) == {"s1", "s2", "s3"}

        # Creating s4 should evict s1 (oldest)
        manager.get_or_create("s4", "a4")
        assert "s1" not in manager.list_sessions()
        assert "s4" in manager.list_sessions()
