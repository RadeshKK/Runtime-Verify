"""
Unit and Integration Tests for Multi-Agent Runtime Verification (Phase 17).
Validates topology graphs, privilege hierarchies, empirical baseline learning,
Markov behavioral transitions, SPRT sequential testing, and verification engine integration.
"""

import pytest
from runtimeverify.events.base import Event
from runtimeverify.events.canonical import (
    CanonicalEvent,
)
from runtimeverify.events.enums import AgentRole, EventType
from runtimeverify.multiagent.baseline import TopologyLearner
from runtimeverify.multiagent.markov import MultiAgentMarkovModel
from runtimeverify.multiagent.models import (
    MultiAgentAnomalyType,
)
from runtimeverify.multiagent.sprt import MultiAgentSPRTEngine
from runtimeverify.multiagent.topology import TopologyGraph
from runtimeverify.multiagent.verifier import MultiAgentVerifier
from runtimeverify.verification.engine import VerificationEngine


@pytest.fixture
def standard_pipeline_graph() -> TopologyGraph:
    """Returns an authorized sequential pipeline: planner -> coder -> tester -> executor."""
    return TopologyGraph.pipeline(["planner", "coder", "tester", "executor"])


@pytest.fixture
def multiagent_verifier(standard_pipeline_graph: TopologyGraph) -> MultiAgentVerifier:
    """Returns a MultiAgentVerifier initialized with the standard pipeline."""
    return MultiAgentVerifier(topology=standard_pipeline_graph)


# ===========================================================================
# 1. Topology & Authorization Tests
# ===========================================================================


def test_normal_pipeline_interaction_allowed(multiagent_verifier: MultiAgentVerifier):
    """Legitimate progression planner -> coder -> tester conforms to pipeline topology."""
    # Step 1: Planner delegates to Coder
    ev1 = CanonicalEvent.create_agent_delegation(
        session_id="sess-multi-001",
        agent_id="planner-1",
        delegate_agent_id="coder-1",
        subtask="Implement authentication middleware",
        delegation_depth=1,
        agent_type=AgentRole.PLANNER.value,
        target_agent_role=AgentRole.CODER.value,
    )
    dec1 = multiagent_verifier.verify_event(ev1)
    assert dec1.decision == "ALLOW"
    assert dec1.risk_level == "LOW"
    assert len(dec1.anomalies) == 0

    # Step 2: Coder hands off to Tester
    ev2 = CanonicalEvent.create_agent_handoff(
        session_id="sess-multi-001",
        agent_id="coder-1",
        target_agent_id="tester-1",
        handoff_type="sequential",
        agent_type=AgentRole.CODER.value,
        target_agent_role=AgentRole.TESTER.value,
    )
    dec2 = multiagent_verifier.verify_event(ev2)
    assert dec2.decision == "ALLOW"
    assert dec2.risk_level == "LOW"


def test_unexpected_delegation_blocked(multiagent_verifier: MultiAgentVerifier):
    """Direct delegation from planner to executor bypassing coder and tester is blocked."""
    ev = CanonicalEvent.create_agent_delegation(
        session_id="sess-multi-002",
        agent_id="planner-1",
        delegate_agent_id="executor-1",
        subtask="Execute shell commands directly",
        delegation_depth=1,
        agent_type=AgentRole.PLANNER.value,
        target_agent_role=AgentRole.EXECUTOR.value,
    )
    dec = multiagent_verifier.verify_event(ev)
    assert dec.decision == "BLOCK"
    assert any(a.anomaly_type == MultiAgentAnomalyType.UNEXPECTED_DELEGATION for a in dec.anomalies)
    assert "not permitted to delegate to role 'executor'" in dec.reason


def test_abnormal_handoff_blocked(multiagent_verifier: MultiAgentVerifier):
    """Coder directly handing off to executor skipping tester validation is blocked."""
    ev = CanonicalEvent.create_agent_handoff(
        session_id="sess-multi-003",
        agent_id="coder-1",
        target_agent_id="executor-1",
        handoff_type="direct",
        agent_type=AgentRole.CODER.value,
        target_agent_role=AgentRole.EXECUTOR.value,
    )
    dec = multiagent_verifier.verify_event(ev)
    assert dec.decision == "BLOCK"
    assert any(a.anomaly_type == MultiAgentAnomalyType.ABNORMAL_HANDOFF for a in dec.anomalies)


def test_cross_agent_privilege_escalation_blocked(multiagent_verifier: MultiAgentVerifier):
    """Low privilege researcher attempting to delegate execution to executor is blocked with CRITICAL severity."""
    ev = Event(
        session_id="sess-multi-004",
        agent_id="researcher-1",
        agent_role="researcher",
        target_agent="executor-1",
        target_agent_role="executor",
        action="delegate",
        type=EventType.AGENT_DELEGATION.value,
    )
    dec = multiagent_verifier.verify_event(ev)
    assert dec.decision == "BLOCK"
    assert dec.risk_level == "CRITICAL"
    assert any(a.anomaly_type == MultiAgentAnomalyType.PRIVILEGE_ESCALATION for a in dec.anomalies)


def test_cyclic_delegation_loop_detected(multiagent_verifier: MultiAgentVerifier):
    """Detects infinite ping-pong delegation loop (agent-A -> agent-B -> agent-A)."""
    ev = Event(
        session_id="sess-multi-005",
        agent_id="coder-1",
        agent_role="coder",
        target_agent="tester-1",
        target_agent_role="tester",
        action="delegate",
        call_chain=["coder-1", "tester-1", "coder-1"],
        type=EventType.AGENT_DELEGATION.value,
    )
    dec = multiagent_verifier.verify_event(ev)
    assert dec.decision == "BLOCK"
    assert any(a.anomaly_type == MultiAgentAnomalyType.CYCLIC_DELEGATION for a in dec.anomalies)


def test_excessive_delegation_depth_blocked(multiagent_verifier: MultiAgentVerifier):
    """Deep nested delegation exceeding max_call_depth is flagged."""
    ev = Event(
        session_id="sess-multi-006",
        agent_id="coder-1",
        agent_role="coder",
        target_agent="tester-1",
        target_agent_role="tester",
        action="delegate",
        delegation_depth=10,
        type=EventType.AGENT_DELEGATION.value,
    )
    dec = multiagent_verifier.verify_event(ev)
    assert dec.decision == "BLOCK"
    assert any(a.anomaly_type == MultiAgentAnomalyType.EXCESSIVE_DELEGATION_DEPTH for a in dec.anomalies)


# ===========================================================================
# 2. Empirical Baseline Learning Tests
# ===========================================================================


def test_topology_learner_fits_benign_traces():
    """TopologyLearner learns authorized edges from legitimate multi-agent traces."""
    learner = TopologyLearner(name="learned_swarm")

    # Generate 5 benign collaborative traces
    traces = []
    for i in range(5):
        sess = f"train-sess-{i}"
        trace = [
            Event(
                session_id=sess,
                agent_id="planner-agent",
                agent_role="planner",
                target_agent="coder-agent",
                target_agent_role="coder",
                action="delegate",
            ),
            Event(
                session_id=sess,
                agent_id="coder-agent",
                agent_role="coder",
                target_agent="tester-agent",
                target_agent_role="tester",
                action="handoff",
            ),
        ]
        traces.append(trace)

    learned_graph = learner.fit_traces(traces)
    assert ("planner", "coder") in learned_graph._edges
    assert ("coder", "tester") in learned_graph._edges
    assert ("planner", "executor") not in learned_graph._edges

    stats = learner.get_statistics()
    assert stats["total_observed_roles"] == 3
    assert stats["total_edges"] == 2


# ===========================================================================
# 3. Multi-Agent Markov & SPRT Behavioral Tests
# ===========================================================================


def test_multiagent_markov_transition_probabilities():
    """MultiAgentMarkovModel assigns high probability to normal transitions and near-zero to anomalous jumps."""
    markov = MultiAgentMarkovModel(smoothing=1e-5)

    # Train on normal sequence: PLANNER:PLAN -> CODER:WRITE -> TESTER:TEST
    normal_sequences = [
        ["PLANNER:PLAN", "PLANNER->CODER:DELEGATE", "CODER:WRITE", "CODER->TESTER:HANDOFF", "TESTER:TEST"]
        for _ in range(20)
    ]
    markov.fit_sequences(normal_sequences)

    # Normal transition probability should be high
    prob_normal = markov.transition_probability("PLANNER->CODER:DELEGATE", "CODER:WRITE")
    assert prob_normal > 0.5

    # Anomalous transition probability should be near zero (smoothing)
    prob_anomaly = markov.transition_probability("PLANNER->CODER:DELEGATE", "EXECUTOR:EXECUTE")
    assert prob_anomaly < 0.01


def test_multiagent_sprt_drift_detection():
    """MultiAgentSPRTEngine accumulates drift on anomalous sequences and flags ACCEPT_H1."""
    markov = MultiAgentMarkovModel(smoothing=1e-5)
    normal_sequences = [
        ["PLANNER:PLAN", "PLANNER->CODER:DELEGATE", "CODER:WRITE", "CODER->TESTER:HANDOFF", "TESTER:TEST"]
        for _ in range(20)
    ]
    markov.fit_sequences(normal_sequences)

    sprt = MultiAgentSPRTEngine(markov_model=markov)
    sess = "sprt-test-session"

    # Start normal
    ev1 = Event(session_id=sess, agent_id="p1", agent_role="planner", action="plan")
    dec1 = sprt.observe_event(ev1)
    assert dec1.status == "PENDING"

    # Repeated anomalous events to trigger drift
    for _ in range(10):
        ev_anom = Event(
            session_id=sess,
            agent_id="p1",
            agent_role="planner",
            target_agent="e1",
            target_agent_role="executor",
            action="execute",
        )
        dec = sprt.observe_event(ev_anom)
        if dec.status == "ACCEPT_H1":
            break

    assert dec.status == "ACCEPT_H1"
    assert dec.log_likelihood_ratio >= dec.upper_threshold


# ===========================================================================
# 4. Hybrid VerificationEngine Integration
# ===========================================================================


def test_verification_engine_integrates_multiagent_verifier(standard_pipeline_graph: TopologyGraph):
    """VerificationEngine blocks multi-agent topology violations with full evidence and explanation."""
    ma_verifier = MultiAgentVerifier(topology=standard_pipeline_graph)
    engine = VerificationEngine(multiagent_verifier=ma_verifier)

    # Forbidden bypass event
    bypass_event = CanonicalEvent.create_agent_delegation(
        session_id="sess-engine-001",
        agent_id="planner-1",
        delegate_agent_id="executor-1",
        subtask="Direct bypass execution",
        delegation_depth=1,
        agent_type=AgentRole.PLANNER.value,
        target_agent_role=AgentRole.EXECUTOR.value,
    )

    result = engine.verify(bypass_event)
    assert result.decision == "BLOCK"
    assert "[MULTI-AGENT VIOLATION]" in result.reason
    assert result.explanation.behavioral_deviation is True
    assert len(result.evidence) > 0


def test_verification_engine_preserves_single_agent_backward_compatibility():
    """Standard single-agent events evaluate normally without multi-agent interference."""
    engine = VerificationEngine()
    event = CanonicalEvent.create_shell_command(
        session_id="sess-single-001",
        agent_id="coding-agent",
        command="git status",
    )
    result = engine.verify(event)
    assert result.decision == "ALLOW"
    assert result.risk_level == "LOW"
