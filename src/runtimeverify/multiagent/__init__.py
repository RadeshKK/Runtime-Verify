"""
Multi-Agent Runtime Verification Package for RuntimeVerify (Phase 17).
Provides topology-aware governance, empirical baseline learning, cross-agent Markov modeling,
sequential drift detection (SPRT), and privilege boundary verification across autonomous agent swarms.
"""

from runtimeverify.multiagent.models import (
    AgentRole,
    MultiAgentAnomaly,
    MultiAgentAnomalyType,
    MultiAgentDecision,
    RolePrivilegeLevel,
    TopologyEdge,
    TopologyType,
)
from runtimeverify.multiagent.topology import TopologyGraph
from runtimeverify.multiagent.baseline import TopologyLearner
from runtimeverify.multiagent.markov import MultiAgentMarkovModel
from runtimeverify.multiagent.sprt import MultiAgentSPRTDecision, MultiAgentSPRTEngine
from runtimeverify.multiagent.verifier import MultiAgentVerifier

__all__ = [
    # Models & Enums
    "AgentRole",
    "RolePrivilegeLevel",
    "TopologyType",
    "TopologyEdge",
    "MultiAgentAnomalyType",
    "MultiAgentAnomaly",
    "MultiAgentDecision",
    # Core Engine Components
    "TopologyGraph",
    "TopologyLearner",
    "MultiAgentMarkovModel",
    "MultiAgentSPRTDecision",
    "MultiAgentSPRTEngine",
    "MultiAgentVerifier",
]
