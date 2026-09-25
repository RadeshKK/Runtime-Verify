"""
Multi-Agent Topology Graph for RuntimeVerify (Phase 17).
Defines and enforces authorized structural interaction graphs, delegation pipelines,
privilege hierarchies, and call-chain constraints.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from runtimeverify.multiagent.models import (
    MultiAgentAnomaly,
    MultiAgentAnomalyType,
    RolePrivilegeLevel,
    TopologyEdge,
    TopologyType,
)


class TopologyGraph:
    """
    Directed graph enforcing authorized interaction topologies between autonomous agents.
    Validates agent-to-agent delegation, messaging, handoffs, and privilege escalation boundaries.
    """

    def __init__(
        self,
        name: str = "default_topology",
        topology_type: TopologyType = TopologyType.CUSTOM,
        allow_unknown_roles: bool = False,
        max_call_depth: int = 5,
        privilege_levels: Optional[Dict[str, int]] = None,
    ):
        self.name = name
        self.topology_type = topology_type
        self.allow_unknown_roles = allow_unknown_roles
        self.max_call_depth = max_call_depth
        self.privilege_levels = privilege_levels or dict(RolePrivilegeLevel.DEFAULT_LEVELS)

        # Edges keyed by (source_role.lower(), target_role.lower())
        self._edges: Dict[Tuple[str, str], TopologyEdge] = {}
        # Specific agent overrides: agent_id -> Set[target_agent_id]
        self._agent_overrides: Dict[str, Set[str]] = {}
        # Known registered roles
        self._roles: Set[str] = set()

    # --- Factory Constructors for Standard Archetypes ---

    @classmethod
    def pipeline(
        cls,
        stages: Optional[List[str]] = None,
        name: str = "sequential_pipeline",
        allow_feedback: bool = True,
    ) -> "TopologyGraph":
        """
        Creates a sequential pipeline topology (e.g. planner -> coder -> tester -> executor).
        Allows forward handoffs/delegations along the pipeline stages, and optional reverse feedback messages.
        """
        if stages is None:
            stages = ["planner", "coder", "tester", "executor"]

        graph = cls(name=name, topology_type=TopologyType.PIPELINE)
        stages_clean = [s.lower() for s in stages]

        for i in range(len(stages_clean) - 1):
            src = stages_clean[i]
            tgt = stages_clean[i + 1]
            graph.add_edge(
                source_role=src,
                target_role=tgt,
                allowed_actions={"delegate", "handoff", "message", "send"},
                require_approval=(tgt == "executor"),
            )
            if allow_feedback:
                # Feedback loop: e.g. tester reporting failure back to coder or planner
                graph.add_edge(
                    source_role=tgt,
                    target_role=src,
                    allowed_actions={"message", "send"},
                    require_approval=False,
                )

        return graph

    @classmethod
    def hierarchical(
        cls,
        orchestrator_role: str = "orchestrator",
        worker_roles: Optional[List[str]] = None,
        name: str = "hierarchical_swarm",
    ) -> "TopologyGraph":
        """
        Creates a hub-and-spoke hierarchical topology where an orchestrator delegates to workers,
        and workers report back exclusively to the orchestrator.
        """
        if worker_roles is None:
            worker_roles = ["coder", "tester", "researcher"]

        graph = cls(name=name, topology_type=TopologyType.HIERARCHICAL)
        orch = orchestrator_role.lower()

        for w in worker_roles:
            worker = w.lower()
            # Orchestrator to worker
            graph.add_edge(
                source_role=orch,
                target_role=worker,
                allowed_actions={"delegate", "message", "send"},
            )
            # Worker back to orchestrator
            graph.add_edge(
                source_role=worker,
                target_role=orch,
                allowed_actions={"handoff", "message", "send", "response"},
            )

        return graph

    @classmethod
    def mesh(
        cls,
        roles: List[str],
        name: str = "collaborative_mesh",
    ) -> "TopologyGraph":
        """
        Creates a peer-to-peer mesh where all listed roles may interact with one another.
        """
        graph = cls(name=name, topology_type=TopologyType.MESH)
        roles_clean = [r.lower() for r in roles]

        for src in roles_clean:
            for tgt in roles_clean:
                if src != tgt:
                    graph.add_edge(
                        source_role=src,
                        target_role=tgt,
                        allowed_actions={"delegate", "handoff", "message", "send"},
                    )

        return graph

    # --- Configuration Methods ---

    def add_edge(
        self,
        source_role: str,
        target_role: str,
        allowed_actions: Optional[Set[str]] = None,
        max_delegation_depth: int = 5,
        require_approval: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "TopologyGraph":
        """Registers a directed interaction edge between two agent roles."""
        src = str(source_role).lower()
        tgt = str(target_role).lower()
        actions = {a.lower() for a in (allowed_actions or {"delegate", "handoff", "message", "send"})}

        edge = TopologyEdge(
            source_role=src,
            target_role=tgt,
            allowed_actions=actions,
            max_delegation_depth=max_delegation_depth,
            require_approval=require_approval,
            metadata=metadata or {},
        )
        self._edges[(src, tgt)] = edge
        self._roles.add(src)
        self._roles.add(tgt)
        return self

    def set_role_privilege(self, role: str, level: int) -> None:
        """Sets the numeric privilege level for an agent role."""
        self.privilege_levels[role.lower()] = level

    def get_role_privilege(self, role: str) -> int:
        """Returns the privilege level for a given role."""
        return self.privilege_levels.get(role.lower(), 10)

    # --- Verification & Anomaly Detection ---

    def validate_interaction(
        self,
        source_agent: str,
        source_role: str,
        target_agent: Optional[str],
        target_role: Optional[str],
        action: str,
        delegation_depth: int = 0,
        call_chain: Optional[List[str]] = None,
    ) -> List[MultiAgentAnomaly]:
        """
        Validates a proposed multi-agent interaction against the topology graph,
        privilege boundaries, and delegation depth constraints.
        Returns a list of detected MultiAgentAnomaly objects (empty if fully valid).
        """
        anomalies: List[MultiAgentAnomaly] = []
        src_role = str(source_role or "unknown").lower()
        tgt_role = str(target_role or "unknown").lower()
        act = str(action or "message").lower()

        # 1. Delegation Call Chain Cycle Detection
        if call_chain:
            chain_anom = self._check_call_chain_cycles(source_agent, src_role, call_chain)
            if chain_anom:
                anomalies.append(chain_anom)

        # 2. Maximum Delegation Depth Check
        if delegation_depth > self.max_call_depth:
            anomalies.append(
                MultiAgentAnomaly(
                    anomaly_type=MultiAgentAnomalyType.EXCESSIVE_DELEGATION_DEPTH,
                    source_agent=source_agent,
                    source_role=src_role,
                    target_agent=target_agent,
                    target_role=tgt_role,
                    action=act,
                    severity="HIGH",
                    reason=(
                        f"Delegation depth {delegation_depth} exceeds maximum allowable depth "
                        f"{self.max_call_depth} in topology '{self.name}'."
                    ),
                    evidence={
                        "delegation_depth": delegation_depth,
                        "max_depth": self.max_call_depth,
                        "call_chain": call_chain or [],
                    },
                )
            )

        # If there is no target agent or role (e.g. self-directed action), return early
        if not target_role and not target_agent:
            return anomalies

        # 3. Structural Edge Validation in Topology
        edge_key = (src_role, tgt_role)
        edge = self._edges.get(edge_key)

        if edge is None:
            if not self.allow_unknown_roles:
                # Classify based on action type
                anomaly_type = MultiAgentAnomalyType.UNEXPECTED_COMMUNICATION
                if act in ("delegate", "spawn"):
                    anomaly_type = MultiAgentAnomalyType.UNEXPECTED_DELEGATION
                elif act in ("handoff", "transfer"):
                    anomaly_type = MultiAgentAnomalyType.ABNORMAL_HANDOFF

                anomalies.append(
                    MultiAgentAnomaly(
                        anomaly_type=anomaly_type,
                        source_agent=source_agent,
                        source_role=src_role,
                        target_agent=target_agent,
                        target_role=tgt_role,
                        action=act,
                        severity="HIGH",
                        reason=(
                            f"Unauthorized cross-agent transition: Role '{src_role}' is not permitted "
                            f"to {act} to role '{tgt_role}' in topology '{self.name}'."
                        ),
                        evidence={
                            "topology": self.name,
                            "source_role": src_role,
                            "target_role": tgt_role,
                            "action": act,
                            "allowed_edges_from_source": [tgt for (s, tgt) in self._edges.keys() if s == src_role],
                        },
                    )
                )
        else:
            # Edge exists; check if the specific action is permitted on this edge
            if act not in edge.allowed_actions and "*" not in edge.allowed_actions:
                anomalies.append(
                    MultiAgentAnomaly(
                        anomaly_type=MultiAgentAnomalyType.UNEXPECTED_COMMUNICATION,
                        source_agent=source_agent,
                        source_role=src_role,
                        target_agent=target_agent,
                        target_role=tgt_role,
                        action=act,
                        severity="MEDIUM",
                        reason=(
                            f"Action '{act}' is not permitted along edge '{src_role} -> {tgt_role}'. "
                            f"Allowed actions: {sorted(list(edge.allowed_actions))}."
                        ),
                        evidence={
                            "allowed_actions": sorted(list(edge.allowed_actions)),
                            "attempted_action": act,
                        },
                    )
                )

        # 4. Privilege Escalation Detection
        src_priv = self.get_role_privilege(src_role)
        tgt_priv = self.get_role_privilege(tgt_role)

        # Privilege escalation check: low-privilege agent directly invoking/delegating to high-privilege executor
        # unless specifically governed by a registered pipeline step
        if tgt_priv >= src_priv + 15 and act in ("delegate", "spawn", "execute"):
            anomalies.append(
                MultiAgentAnomaly(
                    anomaly_type=MultiAgentAnomalyType.PRIVILEGE_ESCALATION,
                    source_agent=source_agent,
                    source_role=src_role,
                    target_agent=target_agent,
                    target_role=tgt_role,
                    action=act,
                    severity="CRITICAL",
                    reason=(
                        f"Cross-agent privilege escalation: Lower-privilege role '{src_role}' (level {src_priv}) "
                        f"attempted to delegate execution to higher-privilege role '{tgt_role}' (level {tgt_priv})."
                    ),
                    evidence={
                        "source_privilege": src_priv,
                        "target_privilege": tgt_priv,
                        "privilege_gap": tgt_priv - src_priv,
                        "action": act,
                    },
                )
            )

        return anomalies

    def _check_call_chain_cycles(
        self, source_agent: str, source_role: str, call_chain: List[str]
    ) -> Optional[MultiAgentAnomaly]:
        """Detects cyclic delegation loops (e.g. A -> B -> A) that cause resource exhaustion."""
        seen: Set[str] = set()
        for agent in call_chain:
            if agent in seen:
                return MultiAgentAnomaly(
                    anomaly_type=MultiAgentAnomalyType.CYCLIC_DELEGATION,
                    source_agent=source_agent,
                    source_role=source_role,
                    action="delegate",
                    severity="HIGH",
                    reason=f"Cyclic delegation loop detected in call chain: {' -> '.join(call_chain)}",
                    evidence={"call_chain": call_chain, "repeated_agent": agent},
                )
            seen.add(agent)

        if source_agent in seen:
            return MultiAgentAnomaly(
                anomaly_type=MultiAgentAnomalyType.CYCLIC_DELEGATION,
                source_agent=source_agent,
                source_role=source_role,
                action="delegate",
                severity="HIGH",
                reason=f"Agent '{source_agent}' delegates back to an active parent in call chain: {' -> '.join(call_chain)}",
                evidence={"call_chain": call_chain, "reentered_agent": source_agent},
            )

        return None
