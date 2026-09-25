"""
Multi-Agent Topology Learner & Baseline Engine for RuntimeVerify (Phase 17).
Extracts, fits, and models empirical multi-agent interaction topologies from benign telemetry traces.
Ensures RuntimeVerify baselines legitimate multi-agent collaboration rather than assuming all communication is hostile.
"""

from collections import Counter, defaultdict
from typing import Any, Dict, List, Set, Tuple
from runtimeverify.events.base import Event
from runtimeverify.multiagent.models import TopologyType
from runtimeverify.multiagent.topology import TopologyGraph


class TopologyLearner:
    """
    Learns valid multi-agent interaction topologies from observation logs or training traces.
    Establishes empirical baselines for normal cross-agent communication, delegation, and handoff sequences.
    """

    def __init__(
        self,
        name: str = "learned_baseline_topology",
        min_transition_count: int = 1,
        frequency_threshold: float = 0.01,
    ):
        self.name = name
        self.min_transition_count = min_transition_count
        self.frequency_threshold = frequency_threshold

        # Counts: (src_role, tgt_role) -> Counter(action -> count)
        self.edge_action_counts: Dict[Tuple[str, str], Counter] = defaultdict(Counter)
        # Outgoing counts from source_role
        self.source_counts: Counter = Counter()
        # Observed roles
        self.observed_roles: Set[str] = set()
        # Observed agent IDs to role mappings
        self.agent_role_cache: Dict[str, str] = {}

    def observe_event(self, event: Event) -> None:
        """Processes a single canonical or telemetry event to update the empirical baseline."""
        src_agent = event.agent_id
        src_role = (event.agent_role or event.agent_type or "worker").lower()
        self.agent_role_cache[src_agent] = src_role
        self.observed_roles.add(src_role)

        tgt_agent = event.target_agent_id
        tgt_role = (event.target_agent_role or "").lower()

        # If target_agent is known in cache but role not specified in event
        if tgt_agent and not tgt_role and tgt_agent in self.agent_role_cache:
            tgt_role = self.agent_role_cache[tgt_agent]

        action = (event.action or "message").lower()

        if tgt_role:
            self.observed_roles.add(tgt_role)
            edge_key = (src_role, tgt_role)
            self.edge_action_counts[edge_key][action] += 1
            self.source_counts[src_role] += 1

    def fit_traces(self, traces: List[List[Event]]) -> "TopologyGraph":
        """
        Batch fits the learner on a collection of session traces,
        returning an initialized and baseline-trained TopologyGraph.
        """
        for trace in traces:
            for event in trace:
                self.observe_event(event)

        return self.build_topology_graph()

    def build_topology_graph(self) -> TopologyGraph:
        """
        Synthesizes the empirical observations into an authorized TopologyGraph.
        Includes all edges meeting the frequency and count criteria.
        """
        graph = TopologyGraph(
            name=self.name,
            topology_type=TopologyType.CUSTOM,
            allow_unknown_roles=False,
        )

        for (src, tgt), action_counter in self.edge_action_counts.items():
            total_edge_trans = sum(action_counter.values())
            src_total = self.source_counts[src]

            freq = total_edge_trans / max(1, src_total)

            if total_edge_trans >= self.min_transition_count and freq >= self.frequency_threshold:
                allowed_acts = set(action_counter.keys())
                graph.add_edge(
                    source_role=src,
                    target_role=tgt,
                    allowed_actions=allowed_acts,
                    metadata={
                        "empirical_count": total_edge_trans,
                        "empirical_frequency": freq,
                    },
                )

        return graph

    def get_statistics(self) -> Dict[str, Any]:
        """Returns diagnostic statistics of the learned topology."""
        edges_summary = []
        for (src, tgt), counter in self.edge_action_counts.items():
            edges_summary.append(
                {
                    "source": src,
                    "target": tgt,
                    "total_transitions": sum(counter.values()),
                    "actions": dict(counter),
                }
            )
        return {
            "total_observed_roles": len(self.observed_roles),
            "roles": sorted(list(self.observed_roles)),
            "total_edges": len(self.edge_action_counts),
            "edges": edges_summary,
        }
