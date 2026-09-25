from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple

from runtimeverify.events.base import Event
from runtimeverify.policy.matcher import PolicyMatcher
from runtimeverify.policy.models import (
    ConflictResolutionStrategy,
    Policy,
    PolicyDecision,
    PolicyDecisionType,
    PolicySet,
)
from runtimeverify.state.classifier import DeterministicSecurityClassifier
from runtimeverify.state.security import SecurityState

logger = logging.getLogger(__name__)


class PolicyEvaluator:
    """
    Deterministic policy evaluator capable of evaluating canonical agent events
    against a PolicySet and producing explainable PolicyDecisions before execution.
    """

    def __init__(
        self,
        policy_set: Optional[PolicySet] = None,
        security_classifier: Optional[DeterministicSecurityClassifier] = None,
    ):
        self.policy_set: PolicySet = policy_set or PolicySet()
        self._classifier = security_classifier or DeterministicSecurityClassifier()

    def evaluate(
        self,
        event: Event,
        security_state: Optional[SecurityState] = None,
    ) -> PolicyDecision:
        """
        Evaluates a runtime event against all enabled policies in the policy set
        and applies conflict resolution rules to render a final PolicyDecision.

        Args:
            event: The observed or intended telemetry event.
            security_state: Optional pre-classified SecurityState.

        Returns:
            The final deterministic PolicyDecision.
        """
        # Resolve security state if not provided
        state = security_state
        if state is None:
            try:
                state = self._classifier.classify(event)
            except Exception as e:
                logger.debug("Failed to classify event state in policy evaluator: %s", e)
                state = None

        matched_list: List[Tuple[Policy, str]] = []

        # Evaluate each enabled policy in document order
        for policy in self.policy_set.policies:
            if not policy.enabled:
                continue

            matches, reason = PolicyMatcher.matches_event(policy, event, state)
            if matches:
                matched_list.append((policy, reason or f"Rule '{policy.id}' triggered"))

        # If no policies matched, return configured fallback
        if not matched_list:
            return PolicyDecision(
                decision=self.policy_set.default_decision,
                policy_id="default",
                severity=self.policy_set.default_severity,
                reason="No explicit policy rule matched; default decision applied.",
                matched_rule=None,
                matched_policies=[],
                timestamp=datetime.now(timezone.utc),
            )

        # Resolve conflict among multiple matching policies
        winning_policy, winning_reason = self._resolve_conflict(matched_list, self.policy_set.conflict_resolution)

        all_matched_rules: List[Dict[str, Any]] = [
            {
                "id": p.id,
                "name": p.name,
                "decision": p.decision.value,
                "severity": p.severity.value,
                "priority": p.priority,
                "reason": r,
            }
            for p, r in matched_list
        ]

        return PolicyDecision(
            decision=winning_policy.decision,
            policy_id=winning_policy.id,
            severity=winning_policy.severity,
            reason=winning_reason,
            matched_rule=winning_policy.model_dump(),
            matched_policies=all_matched_rules,
            timestamp=datetime.now(timezone.utc),
        )

    def _resolve_conflict(
        self,
        matches: List[Tuple[Policy, str]],
        strategy: ConflictResolutionStrategy,
    ) -> Tuple[Policy, str]:
        """
        Selects the winning policy according to the specified conflict resolution strategy.
        """
        if len(matches) == 1:
            return matches[0]

        if strategy == ConflictResolutionStrategy.FIRST_MATCH:
            return matches[0]

        if strategy == ConflictResolutionStrategy.HIGHEST_PRIORITY:
            # 1. Highest priority integer
            # 2. Ties broken by MOST_RESTRICTIVE
            # 3. Ties broken by highest severity
            sorted_matches = sorted(
                matches,
                key=lambda item: (
                    item[0].priority,
                    self._decision_restrictiveness(item[0].decision),
                    item[0].severity.rank,
                ),
                reverse=True,
            )
            return sorted_matches[0]

        if strategy == ConflictResolutionStrategy.HIGHEST_SEVERITY:
            # 1. Highest severity rank
            # 2. Ties broken by MOST_RESTRICTIVE
            # 3. Ties broken by highest priority
            sorted_matches = sorted(
                matches,
                key=lambda item: (
                    item[0].severity.rank,
                    self._decision_restrictiveness(item[0].decision),
                    item[0].priority,
                ),
                reverse=True,
            )
            return sorted_matches[0]

        # Default: MOST_RESTRICTIVE (BLOCK > REVIEW > ALLOW)
        # 1. BLOCK overrides REVIEW, REVIEW overrides ALLOW
        # 2. Ties broken by highest severity
        # 3. Ties broken by highest priority
        sorted_matches = sorted(
            matches,
            key=lambda item: (
                self._decision_restrictiveness(item[0].decision),
                item[0].severity.rank,
                item[0].priority,
            ),
            reverse=True,
        )
        return sorted_matches[0]

    @staticmethod
    def _decision_restrictiveness(decision: PolicyDecisionType) -> int:
        """
        Assigns numeric restrictiveness score:
        BLOCK (3) > REVIEW (2) > ALLOW (1).
        """
        ranks = {
            PolicyDecisionType.BLOCK: 3,
            PolicyDecisionType.REVIEW: 2,
            PolicyDecisionType.ALLOW: 1,
        }
        return ranks.get(decision, 0)

    def add_policy(self, policy: Policy) -> None:
        """Adds a policy rule to the active policy set."""
        # Check for duplicate id
        current = list(self.policy_set.policies)
        if any(p.id == policy.id for p in current):
            raise ValueError(f"Policy with id '{policy.id}' already exists in PolicySet.")
        current.append(policy)
        self.policy_set = PolicySet(
            version=self.policy_set.version,
            name=self.policy_set.name,
            description=self.policy_set.description,
            policies=current,
            default_decision=self.policy_set.default_decision,
            default_severity=self.policy_set.default_severity,
            conflict_resolution=self.policy_set.conflict_resolution,
        )

    def remove_policy(self, policy_id: str) -> bool:
        """Removes a policy by ID."""
        current = [p for p in self.policy_set.policies if p.id != policy_id]
        if len(current) == len(self.policy_set.policies):
            return False
        self.policy_set = PolicySet(
            version=self.policy_set.version,
            name=self.policy_set.name,
            description=self.policy_set.description,
            policies=current,
            default_decision=self.policy_set.default_decision,
            default_severity=self.policy_set.default_severity,
            conflict_resolution=self.policy_set.conflict_resolution,
        )
        return True

    def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Retrieves a policy by ID."""
        for p in self.policy_set.policies:
            if p.id == policy_id:
                return p
        return None
