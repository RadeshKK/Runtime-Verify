import pytest
from pydantic import ValidationError

from runtimeverify.policy.models import (
    PathPattern,
    Policy,
    PolicyDecision,
    PolicyDecisionType,
    PolicyMatchCriteria,
    PolicySet,
    PolicySeverity,
)


class TestPolicyModels:
    """Verifies schema validation, immutability, and constraints of policy models."""

    def test_policy_creation_and_defaults(self):
        policy = Policy(
            id="test-rule-01",
            name="Test Policy",
            decision=PolicyDecisionType.BLOCK,
            severity=PolicySeverity.CRITICAL,
            match=PolicyMatchCriteria(
                event_types=["filesystem.read"],
                path=PathPattern(glob="~/.aws/*"),
            ),
        )
        assert policy.id == "test-rule-01"
        assert policy.decision == PolicyDecisionType.BLOCK
        assert policy.severity == PolicySeverity.CRITICAL
        assert policy.priority == 0
        assert policy.enabled is True

    def test_policy_id_cannot_be_empty(self):
        with pytest.raises(ValidationError):
            Policy(
                id="   ",
                decision=PolicyDecisionType.ALLOW,
                match=PolicyMatchCriteria(),
            )

    def test_policy_immutability(self):
        policy = Policy(
            id="immutable-policy",
            decision=PolicyDecisionType.BLOCK,
            match=PolicyMatchCriteria(),
        )
        with pytest.raises(ValidationError):
            policy.decision = PolicyDecisionType.ALLOW  # type: ignore

    def test_policy_set_duplicate_ids_rejected(self):
        p1 = Policy(
            id="dup-id",
            decision=PolicyDecisionType.ALLOW,
            match=PolicyMatchCriteria(),
        )
        p2 = Policy(
            id="dup-id",
            decision=PolicyDecisionType.BLOCK,
            match=PolicyMatchCriteria(),
        )
        with pytest.raises(ValidationError, match="Duplicate policy ID detected"):
            PolicySet(policies=[p1, p2])

    def test_policy_severity_ranks(self):
        assert PolicySeverity.CRITICAL.rank > PolicySeverity.HIGH.rank
        assert PolicySeverity.HIGH.rank > PolicySeverity.MEDIUM.rank
        assert PolicySeverity.MEDIUM.rank > PolicySeverity.LOW.rank
        assert PolicySeverity.LOW.rank > PolicySeverity.INFO.rank

    def test_match_criteria_shorthand_normalization(self):
        criteria = PolicyMatchCriteria.model_validate(
            {
                "event_type": "filesystem.read",
                "security_category": "FILE_READ",
                "environment": "production",
                "risk_level": "HIGH",
            }
        )
        assert criteria.event_types == ["filesystem.read"]
        assert criteria.security_categories == ["FILE_READ"]
        assert criteria.environments == ["production"]
        assert criteria.risk_levels == ["HIGH"]

    def test_policy_decision_model(self):
        decision = PolicyDecision(
            decision=PolicyDecisionType.BLOCK,
            policy_id="block-rule",
            severity=PolicySeverity.HIGH,
            reason="Blocked due to critical vulnerability",
            matched_rule={"id": "block-rule"},
        )
        assert decision.decision == PolicyDecisionType.BLOCK
        assert decision.policy_id == "block-rule"
        assert decision.severity == PolicySeverity.HIGH
        assert decision.matched_rule == {"id": "block-rule"}
        assert decision.timestamp is not None
