from runtimeverify.events.canonical import ShellCommandEvent
from runtimeverify.policy.evaluator import PolicyEvaluator
from runtimeverify.policy.models import (
    ConflictResolutionStrategy,
    Policy,
    PolicyDecisionType,
    PolicyMatchCriteria,
    PolicySet,
    PolicySeverity,
    StringPattern,
)


class TestConflictResolution:
    """Verifies all conflict resolution rules and strategies."""

    def test_block_overrides_review_and_allow_in_most_restrictive(self):
        # 3 rules matching the same command
        p_allow = Policy(
            id="allow-rule",
            decision=PolicyDecisionType.ALLOW,
            severity=PolicySeverity.LOW,
            match=PolicyMatchCriteria(command=StringPattern(contains="npm")),
        )
        p_review = Policy(
            id="review-rule",
            decision=PolicyDecisionType.REVIEW,
            severity=PolicySeverity.MEDIUM,
            match=PolicyMatchCriteria(command=StringPattern(contains="npm")),
        )
        p_block = Policy(
            id="block-rule",
            decision=PolicyDecisionType.BLOCK,
            severity=PolicySeverity.CRITICAL,
            match=PolicyMatchCriteria(command=StringPattern(contains="npm")),
        )

        policy_set = PolicySet(
            conflict_resolution=ConflictResolutionStrategy.MOST_RESTRICTIVE,
            policies=[p_allow, p_review, p_block],
        )
        evaluator = PolicyEvaluator(policy_set=policy_set)

        ev = ShellCommandEvent(agent_id="a1", session_id="s1", command="npm install lodash")
        res = evaluator.evaluate(ev)

        assert res.decision == PolicyDecisionType.BLOCK
        assert res.policy_id == "block-rule"
        assert len(res.matched_policies) == 3

    def test_review_overrides_allow_in_most_restrictive(self):
        p_allow = Policy(
            id="allow-rule",
            decision=PolicyDecisionType.ALLOW,
            severity=PolicySeverity.LOW,
            match=PolicyMatchCriteria(command=StringPattern(contains="git")),
        )
        p_review = Policy(
            id="review-rule",
            decision=PolicyDecisionType.REVIEW,
            severity=PolicySeverity.MEDIUM,
            match=PolicyMatchCriteria(command=StringPattern(contains="git")),
        )

        policy_set = PolicySet(
            conflict_resolution=ConflictResolutionStrategy.MOST_RESTRICTIVE,
            policies=[p_allow, p_review],
        )
        evaluator = PolicyEvaluator(policy_set=policy_set)

        ev = ShellCommandEvent(agent_id="a1", session_id="s1", command="git push origin main")
        res = evaluator.evaluate(ev)

        assert res.decision == PolicyDecisionType.REVIEW
        assert res.policy_id == "review-rule"
        assert len(res.matched_policies) == 2

    def test_highest_severity_strategy(self):
        # Even if p_allow matches, higher severity p_review or p_block wins
        p_allow = Policy(
            id="allow-rule",
            decision=PolicyDecisionType.ALLOW,
            severity=PolicySeverity.INFO,
            match=PolicyMatchCriteria(command=StringPattern(contains="test")),
        )
        p_review = Policy(
            id="review-rule",
            decision=PolicyDecisionType.REVIEW,
            severity=PolicySeverity.HIGH,
            match=PolicyMatchCriteria(command=StringPattern(contains="test")),
        )

        policy_set = PolicySet(
            conflict_resolution=ConflictResolutionStrategy.HIGHEST_SEVERITY,
            policies=[p_allow, p_review],
        )
        evaluator = PolicyEvaluator(policy_set=policy_set)

        ev = ShellCommandEvent(agent_id="a1", session_id="s1", command="run test")
        res = evaluator.evaluate(ev)

        assert res.decision == PolicyDecisionType.REVIEW
        assert res.policy_id == "review-rule"
        assert res.severity == PolicySeverity.HIGH

    def test_highest_priority_strategy(self):
        p_low_priority_block = Policy(
            id="block-rule-low-pri",
            decision=PolicyDecisionType.BLOCK,
            severity=PolicySeverity.CRITICAL,
            priority=10,
            match=PolicyMatchCriteria(command=StringPattern(contains="exec")),
        )
        p_high_priority_allow = Policy(
            id="allow-rule-high-pri",
            decision=PolicyDecisionType.ALLOW,
            severity=PolicySeverity.INFO,
            priority=100,
            match=PolicyMatchCriteria(command=StringPattern(contains="exec")),
        )

        policy_set = PolicySet(
            conflict_resolution=ConflictResolutionStrategy.HIGHEST_PRIORITY,
            policies=[p_low_priority_block, p_high_priority_allow],
        )
        evaluator = PolicyEvaluator(policy_set=policy_set)

        ev = ShellCommandEvent(agent_id="a1", session_id="s1", command="exec test")
        res = evaluator.evaluate(ev)

        assert res.decision == PolicyDecisionType.ALLOW
        assert res.policy_id == "allow-rule-high-pri"

    def test_first_match_strategy(self):
        p_first = Policy(
            id="first-rule",
            decision=PolicyDecisionType.ALLOW,
            match=PolicyMatchCriteria(command=StringPattern(contains="cmd")),
        )
        p_second = Policy(
            id="second-rule",
            decision=PolicyDecisionType.BLOCK,
            match=PolicyMatchCriteria(command=StringPattern(contains="cmd")),
        )

        policy_set = PolicySet(
            conflict_resolution=ConflictResolutionStrategy.FIRST_MATCH,
            policies=[p_first, p_second],
        )
        evaluator = PolicyEvaluator(policy_set=policy_set)

        ev = ShellCommandEvent(agent_id="a1", session_id="s1", command="cmd arg")
        res = evaluator.evaluate(ev)

        assert res.decision == PolicyDecisionType.ALLOW
        assert res.policy_id == "first-rule"

    def test_fallback_when_no_rules_match(self):
        policy_set = PolicySet(
            default_decision=PolicyDecisionType.ALLOW,
            default_severity=PolicySeverity.INFO,
            policies=[],
        )
        evaluator = PolicyEvaluator(policy_set=policy_set)

        ev = ShellCommandEvent(agent_id="a1", session_id="s1", command="echo hello")
        res = evaluator.evaluate(ev)

        assert res.decision == PolicyDecisionType.ALLOW
        assert res.policy_id == "default"
        assert res.severity == PolicySeverity.INFO
        assert len(res.matched_policies) == 0
