from pathlib import Path
import pytest

from runtimeverify.policy.loader import (
    dump_policy_to_dict,
    dump_policy_to_yaml,
    load_policy_from_dict,
    load_policy_from_yaml,
)
from runtimeverify.policy.models import PolicyDecisionType


class TestYamlLoader:
    """Verifies YAML parsing, validation, serialization, and round-tripping."""

    def test_load_from_yaml_string(self):
        yaml_content = """
version: "1.0"
name: "test-policy-set"
conflict_resolution: "highest_priority"
default_decision: "REVIEW"
policies:
  - id: "rule-1"
    name: "Rule One"
    decision: "BLOCK"
    severity: "HIGH"
    priority: 50
    match:
      command:
        destructive: true
"""
        policy_set = load_policy_from_yaml(yaml_content)
        assert policy_set.version == "1.0"
        assert policy_set.name == "test-policy-set"
        assert policy_set.default_decision == PolicyDecisionType.REVIEW
        assert len(policy_set.policies) == 1
        assert policy_set.policies[0].id == "rule-1"
        assert policy_set.policies[0].decision == PolicyDecisionType.BLOCK

    def test_load_from_yaml_file(self):
        default_file = Path("examples/policies/default.yaml")
        policy_set = load_policy_from_yaml(default_file)
        assert len(policy_set.policies) >= 10

    def test_strict_and_developer_policy_sets(self):
        strict_file = Path("examples/policies/strict.yaml")
        strict_set = load_policy_from_yaml(strict_file)
        assert strict_set.default_decision == PolicyDecisionType.BLOCK

        dev_file = Path("examples/policies/developer.yaml")
        dev_set = load_policy_from_yaml(dev_file)
        assert dev_set.default_decision == PolicyDecisionType.ALLOW

    def test_round_trip_serialization(self):
        default_file = Path("examples/policies/default.yaml")
        policy_set = load_policy_from_yaml(default_file)

        yaml_output = dump_policy_to_yaml(policy_set)
        reloaded = load_policy_from_yaml(yaml_output)

        assert reloaded.version == policy_set.version
        assert len(reloaded.policies) == len(policy_set.policies)
        assert reloaded.policies[0].id == policy_set.policies[0].id

    def test_invalid_yaml_structure_raises(self):
        with pytest.raises(ValueError, match="Invalid YAML policy structure"):
            load_policy_from_yaml("- a\n- b\n- c")

    def test_missing_file_raises_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_policy_from_yaml("non_existent_policy_file.yaml")

    def test_dict_serialization(self):
        default_file = Path("examples/policies/default.yaml")
        policy_set = load_policy_from_yaml(default_file)
        data = dump_policy_to_dict(policy_set)
        assert isinstance(data, dict)
        reloaded = load_policy_from_dict(data)
        assert len(reloaded.policies) == len(policy_set.policies)
