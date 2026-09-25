from pathlib import Path
from typing import Any, Dict, Union
import yaml

from runtimeverify.policy.models import PolicySet


def load_policy_from_dict(data: Dict[str, Any]) -> PolicySet:
    """
    Instantiates and validates a PolicySet from a Python dictionary.

    Args:
        data: Dictionary conforming to PolicySet schema.

    Returns:
        Validated PolicySet model.
    """
    return PolicySet.model_validate(data)


def load_policy_from_yaml(yaml_input: Union[str, Path]) -> PolicySet:
    """
    Loads and validates a PolicySet from YAML content or a file path.

    Args:
        yaml_input: Either a YAML formatted string or a Path / filename pointing to a YAML file.

    Returns:
        Validated PolicySet model.
    """
    # Check if input is an existing file path
    if isinstance(yaml_input, Path) or (
        isinstance(yaml_input, str)
        and "\n" not in yaml_input
        and (yaml_input.endswith(".yaml") or yaml_input.endswith(".yml") or Path(yaml_input).exists())
    ):
        file_path = Path(yaml_input)
        if not file_path.is_file():
            raise FileNotFoundError(f"Policy file not found: {yaml_input}")
        content = file_path.read_text(encoding="utf-8")
    else:
        content = str(yaml_input)

    parsed = yaml.safe_load(content)
    if not isinstance(parsed, dict):
        raise ValueError("Invalid YAML policy structure: root must be a mapping/dictionary.")

    return load_policy_from_dict(parsed)


def dump_policy_to_dict(policy_set: PolicySet) -> Dict[str, Any]:
    """
    Serializes a PolicySet into a raw dictionary, stripping None fields.
    """
    return policy_set.model_dump(mode="json", exclude_none=True)


def dump_policy_to_yaml(policy_set: PolicySet) -> str:
    """
    Serializes a PolicySet into a clean YAML string.
    """
    data = dump_policy_to_dict(policy_set)
    return yaml.dump(data, sort_keys=False, default_flow_style=False)
