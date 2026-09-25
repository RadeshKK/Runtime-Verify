from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from runtimeverify.semantic.models import SemanticEngineConfig


class PolicyDecisionType(str, Enum):
    """
    Deterministic decisions rendered by the policy engine.
    """

    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class PolicySeverity(str, Enum):
    """
    Severity rating associated with a policy rule or policy violation.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric rank for comparing severity (higher = more severe)."""
        ranks = {
            PolicySeverity.INFO: 1,
            PolicySeverity.LOW: 2,
            PolicySeverity.MEDIUM: 3,
            PolicySeverity.HIGH: 4,
            PolicySeverity.CRITICAL: 5,
        }
        return ranks[self]


class ConflictResolutionStrategy(str, Enum):
    """
    Strategy for resolving outcomes when multiple policies match an event.
    """

    MOST_RESTRICTIVE = "most_restrictive"  # BLOCK > REVIEW > ALLOW
    HIGHEST_SEVERITY = "highest_severity"  # CRITICAL > HIGH > MEDIUM > LOW > INFO
    HIGHEST_PRIORITY = "highest_priority"  # Explicit numeric priority
    FIRST_MATCH = "first_match"  # First matching rule in defined order


class StringPattern(BaseModel):
    """
    Configurable pattern for matching string values.
    Supports glob wildcards, regular expressions, exact matching, and prefixes.
    """

    model_config = ConfigDict(frozen=True)

    glob: Optional[str] = Field(None, description="Glob wildcard pattern (e.g. '~/.aws/*')")
    regex: Optional[str] = Field(None, description="Regular expression pattern")
    exact: Optional[str] = Field(None, description="Exact string match")
    prefix: Optional[str] = Field(None, description="Prefix match")
    contains: Optional[str] = Field(None, description="Substring contains match")
    any_of: Optional[List[str]] = Field(None, description="Matches if value equals any in list")
    case_sensitive: bool = Field(False, description="Whether matching is case sensitive")


class PathPattern(BaseModel):
    """
    Specialized pattern for filesystem paths, including home expansion and traversal detection.
    """

    model_config = ConfigDict(frozen=True)

    glob: Optional[str] = Field(None, description="Glob path pattern (e.g. '~/.ssh/*')")
    regex: Optional[str] = Field(None, description="Regular expression path pattern")
    exact: Optional[str] = Field(None, description="Exact path match")
    prefix: Optional[str] = Field(None, description="Path prefix match")
    contains: Optional[str] = Field(None, description="Substring path match")
    any_of: Optional[List[str]] = Field(None, description="Matches any listed path")
    case_sensitive: bool = Field(False, description="Whether path matching is case sensitive")
    block_traversal: bool = Field(True, description="Automatically flags and matches directory traversal (..)")


class ShellPattern(BaseModel):
    """
    Pattern for evaluating shell execution commands.
    """

    model_config = ConfigDict(frozen=True)

    command: Optional[Union[StringPattern, str]] = Field(None, description="Pattern for command string")
    pipe_to_shell: Optional[bool] = Field(None, description="Detects piping directly to shell (e.g. curl | bash)")
    destructive: Optional[bool] = Field(
        None, description="Matches commands flagged as destructive (rm -rf, mkfs, etc.)"
    )
    privileged: Optional[bool] = Field(
        None, description="Matches commands flagged as privileged (sudo, chmod 777, etc.)"
    )
    network: Optional[bool] = Field(None, description="Matches commands initiating network access (curl, wget, ssh)")


class NetworkPattern(BaseModel):
    """
    Pattern for evaluating network destinations, hosts, and IP addresses.
    """

    model_config = ConfigDict(frozen=True)

    domains: Optional[List[Union[StringPattern, str]]] = Field(None, description="List of domain patterns")
    urls: Optional[List[Union[StringPattern, str]]] = Field(None, description="List of URL patterns")
    ip_ranges: Optional[List[str]] = Field(None, description="List of CIDR blocks (e.g. 10.0.0.0/8, 169.254.0.0/16)")
    sensitive_only: Optional[bool] = Field(None, description="Matches cloud metadata (169.254.169.254) or localhost")
    unknown_only: Optional[bool] = Field(None, description="Matches unlisted or untrusted external internet hosts")
    ports: Optional[List[int]] = Field(None, description="Specific ports to match")


class GitPattern(BaseModel):
    """
    Pattern for evaluating git operations and branch policies.
    """

    model_config = ConfigDict(frozen=True)

    operations: Optional[List[str]] = Field(None, description="Git operations to match (e.g. ['push', 'commit'])")
    branches: Optional[List[Union[StringPattern, str]]] = Field(
        None, description="Branches to match (e.g. ['main', 'master'])"
    )
    repositories: Optional[List[Union[StringPattern, str]]] = Field(None, description="Repository URL/name patterns")


class ProcessPattern(BaseModel):
    """
    Pattern for process spawning and execution.
    """

    model_config = ConfigDict(frozen=True)

    command_line: Optional[Union[StringPattern, str]] = Field(None, description="Command line string pattern")
    executable: Optional[Union[StringPattern, str]] = Field(None, description="Executable name or path pattern")


class CredentialPattern(BaseModel):
    """
    Pattern for credential and secret access requests.
    """

    model_config = ConfigDict(frozen=True)

    credential_types: Optional[List[str]] = Field(None, description="Credential types (e.g. ['api_key', 'ssh_key'])")
    target: Optional[Union[StringPattern, str]] = Field(None, description="Credential identifier or target name")


class ToolPattern(BaseModel):
    """
    Pattern for tool invocations and function calls.
    """

    model_config = ConfigDict(frozen=True)

    names: Optional[List[str]] = Field(None, description="Tool names (e.g. ['bash', 'fs_read'])")
    arguments: Optional[Dict[str, Any]] = Field(None, description="Argument key-value match criteria")


class AgentPattern(BaseModel):
    """
    Pattern for agent identity and archetype filtering.
    """

    model_config = ConfigDict(frozen=True)

    agent_ids: Optional[List[str]] = Field(None, description="Specific agent IDs to match")
    agent_types: Optional[List[str]] = Field(None, description="Agent roles or archetypes (e.g. ['coder', 'worker'])")


class PolicyMatchCriteria(BaseModel):
    """
    Composite criteria used to match an incoming event.
    All non-null criteria in this block must be satisfied for the policy to match (logical AND).
    """

    model_config = ConfigDict(frozen=True)

    # General event discriminators
    event_types: Optional[List[str]] = Field(
        None, description="Matching canonical event types (e.g. ['filesystem.read'])"
    )
    security_categories: Optional[List[str]] = Field(None, description="Matching SecurityStateCategory values")
    risk_levels: Optional[List[str]] = Field(None, description="Matching risk levels (e.g. ['HIGH', 'CRITICAL'])")
    environments: Optional[List[str]] = Field(
        None, description="Matching environments (e.g. ['production', 'staging'])"
    )

    # Domain-specific pattern matchers
    path: Optional[Union[PathPattern, StringPattern, str]] = Field(None, description="Filesystem path criteria")
    command: Optional[Union[ShellPattern, StringPattern, str]] = Field(None, description="Shell command criteria")
    network: Optional[Union[NetworkPattern, StringPattern, str]] = Field(
        None, description="Network destination criteria"
    )
    git: Optional[Union[GitPattern, str]] = Field(None, description="Git operation criteria")
    process: Optional[Union[ProcessPattern, StringPattern, str]] = Field(None, description="Process execution criteria")
    credential: Optional[Union[CredentialPattern, str]] = Field(None, description="Credential access criteria")
    tool: Optional[Union[ToolPattern, str]] = Field(None, description="Tool invocation criteria")
    agent: Optional[Union[AgentPattern, str]] = Field(None, description="Agent identity criteria")

    @model_validator(mode="before")
    @classmethod
    def normalize_match_inputs(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Support singular event_type as shorthand for list
            if "event_type" in data and "event_types" not in data:
                val = data.pop("event_type")
                data["event_types"] = [val] if isinstance(val, str) else list(val)

            # Support singular security_category as shorthand
            if "security_category" in data and "security_categories" not in data:
                val = data.pop("security_category")
                data["security_categories"] = [val] if isinstance(val, str) else list(val)

            # Support singular environment as shorthand
            if "environment" in data and "environments" not in data:
                val = data.pop("environment")
                data["environments"] = [val] if isinstance(val, str) else list(val)

            # Support singular risk_level as shorthand
            if "risk_level" in data and "risk_levels" not in data:
                val = data.pop("risk_level")
                data["risk_levels"] = [val] if isinstance(val, str) else list(val)
        return data


class Policy(BaseModel):
    """
    Immutable representation of an individual deterministic policy rule.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., description="Unique policy identifier (e.g. 'deny-aws-credentials')")
    name: Optional[str] = Field(None, description="Human-readable policy name")
    description: Optional[str] = Field(None, description="Description of rule intent and rationale")
    enabled: bool = Field(True, description="Whether this policy is active")
    decision: PolicyDecisionType = Field(..., description="Decision rendered if policy matches: ALLOW, REVIEW, BLOCK")
    severity: PolicySeverity = Field(PolicySeverity.MEDIUM, description="Security severity level")
    priority: int = Field(0, description="Priority integer (higher values evaluated first in priority mode)")
    match: PolicyMatchCriteria = Field(..., description="Criteria required to trigger this policy")
    reason: Optional[str] = Field(None, description="Explanation provided when this rule triggers")

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Policy id cannot be empty.")
        return trimmed


class PolicySet(BaseModel):
    """
    A versioned collection of policy rules with conflict resolution configuration.
    """

    model_config = ConfigDict(frozen=True)

    version: str = Field("1.0", description="Policy schema version")
    name: str = Field("default", description="Name of this policy set")
    description: Optional[str] = Field(None, description="Description of the policy set purpose")
    policies: List[Policy] = Field(default_factory=list, description="Ordered list of policy rules")
    default_decision: PolicyDecisionType = Field(
        PolicyDecisionType.ALLOW, description="Fallback decision if no rules match"
    )
    default_severity: PolicySeverity = Field(PolicySeverity.INFO, description="Fallback severity if no rules match")
    conflict_resolution: ConflictResolutionStrategy = Field(
        ConflictResolutionStrategy.MOST_RESTRICTIVE,
        description="Conflict resolution strategy when multiple policies match",
    )
    semantic_engine: Optional[SemanticEngineConfig] = Field(
        None,
        description="Optional configuration for semantic decision engines (e.g. Laya)",
    )

    @field_validator("policies")
    @classmethod
    def validate_unique_policy_ids(cls, v: List[Policy]) -> List[Policy]:
        seen = set()
        for p in v:
            if p.id in seen:
                raise ValueError(f"Duplicate policy ID detected in PolicySet: '{p.id}'")
            seen.add(p.id)
        return v


class PolicyDecision(BaseModel):
    """
    The structured outcome produced by the PolicyEvaluator.
    Deterministic, explainable, and fully auditable.
    """

    model_config = ConfigDict(frozen=True)

    decision: PolicyDecisionType = Field(..., description="Final decision: ALLOW, REVIEW, or BLOCK")
    policy_id: str = Field(..., description="Identifier of the winning policy, or 'default'")
    severity: PolicySeverity = Field(..., description="Assigned severity rating")
    reason: str = Field(..., description="Human-readable explanation of the evaluation outcome")
    matched_rule: Optional[Dict[str, Any]] = Field(None, description="Details of the winning matched rule")
    matched_policies: List[Dict[str, Any]] = Field(
        default_factory=list, description="All policies that matched during evaluation"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of when the evaluation took place",
    )
