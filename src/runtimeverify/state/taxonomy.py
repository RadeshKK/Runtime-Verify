from enum import Enum
from typing import Dict, List
from runtimeverify.state.categories import StateCategory
from runtimeverify.state.hierarchy import StateHierarchy


class SecurityStateCategory(str, Enum):
    """
    Canonical security-state taxonomy used by RuntimeVerify's behavioral and verification engine.
    Normalized categories mapping runtime agent events into behavioral states.
    """

    # LLM Interactions
    LLM_REQUEST = "LLM_REQUEST"
    LLM_RESPONSE = "LLM_RESPONSE"

    # Filesystem Operations
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    FILE_DELETE = "FILE_DELETE"

    # Shell Execution
    SHELL_SAFE = "SHELL_SAFE"
    SHELL_NETWORK = "SHELL_NETWORK"
    SHELL_PRIVILEGED = "SHELL_PRIVILEGED"
    SHELL_DESTRUCTIVE = "SHELL_DESTRUCTIVE"

    # Network Activity
    NETWORK_TRUSTED = "NETWORK_TRUSTED"
    NETWORK_UNKNOWN = "NETWORK_UNKNOWN"
    NETWORK_SENSITIVE = "NETWORK_SENSITIVE"

    # Git Operations
    GIT_READ = "GIT_READ"
    GIT_COMMIT = "GIT_COMMIT"
    GIT_PUSH = "GIT_PUSH"

    # Process Lifecycle
    PROCESS_CREATE = "PROCESS_CREATE"
    PROCESS_TERMINATE = "PROCESS_TERMINATE"

    # Secrets & Credentials
    SECRET_ACCESS = "SECRET_ACCESS"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"

    # Tool Invocations
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"

    # Multi-Agent Coordination
    AGENT_MESSAGE = "AGENT_MESSAGE"
    AGENT_HANDOFF = "AGENT_HANDOFF"

    # Human Oversight & Policy Enforcement
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    POLICY_ALLOW = "POLICY_ALLOW"
    POLICY_REVIEW = "POLICY_REVIEW"
    POLICY_BLOCK = "POLICY_BLOCK"

    # Unrecognized / Ambiguous
    UNKNOWN = "UNKNOWN"


class SecurityRiskLevel(str, Enum):
    """
    Security risk classification rating associated with behavioral states.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Mapping from SecurityStateCategory to parent operational StateCategory
SECURITY_TO_STATE_CATEGORY: Dict[SecurityStateCategory, StateCategory] = {
    SecurityStateCategory.LLM_REQUEST: StateCategory.LLM,
    SecurityStateCategory.LLM_RESPONSE: StateCategory.LLM,
    SecurityStateCategory.FILE_READ: StateCategory.FILESYSTEM,
    SecurityStateCategory.FILE_WRITE: StateCategory.FILESYSTEM,
    SecurityStateCategory.FILE_DELETE: StateCategory.FILESYSTEM,
    SecurityStateCategory.SHELL_SAFE: StateCategory.EXECUTION,
    SecurityStateCategory.SHELL_NETWORK: StateCategory.EXECUTION,
    SecurityStateCategory.SHELL_PRIVILEGED: StateCategory.EXECUTION,
    SecurityStateCategory.SHELL_DESTRUCTIVE: StateCategory.EXECUTION,
    SecurityStateCategory.NETWORK_TRUSTED: StateCategory.NETWORK,
    SecurityStateCategory.NETWORK_UNKNOWN: StateCategory.NETWORK,
    SecurityStateCategory.NETWORK_SENSITIVE: StateCategory.NETWORK,
    SecurityStateCategory.GIT_READ: StateCategory.SYSTEM,
    SecurityStateCategory.GIT_COMMIT: StateCategory.SYSTEM,
    SecurityStateCategory.GIT_PUSH: StateCategory.SYSTEM,
    SecurityStateCategory.PROCESS_CREATE: StateCategory.SYSTEM,
    SecurityStateCategory.PROCESS_TERMINATE: StateCategory.SYSTEM,
    SecurityStateCategory.SECRET_ACCESS: StateCategory.SECURITY,
    SecurityStateCategory.CREDENTIAL_ACCESS: StateCategory.SECURITY,
    SecurityStateCategory.TOOL_CALL: StateCategory.TOOL,
    SecurityStateCategory.TOOL_RESULT: StateCategory.TOOL,
    SecurityStateCategory.AGENT_MESSAGE: StateCategory.EXECUTION,
    SecurityStateCategory.AGENT_HANDOFF: StateCategory.EXECUTION,
    SecurityStateCategory.HUMAN_APPROVAL: StateCategory.HUMAN,
    SecurityStateCategory.POLICY_ALLOW: StateCategory.POLICY,
    SecurityStateCategory.POLICY_REVIEW: StateCategory.POLICY,
    SecurityStateCategory.POLICY_BLOCK: StateCategory.POLICY,
    SecurityStateCategory.UNKNOWN: StateCategory.SYSTEM,
}


# Default hierarchy paths for each security state category
SECURITY_HIERARCHY_PATHS: Dict[SecurityStateCategory, List[str]] = {
    SecurityStateCategory.LLM_REQUEST: ["LLM", "REQUEST"],
    SecurityStateCategory.LLM_RESPONSE: ["LLM", "RESPONSE"],
    SecurityStateCategory.FILE_READ: ["FILESYSTEM", "READ"],
    SecurityStateCategory.FILE_WRITE: ["FILESYSTEM", "WRITE"],
    SecurityStateCategory.FILE_DELETE: ["FILESYSTEM", "DELETE"],
    SecurityStateCategory.SHELL_SAFE: ["EXECUTION", "SHELL", "SAFE"],
    SecurityStateCategory.SHELL_NETWORK: ["EXECUTION", "SHELL", "NETWORK"],
    SecurityStateCategory.SHELL_PRIVILEGED: ["EXECUTION", "SHELL", "PRIVILEGED"],
    SecurityStateCategory.SHELL_DESTRUCTIVE: ["EXECUTION", "SHELL", "DESTRUCTIVE"],
    SecurityStateCategory.NETWORK_TRUSTED: ["NETWORK", "TRUSTED"],
    SecurityStateCategory.NETWORK_UNKNOWN: ["NETWORK", "UNKNOWN"],
    SecurityStateCategory.NETWORK_SENSITIVE: ["NETWORK", "SENSITIVE"],
    SecurityStateCategory.GIT_READ: ["SYSTEM", "GIT", "READ"],
    SecurityStateCategory.GIT_COMMIT: ["SYSTEM", "GIT", "COMMIT"],
    SecurityStateCategory.GIT_PUSH: ["SYSTEM", "GIT", "PUSH"],
    SecurityStateCategory.PROCESS_CREATE: ["SYSTEM", "PROCESS", "CREATE"],
    SecurityStateCategory.PROCESS_TERMINATE: ["SYSTEM", "PROCESS", "TERMINATE"],
    SecurityStateCategory.SECRET_ACCESS: ["SECURITY", "SECRET", "ACCESS"],
    SecurityStateCategory.CREDENTIAL_ACCESS: ["SECURITY", "CREDENTIAL", "ACCESS"],
    SecurityStateCategory.TOOL_CALL: ["TOOL", "CALL"],
    SecurityStateCategory.TOOL_RESULT: ["TOOL", "RESULT"],
    SecurityStateCategory.AGENT_MESSAGE: ["EXECUTION", "AGENT", "MESSAGE"],
    SecurityStateCategory.AGENT_HANDOFF: ["EXECUTION", "AGENT", "HANDOFF"],
    SecurityStateCategory.HUMAN_APPROVAL: ["HUMAN", "APPROVAL"],
    SecurityStateCategory.POLICY_ALLOW: ["POLICY", "ALLOW"],
    SecurityStateCategory.POLICY_REVIEW: ["POLICY", "REVIEW"],
    SecurityStateCategory.POLICY_BLOCK: ["POLICY", "BLOCK"],
    SecurityStateCategory.UNKNOWN: ["SYSTEM", "UNKNOWN"],
}


# Default baseline risk levels for each category
DEFAULT_SECURITY_RISK_MAP: Dict[SecurityStateCategory, SecurityRiskLevel] = {
    SecurityStateCategory.SHELL_DESTRUCTIVE: SecurityRiskLevel.CRITICAL,
    SecurityStateCategory.SHELL_PRIVILEGED: SecurityRiskLevel.HIGH,
    SecurityStateCategory.SECRET_ACCESS: SecurityRiskLevel.HIGH,
    SecurityStateCategory.CREDENTIAL_ACCESS: SecurityRiskLevel.HIGH,
    SecurityStateCategory.NETWORK_SENSITIVE: SecurityRiskLevel.HIGH,
    SecurityStateCategory.POLICY_BLOCK: SecurityRiskLevel.HIGH,
    SecurityStateCategory.FILE_DELETE: SecurityRiskLevel.MEDIUM,
    SecurityStateCategory.SHELL_NETWORK: SecurityRiskLevel.MEDIUM,
    SecurityStateCategory.GIT_PUSH: SecurityRiskLevel.MEDIUM,
    SecurityStateCategory.POLICY_REVIEW: SecurityRiskLevel.MEDIUM,
    SecurityStateCategory.PROCESS_TERMINATE: SecurityRiskLevel.MEDIUM,
    SecurityStateCategory.FILE_WRITE: SecurityRiskLevel.LOW,
    SecurityStateCategory.GIT_COMMIT: SecurityRiskLevel.LOW,
    SecurityStateCategory.PROCESS_CREATE: SecurityRiskLevel.LOW,
    SecurityStateCategory.NETWORK_UNKNOWN: SecurityRiskLevel.LOW,
    SecurityStateCategory.TOOL_CALL: SecurityRiskLevel.LOW,
    SecurityStateCategory.TOOL_RESULT: SecurityRiskLevel.LOW,
    SecurityStateCategory.HUMAN_APPROVAL: SecurityRiskLevel.LOW,
    SecurityStateCategory.AGENT_HANDOFF: SecurityRiskLevel.LOW,
    SecurityStateCategory.POLICY_ALLOW: SecurityRiskLevel.LOW,
    SecurityStateCategory.FILE_READ: SecurityRiskLevel.INFO,
    SecurityStateCategory.GIT_READ: SecurityRiskLevel.INFO,
    SecurityStateCategory.LLM_REQUEST: SecurityRiskLevel.INFO,
    SecurityStateCategory.LLM_RESPONSE: SecurityRiskLevel.INFO,
    SecurityStateCategory.SHELL_SAFE: SecurityRiskLevel.INFO,
    SecurityStateCategory.NETWORK_TRUSTED: SecurityRiskLevel.INFO,
    SecurityStateCategory.AGENT_MESSAGE: SecurityRiskLevel.INFO,
    SecurityStateCategory.UNKNOWN: SecurityRiskLevel.INFO,
}


def get_default_category(sec_cat: SecurityStateCategory) -> StateCategory:
    """Returns the operational StateCategory corresponding to a SecurityStateCategory."""
    return SECURITY_TO_STATE_CATEGORY.get(sec_cat, StateCategory.SYSTEM)


def get_default_hierarchy(sec_cat: SecurityStateCategory) -> StateHierarchy:
    """Returns the default StateHierarchy for a SecurityStateCategory."""
    path = SECURITY_HIERARCHY_PATHS.get(sec_cat, ["SYSTEM", sec_cat.value])
    return StateHierarchy(path=path)


def get_default_risk(sec_cat: SecurityStateCategory) -> SecurityRiskLevel:
    """Returns the baseline SecurityRiskLevel for a SecurityStateCategory."""
    return DEFAULT_SECURITY_RISK_MAP.get(sec_cat, SecurityRiskLevel.INFO)
