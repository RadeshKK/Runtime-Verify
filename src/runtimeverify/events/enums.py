from enum import Enum


class EventType(str, Enum):
    """
    Standardized event type discriminators for autonomous agent telemetry.
    Dot-separated hierarchical strings align with OpenTelemetry semantic conventions.
    """

    LLM_REQUEST = "llm.request"
    LLM_RESPONSE = "llm.response"
    TOOL_CALL = "tool.call"
    TOOL_RESULT = "tool.result"
    FILESYSTEM_READ = "filesystem.read"
    FILESYSTEM_WRITE = "filesystem.write"
    FILESYSTEM_DELETE = "filesystem.delete"
    SHELL_COMMAND = "shell.command"
    NETWORK_REQUEST = "network.request"
    GIT_OPERATION = "git.operation"
    CREDENTIAL_ACCESS = "credential.access"
    PROCESS_CREATION = "process.creation"
    AGENT_COMMUNICATION = "agent.communication"
    AGENT_DELEGATION = "agent.delegation"
    AGENT_HANDOFF = "agent.handoff"
    HUMAN_APPROVAL = "human.approval"
    POLICY_DECISION = "policy.decision"
    GENERIC = "generic"


class EventAction(str, Enum):
    """
    Standardized action verbs describing the operation performed within an event.
    """

    REQUEST = "request"
    RESPONSE = "response"
    CALL = "call"
    RESULT = "result"
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    CONNECT = "connect"
    COMMIT = "commit"
    PUSH = "push"
    PULL = "pull"
    CLONE = "clone"
    CHECKOUT = "checkout"
    ACCESS = "access"
    SPAWN = "spawn"
    SEND = "send"
    RECEIVE = "receive"
    DELEGATE = "delegate"
    HANDOFF = "handoff"
    MESSAGE = "message"
    APPROVE = "approve"
    REJECT = "reject"
    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"
    UNKNOWN = "unknown"


class AgentType(str, Enum):
    """
    Classification of the role or archetype of the agent generating the telemetry.
    """

    ORCHESTRATOR = "orchestrator"
    WORKER = "worker"
    RESEARCHER = "researcher"
    CODER = "coder"
    TESTER = "tester"
    EXECUTOR = "executor"
    REVIEWER = "reviewer"
    CRITIC = "critic"
    PLANNER = "planner"
    USER_PROXY = "user_proxy"
    CUSTOM = "custom"


# Alias AgentRole to AgentType for natural multi-agent semantics
AgentRole = AgentType


class EventEnvironment(str, Enum):
    """
    Deployment tier or runtime execution boundary of the agent.
    """

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    SANDBOX = "sandbox"
    TEST = "test"


class EventSource(str, Enum):
    """
    Subsystem or actor originating the event.
    """

    AGENT = "agent"
    TOOL = "tool"
    ENVIRONMENT = "environment"
    HUMAN = "human"
    VERIFIER = "verifier"
    SYSTEM = "system"
