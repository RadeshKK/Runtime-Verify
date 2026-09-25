from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field, model_validator

from runtimeverify.events.base import Event
from runtimeverify.events.canonical import (
    FilesystemDeleteEvent,
    FilesystemReadEvent,
    FilesystemWriteEvent,
    GitOperationEvent,
    NetworkRequestEvent,
    ProcessCreationEvent,
    ShellCommandEvent,
)
from runtimeverify.events.enums import EventAction, EventType
from runtimeverify.policy.models import PolicyDecision
from runtimeverify.runtime.context import ExecutionContext
from runtimeverify.semantic.models import DecisionSignal
from runtimeverify.verification.models import VerificationResult


class ActionType(str, Enum):
    """
    Standardized operational categories for intercepted agent actions.
    """

    SHELL = "shell"
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    PROCESS = "process"
    GIT = "git"
    CUSTOM = "custom"


class InterceptionMode(str, Enum):
    """
    Operating mode of the interception layer:
    - OBSERVE: Record, evaluate, and audit decisions without blocking execution.
    - ENFORCE: Actively enforce ALLOW, REVIEW, and BLOCK decisions before execution.
    """

    OBSERVE = "observe"
    ENFORCE = "enforce"


class ActionStatus(str, Enum):
    """
    Lifecycle status of an intercepted action.
    """

    PENDING = "pending"
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    REVIEW_REQUIRED = "review_required"
    EXECUTED = "executed"
    FAILED = "failed"


class Action(BaseModel):
    """
    Canonical representation of an intended autonomous agent action submitted
    to RuntimeVerify for pre-execution inspection, policy evaluation, and verification.
    """

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    action_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this action instance",
    )
    action_type: ActionType = Field(..., description="Action category (shell, filesystem, network, etc.)")
    name: str = Field(..., description="Operation verb (e.g. read, write, execute, push, connect)")
    target: str = Field(..., description="Action target (e.g. path, command string, URL, branch)")
    params: Dict[str, Any] = Field(default_factory=dict, description="Action-specific parameters")
    context: ExecutionContext = Field(..., description="Active session and execution context")
    agent_id: str = Field("", description="Agent identity identifier")
    session_id: str = Field("", description="Trace session identifier")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC creation timestamp",
    )

    @model_validator(mode="before")
    @classmethod
    def populate_context_ids(cls, data: Any) -> Any:
        if isinstance(data, dict):
            ctx = data.get("context")
            if ctx is not None:
                if not data.get("agent_id"):
                    data["agent_id"] = getattr(ctx, "agent_id", "") or (
                        ctx.get("agent_id", "") if isinstance(ctx, dict) else ""
                    )
                if not data.get("session_id"):
                    data["session_id"] = getattr(ctx, "session_id", "") or (
                        ctx.get("session_id", "") if isinstance(ctx, dict) else ""
                    )
        return data

    @classmethod
    def shell(
        cls,
        command: str,
        session_id: str,
        agent_id: str,
        working_directory: Optional[str] = None,
        context: Optional[ExecutionContext] = None,
        **extra_params: Any,
    ) -> "Action":
        """Factory for shell command execution actions."""
        ctx = context or ExecutionContext(session_id=session_id, agent_id=agent_id)
        params = {"command": command, "working_directory": working_directory, **extra_params}
        return cls(
            action_type=ActionType.SHELL,
            name="execute",
            target=command,
            params=params,
            context=ctx,
            agent_id=agent_id,
            session_id=session_id,
        )

    @classmethod
    def filesystem(
        cls,
        operation: str,
        path: str,
        session_id: str,
        agent_id: str,
        content: Optional[str] = None,
        context: Optional[ExecutionContext] = None,
        **extra_params: Any,
    ) -> "Action":
        """Factory for filesystem read, write, or delete actions."""
        ctx = context or ExecutionContext(session_id=session_id, agent_id=agent_id)
        params = {"operation": operation, "path": path, "content": content, **extra_params}
        return cls(
            action_type=ActionType.FILESYSTEM,
            name=operation.lower(),
            target=path,
            params=params,
            context=ctx,
            agent_id=agent_id,
            session_id=session_id,
        )

    @classmethod
    def network(
        cls,
        url: str,
        method: str = "GET",
        session_id: str = "default-session",
        agent_id: str = "default-agent",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Any] = None,
        context: Optional[ExecutionContext] = None,
        **extra_params: Any,
    ) -> "Action":
        """Factory for outbound network actions."""
        ctx = context or ExecutionContext(session_id=session_id, agent_id=agent_id)
        params = {"method": method.upper(), "headers": headers or {}, "body": body, **extra_params}
        return cls(
            action_type=ActionType.NETWORK,
            name=method.upper(),
            target=url,
            params=params,
            context=ctx,
            agent_id=agent_id,
            session_id=session_id,
        )

    @classmethod
    def process(
        cls,
        command_line: str,
        session_id: str,
        agent_id: str,
        executable: Optional[str] = None,
        pid: Optional[int] = None,
        context: Optional[ExecutionContext] = None,
        **extra_params: Any,
    ) -> "Action":
        """Factory for process creation actions."""
        ctx = context or ExecutionContext(session_id=session_id, agent_id=agent_id)
        exe = executable or command_line.split()[0] if command_line else "process"
        params = {"command_line": command_line, "executable": exe, "pid": pid, **extra_params}
        return cls(
            action_type=ActionType.PROCESS,
            name="spawn",
            target=command_line,
            params=params,
            context=ctx,
            agent_id=agent_id,
            session_id=session_id,
        )

    @classmethod
    def git(
        cls,
        operation: str,
        session_id: str,
        agent_id: str,
        branch: Optional[str] = None,
        commit_message: Optional[str] = None,
        context: Optional[ExecutionContext] = None,
        **extra_params: Any,
    ) -> "Action":
        """Factory for git actions."""
        ctx = context or ExecutionContext(session_id=session_id, agent_id=agent_id)
        params = {
            "operation": operation.lower(),
            "branch": branch,
            "commit_message": commit_message,
            **extra_params,
        }
        return cls(
            action_type=ActionType.GIT,
            name=operation.lower(),
            target=branch or operation,
            params=params,
            context=ctx,
            agent_id=agent_id,
            session_id=session_id,
        )

    def to_canonical_event(self) -> Event:
        """
        Translates this Action into its typed CanonicalEvent representation
        ready for policy evaluation and behavioral engine ingestion.
        """
        sid = self.session_id
        aid = self.agent_id

        if self.action_type == ActionType.SHELL:
            cmd = self.params.get("command") or self.target
            exe = cmd.split()[0] if cmd else "shell"
            return ShellCommandEvent(
                session_id=sid,
                agent_id=aid,
                command=cmd,
                target=exe,
                payload={"command": cmd, "working_directory": self.params.get("working_directory")},
            )

        elif self.action_type == ActionType.FILESYSTEM:
            op = self.name.lower()
            path = self.target
            if "delete" in op or "remove" in op or "unlink" in op:
                return FilesystemDeleteEvent(
                    session_id=sid,
                    agent_id=aid,
                    path=path,
                    target=path,
                )
            elif "write" in op or "append" in op or "modify" in op or "touch" in op:
                content = str(self.params.get("content") or "")
                return FilesystemWriteEvent(
                    session_id=sid,
                    agent_id=aid,
                    path=path,
                    target=path,
                    bytes_written=len(content.encode("utf-8")),
                )
            else:
                return FilesystemReadEvent(
                    session_id=sid,
                    agent_id=aid,
                    path=path,
                    target=path,
                )

        elif self.action_type == ActionType.NETWORK:
            return NetworkRequestEvent(
                session_id=sid,
                agent_id=aid,
                url=self.target,
                target=self.target,
                method=self.params.get("method", "GET"),
                headers=self.params.get("headers", {}),
            )

        elif self.action_type == ActionType.PROCESS:
            cmd = self.params.get("command_line") or self.target
            pid = self.params.get("pid") or 0
            return ProcessCreationEvent(
                session_id=sid,
                agent_id=aid,
                command_line=cmd,
                target=cmd,
                pid=pid,
            )

        elif self.action_type == ActionType.GIT:
            op = self.params.get("operation") or self.name
            branch = self.params.get("branch")
            return GitOperationEvent(
                session_id=sid,
                agent_id=aid,
                operation=op,
                target=branch or op,
                branch=branch,
            )

        # Fallback to generic Event
        return Event(
            session_id=sid,
            agent_id=aid,
            event_type=EventType.GENERIC,
            action=EventAction.UNKNOWN,
            target=self.target,
            metadata=self.params,
        )


class ActionResult(BaseModel):
    """
    Execution outcome returned by an ActionExecutor after running an approved action.
    """

    model_config = ConfigDict(frozen=True)

    action_id: str = Field(..., description="Action ID executed")
    success: bool = Field(..., description="Whether action execution succeeded")
    output: Optional[Any] = Field(None, description="Output payload or return value")
    error: Optional[str] = Field(None, description="Error message if execution failed")
    duration_ms: Optional[float] = Field(None, description="Execution duration in milliseconds")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Execution metrics and metadata")


class InterceptionDecision(BaseModel):
    """
    Unified evaluation decision rendered by the RuntimeActionInterceptor.
    Integrates policy rules, behavioral sequential tests, and enforcement modes.
    """

    model_config = ConfigDict(frozen=True)

    decision_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this decision",
    )
    action_id: str = Field(..., description="ID of the evaluated action")
    mode: InterceptionMode = Field(..., description="Operating mode (observe vs enforce)")
    status: str = Field(..., description="Synthesized decision: ALLOW, REVIEW, or BLOCK")
    execution_permitted: bool = Field(..., description="Whether the action is permitted to execute")
    effective_action: str = Field(
        ...,
        description="Effective resolution: EXECUTE, HOLD_FOR_REVIEW, or BLOCK",
    )
    policy_decision: Optional[PolicyDecision] = Field(
        None,
        description="Detailed deterministic policy engine decision",
    )
    behavioral_score: Optional[float] = Field(
        None,
        description="Transition probability or log-likelihood ratio from behavioral engine",
    )
    behavioral_decision: Optional[str] = Field(
        None,
        description="Behavioral detector classification (e.g. NORMAL, ANOMALY, PENDING)",
    )
    semantic_signal: Optional[DecisionSignal] = Field(
        None,
        description="Semantic decision engine evaluation signal (e.g. Laya)",
    )
    verification_result: Optional[VerificationResult] = Field(
        None,
        description="Comprehensive outcome produced by the VerificationEngine",
    )
    reason: str = Field(..., description="Human-readable decision explanation")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC decision timestamp",
    )
    audit_record: Dict[str, Any] = Field(
        default_factory=dict,
        description="Auditable metadata snapshot for compliance and forensics",
    )


class AuditLogEntry(BaseModel):
    """
    Immutable audit trail record documenting an intercepted agent action,
    its policy evaluation, behavioral verification, and execution outcome.
    """

    model_config = ConfigDict(frozen=True)

    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action: Action
    decision: InterceptionDecision
    result: Optional[ActionResult] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
