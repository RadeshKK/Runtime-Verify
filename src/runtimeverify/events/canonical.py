from typing import Optional, Dict, Any, List, Union
from pydantic import Field, ConfigDict, model_validator
from runtimeverify.events.base import Event
from runtimeverify.events.enums import (
    EventType,
    EventAction,
    EventSource,
)
from runtimeverify.events.context import EventContext


class CanonicalEvent(Event):
    """
    Vendor-neutral Canonical Runtime Event Model for autonomous AI agents.

    Standardized top-level attributes:
      - schema_version: "1.0"
      - event_id / id: Unique UUID4 string
      - timestamp: UTC localized datetime
      - session_id: Mandatory session/trace identifier
      - trace_id: Distributed correlation trace identifier
      - span_id: Span identifier
      - parent_event_id: Causal parent event identifier
      - agent_id: Emitting agent identifier
      - agent_type: Archetype of the agent
      - event_type / type: Canonical event type (EventType enum or string)
      - action: Canonical action verb (EventAction enum or string)
      - target: Target entity or resource
      - source: Event originator (EventSource enum or string)
      - environment: Execution tier (EventEnvironment enum or string)
      - context: Structured EventContext (host, process, directory, tags)
      - metadata: Extensible key-value metadata
      - payload: Domain-specific typed payload attributes
    """

    model_config = ConfigDict(
        frozen=True,
        populate_by_name=True,
        extra="allow",
    )

    action: str = Field(default=EventAction.UNKNOWN.value, description="Action verb describing the operation")
    target: Optional[str] = Field(default=None, description="Target resource or entity")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Domain-specific payload attributes")

    # --- Factory Methods for Canonical Event Construction ---

    @classmethod
    def create_llm_request(
        cls,
        session_id: str,
        agent_id: str,
        model: str,
        prompt: Union[str, List[Dict[str, Any]]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        tools_provided: Optional[List[str]] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "LLMRequestEvent":
        payload = {
            "model": model,
            "prompt": prompt,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "tools_provided": tools_provided or [],
            **extra_payload,
        }
        return LLMRequestEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=model,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_llm_response(
        cls,
        session_id: str,
        agent_id: str,
        model: str,
        response: Optional[str] = None,
        prompt_tokens: Optional[int] = None,
        completion_tokens: Optional[int] = None,
        total_tokens: Optional[int] = None,
        finish_reason: Optional[str] = None,
        duration_ms: Optional[float] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "LLMResponseEvent":
        tot_tokens = total_tokens
        if tot_tokens is None and prompt_tokens is not None and completion_tokens is not None:
            tot_tokens = prompt_tokens + completion_tokens
        payload = {
            "model": model,
            "response": response,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": tot_tokens,
            "finish_reason": finish_reason,
            "duration_ms": duration_ms,
            **extra_payload,
        }
        return LLMResponseEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=model,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_tool_call(
        cls,
        session_id: str,
        agent_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        call_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "ToolCallEvent":
        payload = {
            "tool_name": tool_name,
            "arguments": arguments,
            "call_id": call_id,
            **extra_payload,
        }
        return ToolCallEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=tool_name,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_tool_result(
        cls,
        session_id: str,
        agent_id: str,
        tool_name: str,
        output: Optional[Any] = None,
        status: str = "success",
        error_message: Optional[str] = None,
        duration_ms: Optional[float] = None,
        call_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "ToolResultEvent":
        payload = {
            "tool_name": tool_name,
            "output": output,
            "status": status,
            "error_message": error_message,
            "duration_ms": duration_ms,
            "call_id": call_id,
            **extra_payload,
        }
        return ToolResultEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=tool_name,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_filesystem_read(
        cls,
        session_id: str,
        agent_id: str,
        path: str,
        bytes_read: Optional[int] = None,
        status: str = "success",
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "FilesystemReadEvent":
        payload = {
            "path": path,
            "bytes_read": bytes_read,
            "status": status,
            **extra_payload,
        }
        return FilesystemReadEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=path,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_filesystem_write(
        cls,
        session_id: str,
        agent_id: str,
        path: str,
        bytes_written: Optional[int] = None,
        content_hash: Optional[str] = None,
        status: str = "success",
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "FilesystemWriteEvent":
        payload = {
            "path": path,
            "bytes_written": bytes_written,
            "content_hash": content_hash,
            "status": status,
            **extra_payload,
        }
        return FilesystemWriteEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=path,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_filesystem_delete(
        cls,
        session_id: str,
        agent_id: str,
        path: str,
        status: str = "success",
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "FilesystemDeleteEvent":
        payload = {
            "path": path,
            "status": status,
            **extra_payload,
        }
        return FilesystemDeleteEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=path,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_shell_command(
        cls,
        session_id: str,
        agent_id: str,
        command: str,
        arguments: Optional[List[str]] = None,
        working_directory: Optional[str] = None,
        exit_code: Optional[int] = None,
        output: Optional[str] = None,
        duration_ms: Optional[float] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "ShellCommandEvent":
        executable = command.split()[0] if command else "shell"
        payload = {
            "command": command,
            "arguments": arguments or [],
            "working_directory": working_directory,
            "exit_code": exit_code,
            "output": output,
            "duration_ms": duration_ms,
            **extra_payload,
        }
        return ShellCommandEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=executable,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_network_request(
        cls,
        session_id: str,
        agent_id: str,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        status_code: Optional[int] = None,
        bytes_sent: Optional[int] = None,
        bytes_received: Optional[int] = None,
        duration_ms: Optional[float] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "NetworkRequestEvent":
        payload = {
            "url": url,
            "method": method.upper(),
            "headers": headers,
            "status_code": status_code,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration_ms": duration_ms,
            **extra_payload,
        }
        return NetworkRequestEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=url,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_git_operation(
        cls,
        session_id: str,
        agent_id: str,
        operation: str,
        repository: Optional[str] = None,
        branch: Optional[str] = None,
        commit_hash: Optional[str] = None,
        message: Optional[str] = None,
        files_changed: Optional[List[str]] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "GitOperationEvent":
        target = repository or branch or operation
        payload = {
            "operation": operation,
            "repository": repository,
            "branch": branch,
            "commit_hash": commit_hash,
            "message": message,
            "files_changed": files_changed or [],
            **extra_payload,
        }
        return GitOperationEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=target,
            action=operation,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_credential_access(
        cls,
        session_id: str,
        agent_id: str,
        resource_name: str,
        secret_type: str = "api_key",
        access_mode: str = "read",
        sanitized: bool = True,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "CredentialAccessEvent":
        payload = {
            "resource_name": resource_name,
            "secret_type": secret_type,
            "access_mode": access_mode,
            "sanitized": sanitized,
            **extra_payload,
        }
        return CredentialAccessEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=resource_name,
            action=EventAction.ACCESS.value,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_process_creation(
        cls,
        session_id: str,
        agent_id: str,
        command: str,
        pid: Optional[int] = None,
        parent_pid: Optional[int] = None,
        environment_variables: Optional[List[str]] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "ProcessCreationEvent":
        executable = command.split()[0] if command else "process"
        payload = {
            "command": command,
            "pid": pid,
            "parent_pid": parent_pid,
            "environment_variables": environment_variables or [],
            **extra_payload,
        }
        return ProcessCreationEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=executable,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_agent_communication(
        cls,
        session_id: str,
        agent_id: str,
        recipient_agent_id: str,
        message_type: str = "task_handoff",
        content_summary: Optional[str] = None,
        action: str = EventAction.SEND.value,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        agent_role: Optional[str] = None,
        target_agent_role: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "AgentCommunicationEvent":
        payload = {
            "recipient_agent_id": recipient_agent_id,
            "sender_agent_id": agent_id,
            "message_type": message_type,
            "content_summary": content_summary,
            **extra_payload,
        }
        return AgentCommunicationEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=recipient_agent_id,
            action=action,
            parent_agent=agent_id,
            target_agent=recipient_agent_id,
            agent_role=agent_role or agent_type,
            target_agent_role=target_agent_role,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type or agent_role,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_agent_delegation(
        cls,
        session_id: str,
        agent_id: str,
        delegate_agent_id: str,
        subtask: str,
        delegation_depth: int = 1,
        constraints: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        agent_role: Optional[str] = None,
        target_agent_role: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "AgentDelegationEvent":
        payload = {
            "delegate_agent_id": delegate_agent_id,
            "subtask": subtask,
            "delegation_depth": delegation_depth,
            "constraints": constraints or {},
            **extra_payload,
        }
        return AgentDelegationEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=delegate_agent_id,
            action=EventAction.DELEGATE.value,
            parent_agent=agent_id,
            target_agent=delegate_agent_id,
            agent_role=agent_role or agent_type,
            target_agent_role=target_agent_role,
            delegation_depth=delegation_depth,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type or agent_role,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_agent_handoff(
        cls,
        session_id: str,
        agent_id: str,
        target_agent_id: str,
        handoff_type: str = "sequential",
        transferred_state: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        agent_role: Optional[str] = None,
        target_agent_role: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "AgentHandoffEvent":
        payload = {
            "target_agent_id": target_agent_id,
            "handoff_type": handoff_type,
            "transferred_state": transferred_state or {},
            **extra_payload,
        }
        return AgentHandoffEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=target_agent_id,
            action=EventAction.HANDOFF.value,
            parent_agent=agent_id,
            target_agent=target_agent_id,
            agent_role=agent_role or agent_type,
            target_agent_role=target_agent_role,
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type or agent_role,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_human_approval(
        cls,
        session_id: str,
        agent_id: str,
        ticket_id: str,
        decision: str,
        approver_id: Optional[str] = None,
        reason: Optional[str] = None,
        action_requested: Optional[str] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "HumanApprovalEvent":
        payload = {
            "ticket_id": ticket_id,
            "decision": decision,
            "approver_id": approver_id,
            "reason": reason,
            "action_requested": action_requested,
            **extra_payload,
        }
        return HumanApprovalEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=ticket_id,
            action=decision.lower(),
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            source=EventSource.HUMAN.value,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )

    @classmethod
    def create_policy_decision(
        cls,
        session_id: str,
        agent_id: str,
        policy_name: str,
        decision: str,
        deviation_score: Optional[float] = None,
        triggered_rules: Optional[List[str]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        context: Optional[Union[EventContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_payload: Any,
    ) -> "PolicyDecisionEvent":
        payload = {
            "policy_name": policy_name,
            "decision": decision,
            "deviation_score": deviation_score,
            "triggered_rules": triggered_rules or [],
            "evidence": evidence or {},
            **extra_payload,
        }
        return PolicyDecisionEvent(
            session_id=session_id,
            agent_id=agent_id,
            target=policy_name,
            action=decision.lower(),
            trace_id=trace_id,
            span_id=span_id,
            parent_event_id=parent_event_id,
            agent_type=agent_type,
            source=EventSource.VERIFIER.value,
            context=context or EventContext(),
            metadata=metadata or {},
            payload=payload,
        )


# --- 15 Specialized Canonical Event Subclasses ---


class LLMRequestEvent(CanonicalEvent):
    type: str = Field(default=EventType.LLM_REQUEST.value, alias="event_type")
    action: str = Field(default=EventAction.REQUEST.value)

    @model_validator(mode="before")
    @classmethod
    def sync_llm_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "model" in data and "target" not in data:
                data["target"] = data["model"]
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("model", "prompt", "temperature", "max_tokens", "tools_provided"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def model_name(self) -> str:
        return self.target or self.payload.get("model", "")

    @property
    def prompt(self) -> Any:
        return self.payload.get("prompt")


class LLMResponseEvent(CanonicalEvent):
    type: str = Field(default=EventType.LLM_RESPONSE.value, alias="event_type")
    action: str = Field(default=EventAction.RESPONSE.value)

    @model_validator(mode="before")
    @classmethod
    def sync_llm_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "model" in data and "target" not in data:
                data["target"] = data["model"]
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in (
                    "model",
                    "response",
                    "prompt_tokens",
                    "completion_tokens",
                    "total_tokens",
                    "finish_reason",
                    "duration_ms",
                ):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def model_name(self) -> str:
        return self.target or self.payload.get("model", "")

    @property
    def response(self) -> Optional[str]:
        return self.payload.get("response")

    @property
    def total_tokens(self) -> Optional[int]:
        return self.payload.get("total_tokens")


class ToolCallEvent(CanonicalEvent):
    type: str = Field(default=EventType.TOOL_CALL.value, alias="event_type")
    action: str = Field(default=EventAction.CALL.value)

    @model_validator(mode="before")
    @classmethod
    def sync_tool_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "tool_name" in data and "target" not in data:
                data["target"] = data["tool_name"]
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("tool_name", "arguments", "call_id"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def tool_name(self) -> str:
        return self.target or self.payload.get("tool_name", "")

    @property
    def arguments(self) -> Dict[str, Any]:
        return self.payload.get("arguments", {})


class ToolResultEvent(CanonicalEvent):
    type: str = Field(default=EventType.TOOL_RESULT.value, alias="event_type")
    action: str = Field(default=EventAction.RESULT.value)

    @model_validator(mode="before")
    @classmethod
    def sync_tool_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "tool_name" in data and "target" not in data:
                data["target"] = data["tool_name"]
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("tool_name", "output", "status", "error_message", "duration_ms", "call_id"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def tool_name(self) -> str:
        return self.target or self.payload.get("tool_name", "")

    @property
    def output(self) -> Any:
        return self.payload.get("output")

    @property
    def status(self) -> str:
        return self.payload.get("status", "success")


class FilesystemReadEvent(CanonicalEvent):
    type: str = Field(default=EventType.FILESYSTEM_READ.value, alias="event_type")
    action: str = Field(default=EventAction.READ.value)

    @model_validator(mode="before")
    @classmethod
    def sync_fs_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "path" in data and "target" not in data:
                data["target"] = data["path"]
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("path", "bytes_read", "status"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def path(self) -> str:
        return self.target or self.payload.get("path", "")


class FilesystemWriteEvent(CanonicalEvent):
    type: str = Field(default=EventType.FILESYSTEM_WRITE.value, alias="event_type")
    action: str = Field(default=EventAction.WRITE.value)

    @model_validator(mode="before")
    @classmethod
    def sync_fs_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "path" in data and "target" not in data:
                data["target"] = data["path"]
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("path", "bytes_written", "content_hash", "status"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def path(self) -> str:
        return self.target or self.payload.get("path", "")

    @property
    def content_hash(self) -> Optional[str]:
        return self.payload.get("content_hash")


class FilesystemDeleteEvent(CanonicalEvent):
    type: str = Field(default=EventType.FILESYSTEM_DELETE.value, alias="event_type")
    action: str = Field(default=EventAction.DELETE.value)

    @model_validator(mode="before")
    @classmethod
    def sync_fs_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "path" in data and "target" not in data:
                data["target"] = data["path"]
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("path", "status"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def path(self) -> str:
        return self.target or self.payload.get("path", "")


class ShellCommandEvent(CanonicalEvent):
    type: str = Field(default=EventType.SHELL_COMMAND.value, alias="event_type")
    action: str = Field(default=EventAction.EXECUTE.value)

    @model_validator(mode="before")
    @classmethod
    def sync_shell_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "command" in data and "target" not in data:
                cmd = data["command"]
                data["target"] = cmd.split()[0] if cmd else "shell"
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("command", "arguments", "working_directory", "exit_code", "output", "duration_ms"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def command(self) -> str:
        return self.payload.get("command", "")

    @property
    def exit_code(self) -> Optional[int]:
        return self.payload.get("exit_code")


class NetworkRequestEvent(CanonicalEvent):
    type: str = Field(default=EventType.NETWORK_REQUEST.value, alias="event_type")
    action: str = Field(default=EventAction.REQUEST.value)

    @model_validator(mode="before")
    @classmethod
    def sync_network_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "url" in data and "target" not in data:
                data["target"] = data["url"]
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("url", "method", "headers", "status_code", "bytes_sent", "bytes_received", "duration_ms"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def url(self) -> str:
        return self.target or self.payload.get("url", "")

    @property
    def method(self) -> str:
        return self.payload.get("method", "GET")

    @property
    def status_code(self) -> Optional[int]:
        return self.payload.get("status_code")


class GitOperationEvent(CanonicalEvent):
    type: str = Field(default=EventType.GIT_OPERATION.value, alias="event_type")
    action: str = Field(default="commit")

    @model_validator(mode="before")
    @classmethod
    def sync_git_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "repository" in data and "target" not in data:
                data["target"] = data["repository"]
            if "operation" in data and "action" not in data:
                data["action"] = data["operation"]
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("operation", "repository", "branch", "commit_hash", "message", "files_changed"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def operation(self) -> str:
        return self.payload.get("operation", self.action)

    @property
    def repository(self) -> Optional[str]:
        return self.payload.get("repository")

    @property
    def commit_hash(self) -> Optional[str]:
        return self.payload.get("commit_hash")


class CredentialAccessEvent(CanonicalEvent):
    type: str = Field(default=EventType.CREDENTIAL_ACCESS.value, alias="event_type")
    action: str = Field(default=EventAction.ACCESS.value)

    @model_validator(mode="before")
    @classmethod
    def sync_credential_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "resource_name" in data and "target" not in data:
                data["target"] = data["resource_name"]
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("resource_name", "secret_type", "access_mode", "sanitized"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def resource_name(self) -> str:
        return self.target or self.payload.get("resource_name", "")

    @property
    def secret_type(self) -> str:
        return self.payload.get("secret_type", "api_key")


class ProcessCreationEvent(CanonicalEvent):
    type: str = Field(default=EventType.PROCESS_CREATION.value, alias="event_type")
    action: str = Field(default=EventAction.SPAWN.value)

    @model_validator(mode="before")
    @classmethod
    def sync_process_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "command" in data and "target" not in data:
                cmd = data["command"]
                data["target"] = cmd.split()[0] if cmd else "process"
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("command", "pid", "parent_pid", "environment_variables"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def command(self) -> str:
        return self.payload.get("command", "")

    @property
    def pid(self) -> Optional[int]:
        return self.payload.get("pid")


class AgentCommunicationEvent(CanonicalEvent):
    type: str = Field(default=EventType.AGENT_COMMUNICATION.value, alias="event_type")
    action: str = Field(default=EventAction.SEND.value)

    @model_validator(mode="before")
    @classmethod
    def sync_comm_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "recipient_agent_id" in data and "target" not in data:
                data["target"] = data["recipient_agent_id"]
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("recipient_agent_id", "sender_agent_id", "message_type", "content_summary"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def recipient_agent_id(self) -> str:
        return self.target or self.payload.get("recipient_agent_id", "")

    @property
    def message_type(self) -> str:
        return self.payload.get("message_type", "message")


class AgentDelegationEvent(CanonicalEvent):
    type: str = Field(default=EventType.AGENT_DELEGATION.value, alias="event_type")
    action: str = Field(default=EventAction.DELEGATE.value)

    @model_validator(mode="before")
    @classmethod
    def sync_delegation_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "delegate_agent_id" in data and "target" not in data:
                data["target"] = data["delegate_agent_id"]
            if "target_agent" in data and "target" not in data:
                data["target"] = data["target_agent"]
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("delegate_agent_id", "subtask", "delegation_depth", "constraints"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def delegate_agent_id(self) -> str:
        return self.target or self.payload.get("delegate_agent_id", "")

    @property
    def subtask(self) -> str:
        return self.payload.get("subtask", "")


class AgentHandoffEvent(CanonicalEvent):
    type: str = Field(default=EventType.AGENT_HANDOFF.value, alias="event_type")
    action: str = Field(default=EventAction.HANDOFF.value)

    @model_validator(mode="before")
    @classmethod
    def sync_handoff_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "target_agent_id" in data and "target" not in data:
                data["target"] = data["target_agent_id"]
            if "target_agent" in data and "target" not in data:
                data["target"] = data["target_agent"]
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("target_agent_id", "handoff_type", "transferred_state"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def target_agent_id(self) -> str:
        return self.target or self.payload.get("target_agent_id", "")

    @property
    def handoff_type(self) -> str:
        return self.payload.get("handoff_type", "sequential")


class HumanApprovalEvent(CanonicalEvent):
    type: str = Field(default=EventType.HUMAN_APPROVAL.value, alias="event_type")
    action: str = Field(default=EventAction.APPROVE.value)
    source: str = Field(default=EventSource.HUMAN.value)

    @model_validator(mode="before")
    @classmethod
    def sync_approval_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "ticket_id" in data and "target" not in data:
                data["target"] = data["ticket_id"]
            if "decision" in data and "action" not in data:
                data["action"] = data["decision"].lower()
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("ticket_id", "decision", "approver_id", "reason", "action_requested"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def ticket_id(self) -> str:
        return self.target or self.payload.get("ticket_id", "")

    @property
    def decision(self) -> str:
        return self.payload.get("decision", self.action)

    @property
    def approver_id(self) -> Optional[str]:
        return self.payload.get("approver_id")


class PolicyDecisionEvent(CanonicalEvent):
    type: str = Field(default=EventType.POLICY_DECISION.value, alias="event_type")
    action: str = Field(default=EventAction.ALLOW.value)
    source: str = Field(default=EventSource.VERIFIER.value)

    @model_validator(mode="before")
    @classmethod
    def sync_policy_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "policy_name" in data and "target" not in data:
                data["target"] = data["policy_name"]
            if "decision" in data and "action" not in data:
                data["action"] = data["decision"].lower()
            payload = data.get("payload", {})
            if isinstance(payload, dict):
                for k in ("policy_name", "decision", "deviation_score", "triggered_rules", "evidence"):
                    if k in data and k not in payload:
                        payload[k] = data[k]
                data["payload"] = payload
        return data

    @property
    def policy_name(self) -> str:
        return self.target or self.payload.get("policy_name", "")

    @property
    def decision(self) -> str:
        return self.payload.get("decision", self.action.upper())

    @property
    def deviation_score(self) -> Optional[float]:
        return self.payload.get("deviation_score")
