"""
AgentSession implementation for RuntimeVerify SDK (Phase 9).
Provides scoped session lifecycle management, correlation ID propagation,
and pre-execution gating for tool invocations.
"""

from datetime import datetime, timezone
import functools
import inspect
import json
import logging
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple, Union
import uuid

from runtimeverify.events.canonical import CanonicalEvent
from runtimeverify.events.enums import EventAction, EventType
from runtimeverify.interception.exceptions import (
    ExecutionBlockedError,
    ExecutionReviewRequiredError,
)
from runtimeverify.interception.models import (
    Action,
    ActionResult,
    ActionType,
    InterceptionDecision,
)
from runtimeverify.runtime.context import ExecutionContext

if TYPE_CHECKING:
    from runtimeverify.audit.models import AuditRecord
    from runtimeverify.sdk.client import RuntimeVerifyClient

logger = logging.getLogger(__name__)


class AgentSession:
    """
    Scoped agent session preserving correlation IDs (agent_id, session_id, trace_id, environment).
    Supports Python context manager semantics:
        with runtimeverify.session(agent_id="coding-agent") as session:
            result = session.execute(tool_call)
    """

    def __init__(
        self,
        client: "RuntimeVerifyClient",
        agent_id: str = "default-agent",
        session_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        environment: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.client = client
        self.agent_id = agent_id
        self.session_id = session_id or f"sess-{uuid.uuid4().hex[:12]}"
        self.trace_id = trace_id or f"tr-{uuid.uuid4().hex[:16]}"
        self.environment = environment or getattr(client, "environment", None) or "development"
        self.metadata = metadata or {}
        self.is_active = True
        self.created_at = datetime.now(timezone.utc)
        self.history: List[ActionResult] = []

    def __enter__(self) -> "AgentSession":
        """Enters session context, recording a session start audit event."""
        if not self.is_active:
            self.is_active = True
        if self.client.audit_service:
            self.client.audit_service.log_event(
                summary=f"Agent session '{self.session_id}' started for agent '{self.agent_id}'",
                agent_id=self.agent_id,
                session_id=self.session_id,
                trace_id=self.trace_id,
                environment=self.environment,
                details={"metadata": self.metadata},
            )
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exits session context, recording error if unhandled exception occurred, then closing."""
        if exc_type is not None:
            # Check if this was a legitimate security block
            if issubclass(exc_type, (ExecutionBlockedError, ExecutionReviewRequiredError)):
                logger.debug(
                    "Session '%s' intercepted blocked/reviewed action: %s",
                    self.session_id,
                    exc_val,
                )
            else:
                if self.client.audit_service:
                    self.client.audit_service.log_error(
                        error_type=exc_type.__name__,
                        error_message=str(exc_val),
                        agent_id=self.agent_id,
                        session_id=self.session_id,
                        trace_id=self.trace_id,
                        environment=self.environment,
                    )
        self.close()

    def create_context(self, extra_metadata: Optional[Dict[str, Any]] = None) -> ExecutionContext:
        """Creates an ExecutionContext stamped with this session's correlation IDs."""
        meta = dict(self.metadata)
        if extra_metadata:
            meta.update(extra_metadata)
        return ExecutionContext(
            session_id=self.session_id,
            agent_id=self.agent_id,
            trace_id=self.trace_id,
            environment=self.environment,
            metadata=meta,
        )

    def map_to_action(self, tool_call: Any, **kwargs: Any) -> Action:
        """
        Translates diverse tool invocation representations into a typed canonical Action.
        Accepts:
        - Action instance (adds session correlation if missing)
        - Python callable / function
        - Dict with 'name'/'arguments' or 'tool'/'input' or 'command'/'path'
        - Object with name/arguments attributes (e.g. OpenAI / LangChain tool calls)
        """
        # Case 1: Already an Action
        if isinstance(tool_call, Action):
            if not tool_call.session_id or not tool_call.agent_id:
                ctx = self.create_context(tool_call.params)
                return Action(
                    action_id=tool_call.action_id,
                    action_type=tool_call.action_type,
                    name=tool_call.name,
                    target=tool_call.target,
                    params=tool_call.params,
                    context=ctx,
                    agent_id=self.agent_id,
                    session_id=self.session_id,
                )
            return tool_call

        ctx = self.create_context(kwargs)

        # Case 2: Python Callable
        if callable(tool_call):
            func_name = getattr(tool_call, "__name__", "custom_tool")
            return self._infer_action_from_name_and_args(func_name, kwargs, ctx)

        # Case 3: Dictionary
        if isinstance(tool_call, dict):
            # Check for OpenAI-style tool call: {"type": "function", "function": {"name": ..., "arguments": ...}}
            if "function" in tool_call and isinstance(tool_call["function"], dict):
                fn = tool_call["function"]
                name = fn.get("name", "custom_tool")
                raw_args = fn.get("arguments", {})
                args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                args.update(kwargs)
                return self._infer_action_from_name_and_args(name, args, ctx)

            # Check for direct {"name": ..., "arguments": ...}
            if "name" in tool_call:
                name = tool_call["name"]
                raw_args = tool_call.get("arguments", tool_call.get("params", {}))
                args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                args.update(kwargs)
                return self._infer_action_from_name_and_args(name, args, ctx)

            # Check for LangChain-style {"tool": ..., "input": ...}
            if "tool" in tool_call:
                name = tool_call["tool"]
                raw_input = tool_call.get("input", {})
                args = (
                    json.loads(raw_input)
                    if isinstance(raw_input, str) and raw_input.strip().startswith("{")
                    else ({"input": raw_input} if not isinstance(raw_input, dict) else raw_input)
                )
                args.update(kwargs)
                return self._infer_action_from_name_and_args(name, args, ctx)

            # Check for shell command dict: {"command": "ls -la"}
            if "command" in tool_call or "cmd" in tool_call:
                cmd = str(tool_call.get("command") or tool_call.get("cmd"))
                args = dict(tool_call)
                args.update(kwargs)
                args.pop("command", None)
                args.pop("cmd", None)
                return Action.shell(
                    command=cmd,
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                    context=ctx,
                    **args,
                )

            # Check for filesystem path dict: {"path": "/etc/hosts", "operation": "read"}
            if "path" in tool_call:
                path = str(tool_call["path"])
                op = str(tool_call.get("operation", "read"))
                args = dict(tool_call)
                args.update(kwargs)
                args.pop("path", None)
                args.pop("operation", None)
                content = args.pop("content", None)
                return Action.filesystem(
                    operation=op,
                    path=path,
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                    content=content,
                    context=ctx,
                    **args,
                )

            # Generic dict
            return self._infer_action_from_name_and_args(
                tool_call.get("action", "custom_tool"),
                tool_call,
                ctx,
            )

        # Case 4: Object (e.g. LangChain ToolCall, OpenAI ChatCompletionMessageToolCall)
        if hasattr(tool_call, "function"):
            fn = getattr(tool_call, "function")
            name = getattr(fn, "name", "tool")
            raw_args = getattr(fn, "arguments", {})
            args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
            args.update(kwargs)
            return self._infer_action_from_name_and_args(name, args, ctx)

        if hasattr(tool_call, "name"):
            name = getattr(tool_call, "name")
            raw_args = getattr(tool_call, "args", getattr(tool_call, "arguments", {}))
            args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
            args.update(kwargs)
            return self._infer_action_from_name_and_args(name, args, ctx)

        # Fallback: treat string as shell command or generic target
        target_str = str(tool_call)
        extra = dict(kwargs)
        extra.pop("command", None)
        return Action.shell(
            command=target_str,
            session_id=self.session_id,
            agent_id=self.agent_id,
            context=ctx,
            **extra,
        )

    def _infer_action_from_name_and_args(
        self,
        name: str,
        args: Dict[str, Any],
        ctx: ExecutionContext,
    ) -> Action:
        """Infers the appropriate Action subclass/type from tool name and arguments."""
        name_lower = name.lower()

        # 1. Shell commands
        if any(term in name_lower for term in ["shell", "bash", "terminal", "exec", "command", "cmd", "run_bash"]):
            cmd = str(args.get("command") or args.get("cmd") or args.get("input") or "")
            if not cmd and args:
                # First string argument
                for v in args.values():
                    if isinstance(v, str):
                        cmd = v
                        break
            extra = dict(args)
            extra.pop("command", None)
            extra.pop("cmd", None)
            extra.pop("input", None)
            return Action.shell(
                command=cmd or name,
                session_id=self.session_id,
                agent_id=self.agent_id,
                context=ctx,
                **extra,
            )

        # 2. Filesystem
        if any(term in name_lower for term in ["file", "read", "write", "delete", "fs", "cat", "directory"]):
            path = str(args.get("path") or args.get("file_path") or args.get("filename") or args.get("target") or "")
            if not path and args:
                for k, v in args.items():
                    if "path" in k.lower() or "file" in k.lower():
                        path = str(v)
                        break

            op = "read"
            if any(w in name_lower for w in ["write", "create", "append", "save"]):
                op = "write"
            elif any(d in name_lower for d in ["delete", "remove", "unlink", "rm"]):
                op = "delete"

            extra = dict(args)
            extra.pop("operation", None)
            extra.pop("path", None)
            extra.pop("file_path", None)
            extra.pop("filename", None)
            extra.pop("target", None)
            content = extra.pop("content", None)

            return Action.filesystem(
                operation=op,
                path=path or name,
                session_id=self.session_id,
                agent_id=self.agent_id,
                content=content,
                context=ctx,
                **extra,
            )

        # 3. Network
        if any(term in name_lower for term in ["http", "request", "fetch", "curl", "url", "api_call", "web"]):
            url = str(args.get("url") or args.get("endpoint") or args.get("host") or "")
            method = str(args.get("method", "GET"))
            extra = dict(args)
            extra.pop("url", None)
            extra.pop("endpoint", None)
            extra.pop("host", None)
            extra.pop("method", None)
            return Action.network(
                url=url or name,
                method=method,
                session_id=self.session_id,
                agent_id=self.agent_id,
                context=ctx,
                **extra,
            )

        # 4. Git
        if "git" in name_lower:
            op = str(args.get("operation") or name_lower.replace("git_", "").replace("git-", "") or "status")
            extra = dict(args)
            extra.pop("operation", None)
            branch = extra.pop("branch", None)
            remote = extra.pop("remote", None)
            return Action.git(
                operation=op,
                session_id=self.session_id,
                agent_id=self.agent_id,
                branch=branch,
                remote=remote,
                context=ctx,
                **extra,
            )

        # 5. Process
        if any(term in name_lower for term in ["process", "spawn", "subprocess", "daemon"]):
            cmd = str(args.get("command_line") or args.get("command") or name)
            extra = dict(args)
            extra.pop("command_line", None)
            extra.pop("command", None)
            return Action.process(
                command_line=cmd,
                session_id=self.session_id,
                agent_id=self.agent_id,
                context=ctx,
                **extra,
            )

        # Fallback to ActionType.CUSTOM
        return Action(
            action_type=ActionType.CUSTOM,
            name=name,
            target=str(args.get("target") or args.get("name") or name),
            params=args,
            context=ctx,
            agent_id=self.agent_id,
            session_id=self.session_id,
        )

    def check(self, tool_call: Any, **kwargs: Any) -> InterceptionDecision:
        """
        Dry-run inspection of an intended tool call or action.
        Evaluates policies and verification models without executing.
        """
        action = self.map_to_action(tool_call, **kwargs)
        return self.client.check(action)

    def observe(
        self,
        tool_call: Any,
        execute_fn: Optional[Callable[[Action], Any]] = None,
        **kwargs: Any,
    ) -> Tuple[InterceptionDecision, Optional[ActionResult]]:
        """
        Observes a tool call in observe mode.
        Evaluates and logs audit events without blocking execution.
        """
        action = self.map_to_action(tool_call, **kwargs)
        return self.client.observe(action, execute_fn=execute_fn)

    def authorize(
        self,
        tool_call: Any,
        execute_fn: Optional[Callable[[Action], Any]] = None,
        **kwargs: Any,
    ) -> ActionResult:
        """
        Enforces policy and verification decisions for a tool call.
        If allowed, executes and returns ActionResult.
        If blocked, raises ExecutionBlockedError.
        If review required and unapproved, raises ExecutionReviewRequiredError.
        """
        action = self.map_to_action(tool_call, **kwargs)
        result = self.client.authorize(action, execute_fn=execute_fn)
        self.history.append(result)
        return result

    def execute(
        self,
        tool_call: Any,
        execute_fn: Optional[Callable[..., Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """
        High-level wrapper to verify, enforce, and execute a tool invocation.
        Example:
            with runtimeverify.session(agent_id="coding-agent") as session:
                result = session.execute(read_file, path="README.md")
        """
        action = self.map_to_action(tool_call, **kwargs)

        # Determine target execution callable
        fn_to_run = execute_fn
        if fn_to_run is None:
            if callable(tool_call):

                def fn_to_run(act: Action) -> Any:
                    return tool_call(**kwargs)
            elif isinstance(tool_call, dict) and callable(tool_call.get("func")):
                callable_func = tool_call["func"]

                def fn_to_run(act: Action) -> Any:
                    return callable_func(**kwargs)

        # Authorize and execute through interceptor
        action_result = self.authorize(action, execute_fn=fn_to_run)

        # If a direct callable was executed, return its underlying output
        if fn_to_run is not None:
            return action_result.output
        return action_result

    def wrap_tool(
        self,
        func: Optional[Callable[..., Any]] = None,
        *,
        action_type: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> Callable[..., Any]:
        """
        Decorator for wrapping arbitrary Python tool functions with runtime verification.
        Example:
            @session.wrap_tool
            def bash(command: str) -> str:
                return subprocess.check_output(command, shell=True).decode()
        """

        def decorator(target_fn: Callable[..., Any]) -> Callable[..., Any]:
            effective_name = tool_name or getattr(target_fn, "__name__", "tool")

            @functools.wraps(target_fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Bind function signature to arguments dict
                try:
                    sig = inspect.signature(target_fn)
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    call_kwargs = dict(bound.arguments)
                except Exception:
                    call_kwargs = dict(kwargs)
                    if args:
                        call_kwargs["args"] = args

                if action_type:
                    call_kwargs["_action_type"] = action_type

                def run_wrapped(act: Action) -> Any:
                    return target_fn(*args, **kwargs)

                return self.execute(
                    tool_call={"name": effective_name, "arguments": call_kwargs},
                    execute_fn=run_wrapped,
                    **call_kwargs,
                )

            return wrapper

        if func is not None:
            return decorator(func)
        return decorator

    def create_event(
        self,
        event_type: Union[EventType, str],
        action: Union[EventAction, str] = EventAction.UNKNOWN,
        target: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> CanonicalEvent:
        """Helper to construct a CanonicalEvent bound to this session's correlation IDs."""
        return CanonicalEvent(
            session_id=self.session_id,
            agent_id=self.agent_id,
            trace_id=self.trace_id,
            environment=self.environment,
            event_type=event_type,
            action=action,
            target=target,
            payload=payload or {},
            **kwargs,
        )

    def record(self, event: Union[CanonicalEvent, Dict[str, Any]]) -> "AuditRecord":
        """Records a canonical telemetry event or audit record linked to this session."""
        if isinstance(event, dict):
            return self.client.audit_service.log_event(
                summary=event.get("summary", "Custom event"),
                agent_id=self.agent_id,
                session_id=self.session_id,
                trace_id=self.trace_id,
                environment=self.environment,
                details=event,
            )
        # Canonical event
        return self.client.record(event)

    def close(self) -> None:
        """Marks the session as closed and logs session termination."""
        if not self.is_active:
            return
        self.is_active = False
        if self.client.audit_service:
            self.client.audit_service.log_event(
                summary=f"Agent session '{self.session_id}' closed. Total actions: {len(self.history)}",
                agent_id=self.agent_id,
                session_id=self.session_id,
                trace_id=self.trace_id,
                environment=self.environment,
                details={
                    "total_actions": len(self.history),
                    "created_at": self.created_at.isoformat(),
                    "closed_at": datetime.now(timezone.utc).isoformat(),
                },
            )
