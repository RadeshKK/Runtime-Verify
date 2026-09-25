"""
RuntimeVerify Python SDK (Phase 9).
Provides in-process runtime verification, agent session management,
and pre-execution gating for autonomous AI agent architectures.
"""

from pathlib import Path
import threading
from typing import Any, Callable, Dict, Optional, Tuple, Union

from runtimeverify.audit import AuditRecord
from runtimeverify.events.canonical import CanonicalEvent
from runtimeverify.interception.models import (
    Action,
    ActionResult,
    InterceptionDecision,
    InterceptionMode,
)
from runtimeverify.sdk.client import RuntimeVerifyClient
from runtimeverify.sdk.session import AgentSession

_default_client: Optional[RuntimeVerifyClient] = None
_client_lock = threading.Lock()


def get_default_client() -> RuntimeVerifyClient:
    """Returns the shared global RuntimeVerifyClient, initializing with defaults if needed."""
    global _default_client
    with _client_lock:
        if _default_client is None:
            _default_client = RuntimeVerifyClient()
        return _default_client


def set_default_client(client: RuntimeVerifyClient) -> None:
    """Sets the shared global RuntimeVerifyClient."""
    global _default_client
    with _client_lock:
        _default_client = client


def init_client(
    mode: Union[InterceptionMode, str] = InterceptionMode.ENFORCE,
    policy_path: Optional[Union[str, Path]] = None,
    audit_log_path: Optional[str] = ".runtimeverify/audit.log",
    in_memory_audit: bool = False,
    **kwargs: Any,
) -> RuntimeVerifyClient:
    """Initializes and registers the default global RuntimeVerifyClient."""
    client = RuntimeVerifyClient(
        mode=mode,
        policy_path=policy_path,
        audit_log_path=audit_log_path,
        in_memory_audit=in_memory_audit,
        **kwargs,
    )
    set_default_client(client)
    return client


def session(
    agent_id: str = "default-agent",
    session_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    environment: Optional[str] = None,
    mode: Union[InterceptionMode, str] = InterceptionMode.ENFORCE,
    policy_path: Optional[Union[str, Path]] = None,
    audit_log_path: Optional[str] = None,
    in_memory_audit: bool = False,
    client: Optional[RuntimeVerifyClient] = None,
    metadata: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> AgentSession:
    """
    Creates a scoped AgentSession. Can be used directly as a context manager:
        with runtimeverify.session(agent_id="coding-agent") as session:
            result = session.execute(tool_call)
    """
    if client is not None:
        target_client = client
    elif policy_path or audit_log_path or in_memory_audit or kwargs:
        # Custom parameters supplied: instantiate dedicated client
        target_client = RuntimeVerifyClient(
            mode=mode,
            policy_path=policy_path,
            audit_log_path=audit_log_path or ".runtimeverify/audit.log",
            in_memory_audit=in_memory_audit,
            **kwargs,
        )
    else:
        target_client = get_default_client()

    return target_client.session(
        agent_id=agent_id,
        session_id=session_id,
        trace_id=trace_id,
        environment=environment,
        metadata=metadata,
    )


def check(action: Action) -> InterceptionDecision:
    """Dry-run inspection using the default client."""
    return get_default_client().check(action)


def observe(
    action: Action,
    execute_fn: Optional[Callable[[Action], Any]] = None,
) -> Tuple[InterceptionDecision, Optional[ActionResult]]:
    """Observes an action using the default client without blocking."""
    return get_default_client().observe(action, execute_fn=execute_fn)


def authorize(
    action: Action,
    execute_fn: Optional[Callable[[Action], Any]] = None,
) -> ActionResult:
    """Authorizes and enforces policy verification using the default client."""
    return get_default_client().authorize(action, execute_fn=execute_fn)


def record(event: CanonicalEvent) -> AuditRecord:
    """Records a canonical event using the default client."""
    return get_default_client().record(event)


def close() -> None:
    """Closes the default client and active sessions."""
    global _default_client
    with _client_lock:
        if _default_client is not None:
            _default_client.close()
            _default_client = None


__all__ = [
    "AgentSession",
    "RuntimeVerifyClient",
    "authorize",
    "check",
    "close",
    "get_default_client",
    "init_client",
    "observe",
    "record",
    "session",
    "set_default_client",
]
