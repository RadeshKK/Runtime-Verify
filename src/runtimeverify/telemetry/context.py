import contextlib
import uuid
from contextvars import ContextVar
from typing import Optional, Dict, Any, Generator
from pydantic import BaseModel, Field


class TelemetryContext(BaseModel):
    """
    Data model representing the active telemetry trace context.
    Propagated dynamically across concurrent tasks and execution threads.
    """

    session_id: str = Field(..., description="Unique identifier for the session/run")
    agent_id: str = Field(..., description="Unique identifier for the agent context")
    trace_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Trace identifier for execution grouping"
    )
    parent_event_id: Optional[str] = Field(default=None, description="Identifier of the calling/parent event")
    correlation_id: Optional[str] = Field(
        default=None, description="Correlation identifier for external messaging systems"
    )
    extra: Dict[str, Any] = Field(default_factory=dict, description="Additional context parameters")


# Module-level ContextVar to hold active telemetry context
_ACTIVE_CONTEXT: ContextVar[Optional[TelemetryContext]] = ContextVar("active_context", default=None)


@contextlib.contextmanager
def active_context(context: TelemetryContext) -> Generator[TelemetryContext, None, None]:
    """
    Context manager to bind a TelemetryContext to the current execution thread/task.

    Example:
        ctx = TelemetryContext(session_id="s1", agent_id="a1")
        with active_context(ctx):
            # context is active here
            pass
    """
    token = _ACTIVE_CONTEXT.set(context)
    try:
        yield context
    finally:
        _ACTIVE_CONTEXT.reset(token)


def get_current_context() -> Optional[TelemetryContext]:
    """
    Retrieves the currently active TelemetryContext.
    Returns None if no context is active.
    """
    return _ACTIVE_CONTEXT.get()
