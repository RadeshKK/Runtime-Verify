import time
import inspect
import functools
from typing import Callable, Any, Optional
from runtimeverify.events import Event
from runtimeverify.telemetry.context import TelemetryContext, active_context
from runtimeverify.telemetry.manager import get_global_manager


class TelemetryMiddleware:
    """
    Middleware runner class that wraps an agent's execution loop or primary run method.
    Establishes the active thread/task TelemetryContext and automatically fires
    agent lifecycle start, finish, and error events to the event bus.
    """

    def __init__(self, session_id: str, agent_id: str, correlation_id: Optional[str] = None):
        self.session_id = session_id
        self.agent_id = agent_id
        self.correlation_id = correlation_id

    def __call__(self, run_func: Callable[..., Any]) -> Callable[..., Any]:
        """Wraps the target run function with telemetry context propagation and start/end events."""

        @functools.wraps(run_func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            manager = get_global_manager()
            ctx = TelemetryContext(
                session_id=self.session_id, agent_id=self.agent_id, correlation_id=self.correlation_id
            )

            with active_context(ctx):
                # Emit agent execution start event
                start_time = time.perf_counter()
                manager.emitter.emit(
                    Event(
                        session_id=self.session_id,
                        agent_id=self.agent_id,
                        type="agent_start",
                        metadata={"timestamp": start_time},
                    )
                )

                try:
                    result = run_func(*args, **kwargs)
                    duration = (time.perf_counter() - start_time) * 1000.0

                    # Emit agent execution complete event
                    manager.emitter.emit(
                        Event(
                            session_id=self.session_id,
                            agent_id=self.agent_id,
                            type="agent_end",
                            metadata={"duration_ms": duration, "status": "success"},
                        )
                    )
                    return result
                except Exception as e:
                    duration = (time.perf_counter() - start_time) * 1000.0
                    # Emit error event
                    manager.emitter.emit(
                        Event(
                            session_id=self.session_id,
                            agent_id=self.agent_id,
                            type="agent_error",
                            metadata={
                                "duration_ms": duration,
                                "status": "error",
                                "error_message": str(e),
                                "error_class": e.__class__.__name__,
                            },
                        )
                    )
                    raise

        @functools.wraps(run_func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            manager = get_global_manager()
            ctx = TelemetryContext(
                session_id=self.session_id, agent_id=self.agent_id, correlation_id=self.correlation_id
            )

            with active_context(ctx):
                start_time = time.perf_counter()
                manager.emitter.emit(
                    Event(
                        session_id=self.session_id,
                        agent_id=self.agent_id,
                        type="agent_start",
                        metadata={"timestamp": start_time},
                    )
                )

                try:
                    result = await run_func(*args, **kwargs)
                    duration = (time.perf_counter() - start_time) * 1000.0

                    manager.emitter.emit(
                        Event(
                            session_id=self.session_id,
                            agent_id=self.agent_id,
                            type="agent_end",
                            metadata={"duration_ms": duration, "status": "success"},
                        )
                    )
                    return result
                except Exception as e:
                    duration = (time.perf_counter() - start_time) * 1000.0
                    manager.emitter.emit(
                        Event(
                            session_id=self.session_id,
                            agent_id=self.agent_id,
                            type="agent_error",
                            metadata={
                                "duration_ms": duration,
                                "status": "error",
                                "error_message": str(e),
                                "error_class": e.__class__.__name__,
                            },
                        )
                    )
                    raise

        return async_wrapper if inspect.iscoroutinefunction(run_func) else sync_wrapper
