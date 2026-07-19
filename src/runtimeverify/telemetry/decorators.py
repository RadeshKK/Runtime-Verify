import time
import functools
import inspect
import contextlib
from typing import Optional, Callable, Any, Generator
from runtimeverify.events.base import Event
from runtimeverify.telemetry.manager import get_global_manager
from runtimeverify.telemetry.context import get_current_context

def observe_tool(func: Optional[Callable[..., Any]] = None, *, name: Optional[str] = None):
    """
    Decorator to automatically trace synchronous or asynchronous tool execution.
    Collects arguments, return value, errors, and duration metrics.
    
    Usage:
        @observe_tool
        def my_tool(x, y):
            return x + y
            
        @observe_tool(name="custom_name")
        async def fetch_data():
            ...
    """
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = name or f.__name__

        @functools.wraps(f)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            manager = get_global_manager()
            sig = inspect.signature(f)
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            arguments = {k: v for k, v in bound.arguments.items() if k != "self" and k != "cls"}
            
            start_time = time.perf_counter()
            try:
                output = f(*args, **kwargs)
                duration = (time.perf_counter() - start_time) * 1000.0
                manager.collector.collect_tool(
                    tool_name=tool_name,
                    arguments=arguments,
                    output=output,
                    status="success",
                    duration_ms=duration,
                )
                return output
            except Exception as e:
                duration = (time.perf_counter() - start_time) * 1000.0
                manager.collector.collect_tool(
                    tool_name=tool_name,
                    arguments=arguments,
                    status="error",
                    error_message=str(e),
                    duration_ms=duration,
                )
                raise

        @functools.wraps(f)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            manager = get_global_manager()
            sig = inspect.signature(f)
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            arguments = {k: v for k, v in bound.arguments.items() if k != "self" and k != "cls"}
            
            start_time = time.perf_counter()
            try:
                output = await f(*args, **kwargs)
                duration = (time.perf_counter() - start_time) * 1000.0
                manager.collector.collect_tool(
                    tool_name=tool_name,
                    arguments=arguments,
                    output=output,
                    status="success",
                    duration_ms=duration,
                )
                return output
            except Exception as e:
                duration = (time.perf_counter() - start_time) * 1000.0
                manager.collector.collect_tool(
                    tool_name=tool_name,
                    arguments=arguments,
                    status="error",
                    error_message=str(e),
                    duration_ms=duration,
                )
                raise

        return async_wrapper if inspect.iscoroutinefunction(f) else sync_wrapper

    if func is not None:
        return decorator(func)
    return decorator


def observe_llm(func: Optional[Callable[..., Any]] = None, *, model: Optional[str] = None):
    """
    Decorator to trace language model prompts, responses, and token counts.
    Supports wrapping functions returning a string, a dictionary, or a tuple/response object.
    
    Usage:
        @observe_llm(model="gemini-1.5-pro")
        def ask_llm(prompt):
            return "response"
    """
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        llm_model = model or f.__name__

        @functools.wraps(f)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            manager = get_global_manager()
            # Extract prompt context from the first argument or keyword arguments
            prompt = args[0] if args else kwargs.get("prompt", None)
            
            start_time = time.perf_counter()
            try:
                output = f(*args, **kwargs)
                duration = (time.perf_counter() - start_time) * 1000.0
                
                # Try to extract response token counts if dictionary or rich object is returned
                prompt_tokens = None
                completion_tokens = None
                response_str = str(output)
                if isinstance(output, dict):
                    prompt_tokens = output.get("prompt_tokens")
                    completion_tokens = output.get("completion_tokens")
                    response_str = output.get("response", response_str)
                
                manager.collector.collect_llm(
                    model=llm_model,
                    prompt=prompt,
                    response=response_str,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    duration_ms=duration,
                )
                return output
            except Exception as e:
                duration = (time.perf_counter() - start_time) * 1000.0
                manager.collector.collect_llm(
                    model=llm_model,
                    prompt=prompt,
                    response=f"Error: {e}",
                    duration_ms=duration,
                )
                raise

        @functools.wraps(f)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            manager = get_global_manager()
            prompt = args[0] if args else kwargs.get("prompt", None)
            
            start_time = time.perf_counter()
            try:
                output = await f(*args, **kwargs)
                duration = (time.perf_counter() - start_time) * 1000.0
                
                prompt_tokens = None
                completion_tokens = None
                response_str = str(output)
                if isinstance(output, dict):
                    prompt_tokens = output.get("prompt_tokens")
                    completion_tokens = output.get("completion_tokens")
                    response_str = output.get("response", response_str)
                
                manager.collector.collect_llm(
                    model=llm_model,
                    prompt=prompt,
                    response=response_str,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    duration_ms=duration,
                )
                return output
            except Exception as e:
                duration = (time.perf_counter() - start_time) * 1000.0
                manager.collector.collect_llm(
                    model=llm_model,
                    prompt=prompt,
                    response=f"Error: {e}",
                    duration_ms=duration,
                )
                raise

        return async_wrapper if inspect.iscoroutinefunction(f) else sync_wrapper

    if func is not None:
        return decorator(func)
    return decorator


@contextlib.contextmanager
def span(name: str) -> Generator[None, None, None]:
    """
    Context manager to wrap an arbitrary block of code, measuring its latency 
    and publishing a generic event to the event bus.
    
    Usage:
        with telemetry.span("database_query"):
            # code here
            pass
    """
    manager = get_global_manager()
    ctx = get_current_context()
    sess_id = ctx.session_id if ctx else "unknown_session"
    agent_id = ctx.agent_id if ctx else "unknown_agent"
    
    start_time = time.perf_counter()
    try:
        yield
        duration = (time.perf_counter() - start_time) * 1000.0
        # Emit a generic event signaling successful span execution
        event = Event(
            session_id=sess_id,
            agent_id=agent_id,
            type="span",
            metadata={
                "span_name": name,
                "status": "success",
                "duration_ms": duration,
            }
        )
        manager.emitter.emit(event)
    except Exception as e:
        duration = (time.perf_counter() - start_time) * 1000.0
        event = Event(
            session_id=sess_id,
            agent_id=agent_id,
            type="span",
            metadata={
                "span_name": name,
                "status": "error",
                "error_message": str(e),
                "duration_ms": duration,
            }
        )
        manager.emitter.emit(event)
        raise
