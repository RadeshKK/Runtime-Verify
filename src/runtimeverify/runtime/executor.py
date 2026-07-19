import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Any

class RuntimeExecutor:
    """
    Worker pool executor to run telemetry monitoring loops or pipeline checks 
    within isolated workers, protecting sessions from cross-interference.
    """
    
    def __init__(self, max_workers: int = 10):
        self._thread_pool = ThreadPoolExecutor(max_workers=max_workers)

    def submit(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Submits a synchronous processing task to the worker pool."""
        return self._thread_pool.submit(fn, *args, **kwargs)

    async def execute_async(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Runs a synchronous blocking function asynchronously within a thread pool worker."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._thread_pool, lambda: fn(*args, **kwargs))

    def shutdown(self, wait: bool = True) -> None:
        """Shuts down the worker execution pool."""
        self._thread_pool.shutdown(wait=wait)
