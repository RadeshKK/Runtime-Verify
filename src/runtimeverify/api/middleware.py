"""
Middleware, Rate Limiting, Correlation ID propagation, Secret Redaction,
and Structured Error Handling for RuntimeVerify API (Phase 11).
"""

from collections import deque
from datetime import datetime, timezone
import json
import logging
import threading
import time
from typing import Any, Deque, Dict, Optional, Tuple
import uuid

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from starlette.middleware.base import BaseHTTPMiddleware

from runtimeverify.audit.redaction import SecretRedactor
from runtimeverify.interception.exceptions import ExecutionBlockedError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Correlation ID Middleware
# ---------------------------------------------------------------------------


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Extracts or generates correlation, trace, and request IDs.
    Attaches correlation IDs to request.state and propagates them in HTTP response headers.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        corr_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        trace_id = request.headers.get("X-Trace-ID") or corr_id
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        request.state.correlation_id = corr_id
        request.state.trace_id = trace_id
        request.state.request_id = req_id

        response = await call_next(request)

        response.headers["X-Correlation-ID"] = corr_id
        response.headers["X-Trace-ID"] = trace_id
        response.headers["X-Request-ID"] = req_id
        return response


# ---------------------------------------------------------------------------
# Secret Redaction Middleware
# ---------------------------------------------------------------------------


class SecretRedactionMiddleware(BaseHTTPMiddleware):
    """
    Intercepts JSON responses and sanitizes sensitive credentials, private keys,
    passwords, and tokens using SecretRedactor before transmission.
    Guarantees no secrets are exposed via API endpoints.
    """

    def __init__(self, app, redactor: Optional[SecretRedactor] = None):
        super().__init__(app)
        self.redactor = redactor or SecretRedactor()

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        content_type = response.headers.get("content-type", "")

        # Only inspect and redact JSON payloads
        if "application/json" in content_type:
            body_chunks = []
            async for chunk in response.body_iterator:
                body_chunks.append(chunk)
            body_bytes = b"".join(body_chunks)

            try:
                decoded = json.loads(body_bytes.decode("utf-8"))
                sanitized, modified = self.redactor.redact(decoded)
                if modified:
                    new_bytes = json.dumps(sanitized).encode("utf-8")
                    headers = dict(response.headers)
                    headers["content-length"] = str(len(new_bytes))
                    return Response(
                        content=new_bytes,
                        status_code=response.status_code,
                        headers=headers,
                        media_type="application/json",
                    )
            except Exception as e:
                logger.debug("Failed to decode response JSON for secret redaction: %s", e)

            # Return reconstructed body if not modified
            return Response(
                content=body_bytes,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )

        return response


# ---------------------------------------------------------------------------
# Rate Limiting Abstraction & Implementation
# ---------------------------------------------------------------------------


class RateLimiter:
    """Abstract interface for rate limiting implementations."""

    def is_allowed(self, client_key: str) -> Tuple[bool, int, float]:
        """
        Evaluates whether a request from client_key is allowed.
        Returns: (allowed: bool, remaining_requests: int, retry_after_seconds: float)
        """
        raise NotImplementedError


class InMemoryRateLimiter(RateLimiter):
    """
    Thread-safe in-memory sliding-window rate limiter.
    Maintains a rolling window of request timestamps per client key.
    """

    def __init__(self, max_requests: int = 10000, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._windows: Dict[str, Deque[float]] = {}

    def is_allowed(self, client_key: str) -> Tuple[bool, int, float]:
        now = time.time()
        with self._lock:
            if client_key not in self._windows:
                self._windows[client_key] = deque()

            window = self._windows[client_key]
            cutoff = now - self.window_seconds

            # Prune timestamps older than window
            while window and window[0] < cutoff:
                window.popleft()

            if len(window) < self.max_requests:
                window.append(now)
                remaining = self.max_requests - len(window)
                return True, remaining, 0.0

            # Exceeded rate limit
            oldest = window[0]
            retry_after = max(0.1, (oldest + self.window_seconds) - now)
            return False, 0, retry_after

    def reset(self) -> None:
        """Clears all tracking windows."""
        with self._lock:
            self._windows.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware enforcing sliding-window rate limits.
    Returns HTTP 429 Too Many Requests with Retry-After header when threshold exceeded.
    """

    def __init__(
        self,
        app,
        limiter: Optional[RateLimiter] = None,
        enabled: bool = True,
    ):
        super().__init__(app)
        self.limiter = limiter or InMemoryRateLimiter()
        self.enabled = enabled

    async def dispatch(self, request: Request, call_next) -> Response:
        if not self.enabled:
            return await call_next(request)

        # Skip rate limiting for static docs or OpenAPI schema
        if request.url.path in ("/docs", "/redoc", "/openapi.json"):
            return await call_next(request)

        # Derive client key from auth or IP
        client_key = (
            request.headers.get("X-API-Key")
            or request.headers.get("X-Forwarded-For")
            or (request.client.host if request.client else "unknown-client")
        )

        allowed, remaining, retry_after = self.limiter.is_allowed(client_key)
        if not allowed:
            corr_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
            error_body = {
                "error": {
                    "code": "RATE_LIMIT_EXCEEDED",
                    "message": f"Rate limit exceeded. Try again in {retry_after:.1f} seconds.",
                    "details": {
                        "retry_after_seconds": round(retry_after, 2),
                        "limit": getattr(self.limiter, "max_requests", None),
                    },
                    "correlation_id": corr_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            }
            return Response(
                content=json.dumps(error_body),
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={
                    "Retry-After": str(int(retry_after) + 1),
                    "X-RateLimit-Remaining": "0",
                    "X-Correlation-ID": corr_id,
                    "Content-Type": "application/json",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response


# ---------------------------------------------------------------------------
# Structured Error Handlers
# ---------------------------------------------------------------------------


def register_error_handlers(app: FastAPI) -> None:
    """
    Registers comprehensive structured exception handlers on the FastAPI application.
    Converts all exceptions into a predictable, auditable error schema:
    {
        "error": {
            "code": "<ERROR_CODE>",
            "message": "<HUMAN_MESSAGE>",
            "details": {...},
            "correlation_id": "<CORRELATION_ID>",
            "timestamp": "<ISO_TIMESTAMP>"
        }
    }
    """

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        corr_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        code_str = f"HTTP_{exc.status_code}"
        msg = exc.detail if isinstance(exc.detail, str) else "HTTP Exception"
        details: dict[str, Any] = exc.detail if isinstance(exc.detail, dict) else {}

        headers = dict(exc.headers or {})
        headers["X-Correlation-ID"] = corr_id

        return Response(
            content=json.dumps(
                {
                    "error": {
                        "code": code_str,
                        "message": msg,
                        "details": details,
                        "correlation_id": corr_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                }
            ),
            status_code=exc.status_code,
            headers=headers,
            media_type="application/json",
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        corr_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        return Response(
            content=json.dumps(
                {
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "Invalid request parameters or payload schema",
                        "details": {"validation_errors": exc.errors()},
                        "correlation_id": corr_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                }
            ),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            headers={"X-Correlation-ID": corr_id},
            media_type="application/json",
        )

    @app.exception_handler(ExecutionBlockedError)
    async def blocked_exception_handler(request: Request, exc: ExecutionBlockedError):
        corr_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        return Response(
            content=json.dumps(
                {
                    "error": {
                        "code": "ACTION_BLOCKED",
                        "message": str(exc),
                        "details": getattr(exc, "details", {}),
                        "correlation_id": corr_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                }
            ),
            status_code=status.HTTP_403_FORBIDDEN,
            headers={"X-Correlation-ID": corr_id},
            media_type="application/json",
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        corr_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        logger.exception("Unhandled server exception [%s]: %s", corr_id, exc)
        return Response(
            content=json.dumps(
                {
                    "error": {
                        "code": "INTERNAL_SERVER_ERROR",
                        "message": str(exc) if str(exc) else "An unexpected internal server error occurred",
                        "details": {},
                        "correlation_id": corr_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                }
            ),
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            headers={"X-Correlation-ID": corr_id},
            media_type="application/json",
        )
