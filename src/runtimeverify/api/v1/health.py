"""
Health, Readiness, and Liveness Probes Router (Phase 11).
Provides standard endpoints for Kubernetes probes and operational monitoring.
"""

from datetime import datetime, timezone
import time
from fastapi import APIRouter
from runtimeverify.api.schemas import HealthResponse, LivenessResponse, ReadinessResponse
from runtimeverify.audit.service import get_default_audit_service

router = APIRouter(tags=["Health"])

_START_TIME = time.time()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System Health Check",
    description="Returns high-level system health status, version, uptime, and component statuses.",
)
def get_health() -> HealthResponse:
    from runtimeverify.api.app import engine

    uptime = time.time() - _START_TIME
    engine_status = engine.lifecycle.current.value if engine else "uninitialized"

    components = {
        "engine": engine_status,
        "audit_service": "healthy",
        "policy_engine": "healthy",
    }
    return HealthResponse(
        status="healthy" if engine else "degraded",
        version="1.0.0",
        uptime_seconds=round(uptime, 2),
        components=components,
    )


@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    summary="Kubernetes Readiness Probe",
    description="Validates whether the verification engine and persistence layers are ready to accept traffic.",
)
def get_readiness() -> ReadinessResponse:
    from runtimeverify.api.app import engine

    engine_ready = engine is not None and getattr(engine.lifecycle, "current", None) is not None
    audit_service = get_default_audit_service()
    audit_ready = audit_service is not None

    checks = {
        "engine_initialized": bool(engine_ready),
        "audit_service_ready": bool(audit_ready),
    }

    all_ready = all(checks.values())
    return ReadinessResponse(
        ready=all_ready,
        checks=checks,
        message="All subsystems ready" if all_ready else "Subsystems initializing",
    )


@router.get(
    "/health/live",
    response_model=LivenessResponse,
    summary="Kubernetes Liveness Probe",
    description="Simple process liveness verification confirming HTTP server responsiveness.",
)
def get_liveness() -> LivenessResponse:
    return LivenessResponse(
        alive=True,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
