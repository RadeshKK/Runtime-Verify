"""
Unified API v1 Router for RuntimeVerify (Phase 11).
Aggregates all version 1 endpoints:
- /api/v1/health
- /api/v1/events
- /api/v1/decisions
- /api/v1/agents
- /api/v1/policies
- /api/v1/approvals
- /api/v1/audit
"""

from fastapi import APIRouter

from runtimeverify.api.v1.agents import router as agents_router
from runtimeverify.api.v1.approvals import router as approvals_router
from runtimeverify.api.v1.audit import router as audit_router
from runtimeverify.api.v1.decisions import router as decisions_router
from runtimeverify.api.v1.events import router as events_router
from runtimeverify.api.v1.health import router as health_router
from runtimeverify.api.v1.policies import router as policies_router

api_v1_router = APIRouter(prefix="/api/v1")

# Mount sub-routers
api_v1_router.include_router(health_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(decisions_router)
api_v1_router.include_router(agents_router)
api_v1_router.include_router(policies_router)
api_v1_router.include_router(approvals_router)
api_v1_router.include_router(audit_router)
