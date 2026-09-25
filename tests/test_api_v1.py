"""
Comprehensive Unit and Integration Test Suite for Phase 11: RuntimeVerify Enterprise API.
Verifies OpenAPI docs, health/readiness, correlation ID propagation, secret redaction,
rate limiting, authentication & authorization abstractions, and /api/v1 endpoints:
- /api/v1/events
- /api/v1/decisions
- /api/v1/agents
- /api/v1/policies
- /api/v1/approvals
- /api/v1/audit
- /api/v1/health
"""

import base64
from datetime import datetime, timedelta, timezone
import json
import time
from typing import Any, Dict
import pytest
from fastapi.testclient import TestClient

from runtimeverify.api import (
    AnonymousAuthProvider,
    ApiKeyAuthProvider,
    InMemoryRateLimiter,
    OIDCAuthProvider,
    Role,
    app,
    set_auth_provider,
)
from runtimeverify.approvals import (
    ApprovalRequest,
    ApprovalStore,
    set_default_approval_store,
)
from runtimeverify.audit import get_default_audit_service


@pytest.fixture(autouse=True)
def reset_api_state():
    """Resets global auth provider and default stores before each test."""
    set_auth_provider(AnonymousAuthProvider(allow_all=True))
    yield
    set_auth_provider(AnonymousAuthProvider(allow_all=True))


@pytest.fixture
def client():
    return TestClient(app)


# ============================================================================
# 1. OpenAPI & Documentation Tests
# ============================================================================


def test_openapi_documentation(client: TestClient):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()

    assert schema["info"]["title"] == "RuntimeVerify Enterprise API"
    assert schema["info"]["version"] == "1.0.0"

    paths = schema["paths"]
    assert "/api/v1/health" in paths
    assert "/api/v1/health/ready" in paths
    assert "/api/v1/health/live" in paths
    assert "/api/v1/events" in paths
    assert "/api/v1/decisions" in paths
    assert "/api/v1/decisions/evaluate" in paths
    assert "/api/v1/agents" in paths
    assert "/api/v1/policies" in paths
    assert "/api/v1/approvals" in paths
    assert "/api/v1/audit" in paths

    docs_resp = client.get("/docs")
    assert docs_resp.status_code == 200


# ============================================================================
# 2. Health & Readiness Probes Tests
# ============================================================================


def test_health_endpoints(client: TestClient):
    # GET /api/v1/health
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"
    assert data["uptime_seconds"] >= 0
    assert "engine" in data["components"]

    # GET /api/v1/health/ready
    ready_resp = client.get("/api/v1/health/ready")
    assert ready_resp.status_code == 200
    ready_data = ready_resp.json()
    assert ready_data["ready"] is True
    assert ready_data["checks"]["engine_initialized"] is True
    assert ready_data["checks"]["audit_service_ready"] is True

    # GET /api/v1/health/live
    live_resp = client.get("/api/v1/health/live")
    assert live_resp.status_code == 200
    assert live_resp.json()["alive"] is True


# ============================================================================
# 3. Correlation ID & Tracing Headers Tests
# ============================================================================


def test_correlation_id_propagation(client: TestClient):
    # Without incoming headers -> generates UUIDs
    resp1 = client.get("/api/v1/health")
    assert resp1.status_code == 200
    assert "X-Correlation-ID" in resp1.headers
    assert "X-Trace-ID" in resp1.headers
    assert "X-Request-ID" in resp1.headers

    # With custom incoming headers -> preserves them
    custom_headers = {
        "X-Correlation-ID": "test-corr-uuid-1234",
        "X-Trace-ID": "test-trace-uuid-5678",
        "X-Request-ID": "test-req-uuid-9999",
    }
    resp2 = client.get("/api/v1/health", headers=custom_headers)
    assert resp2.status_code == 200
    assert resp2.headers["X-Correlation-ID"] == "test-corr-uuid-1234"
    assert resp2.headers["X-Trace-ID"] == "test-trace-uuid-5678"
    assert resp2.headers["X-Request-ID"] == "test-req-uuid-9999"


# ============================================================================
# 4. Events API Tests
# ============================================================================


def test_events_lifecycle(client: TestClient):
    # Ingest tool event
    payload = {
        "id": "ev-test-tool-1",
        "session_id": "sess-events-test",
        "agent_id": "agent-unit-tester",
        "type": "tool",
        "target": "read_source_code",
        "status": "success",
        "payload": {"resource": "read_source_code"},
    }
    resp = client.post("/api/v1/events", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "ingested"
    assert body["event_id"] == "ev-test-tool-1"
    assert "decision" in body

    # List events with pagination and filter
    list_resp = client.get(
        "/api/v1/events",
        params={"agent_id": "agent-unit-tester", "page": 1, "page_size": 10},
    )
    assert list_resp.status_code == 200
    data = list_resp.json()
    assert data["total"] >= 1
    assert data["page"] == 1
    assert any(ev["id"] == "ev-test-tool-1" for ev in data["items"])

    # Get single event
    get_resp = client.get("/api/v1/events/ev-test-tool-1")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == "ev-test-tool-1"
    assert get_resp.json()["agent_id"] == "agent-unit-tester"

    # Non-existent event -> 404
    missing_resp = client.get("/api/v1/events/non_existent_event_999")
    assert missing_resp.status_code == 404
    assert missing_resp.json()["error"]["code"] == "HTTP_404"


# ============================================================================
# 5. Decisions API Tests
# ============================================================================


def test_decisions_evaluate_and_list(client: TestClient):
    # Dry-run evaluation of safe action
    safe_eval = {
        "action_type": "shell",
        "target": "git status",
        "agent_id": "coding-agent",
        "session_id": "sess-dec-1",
        "params": {"command": "git status"},
        "dry_run": True,
    }
    resp_safe = client.post("/api/v1/decisions/evaluate", json=safe_eval)
    assert resp_safe.status_code == 200
    data_safe = resp_safe.json()
    assert data_safe["decision"] == "ALLOW"
    assert data_safe["risk_level"] in ("LOW", "UNKNOWN")
    assert data_safe["verification_id"] is not None

    # Dry-run evaluation of blocked action
    blocked_eval = {
        "action_type": "shell",
        "target": "rm -rf /",
        "agent_id": "coding-agent",
        "session_id": "sess-dec-2",
        "params": {"command": "rm -rf /"},
        "dry_run": True,
    }
    resp_blocked = client.post("/api/v1/decisions/evaluate", json=blocked_eval)
    assert resp_blocked.status_code == 200
    data_blocked = resp_blocked.json()
    assert data_blocked["decision"] == "BLOCK"
    assert data_blocked["risk_level"] == "CRITICAL"

    # List decisions
    list_resp = client.get("/api/v1/decisions", params={"page": 1, "page_size": 20})
    assert list_resp.status_code == 200
    assert "items" in list_resp.json()


# ============================================================================
# 6. Agents API Tests
# ============================================================================


def test_agents_fleet_and_session(client: TestClient):
    # Seed an event for agent-delta
    client.post(
        "/api/v1/events",
        json={
            "id": "ev-agent-delta-1",
            "session_id": "sess-agent-delta",
            "agent_id": "agent-delta",
            "type": "filesystem",
            "target": "/workspace/main.py",
            "status": "success",
        },
    )

    # List agents
    resp_list = client.get("/api/v1/agents")
    assert resp_list.status_code == 200
    data = resp_list.json()
    assert any(a["agent_id"] == "agent-delta" for a in data["items"])

    # Get single agent profile
    resp_agent = client.get("/api/v1/agents/agent-delta")
    assert resp_agent.status_code == 200
    assert resp_agent.json()["agent_id"] == "agent-delta"
    assert resp_agent.json()["total_events"] >= 1

    # Get agent session detail
    resp_sess = client.get("/api/v1/agents/agent-delta/sessions/sess-agent-delta")
    assert resp_sess.status_code == 200
    sess_data = resp_sess.json()
    assert sess_data["agent_id"] == "agent-delta"
    assert sess_data["session_id"] == "sess-agent-delta"
    assert len(sess_data["events"]) >= 1

    # 404 for unknown agent
    resp_missing = client.get("/api/v1/agents/unknown-agent-xyz")
    assert resp_missing.status_code == 404


# ============================================================================
# 7. Policies API Tests
# ============================================================================


def test_policies_endpoints(client: TestClient):
    # List active policies
    resp_list = client.get("/api/v1/policies")
    assert resp_list.status_code == 200
    rules = resp_list.json()["items"]
    assert len(rules) > 0
    rule_ids = [r["id"] for r in rules]
    assert "block-rm-rf" in rule_ids or "deny-aws-credentials" in rule_ids

    # Get policy by ID
    sample_id = rule_ids[0]
    resp_get = client.get(f"/api/v1/policies/{sample_id}")
    assert resp_get.status_code == 200
    assert resp_get.json()["id"] == sample_id

    # 404 for missing policy
    resp_missing = client.get("/api/v1/policies/non-existent-policy-999")
    assert resp_missing.status_code == 404

    # Validate valid YAML policy
    valid_yaml = """
version: "1.0"
policies:
  - id: custom-test-rule
    description: Block test path
    decision: BLOCK
    severity: HIGH
    match:
      event_type: FILE_READ
      path:
        glob: "/etc/shadow"
"""
    val_resp = client.post("/api/v1/policies/validate", json={"content": valid_yaml, "format": "yaml"})
    assert val_resp.status_code == 200
    val_data = val_resp.json()
    assert val_data["valid"] is True
    assert val_data["policy_count"] == 1
    assert val_data["policies"][0]["id"] == "custom-test-rule"

    # Validate invalid policy
    invalid_content = "some-invalid: yaml: [syntax error"
    val_err = client.post("/api/v1/policies/validate", json={"content": invalid_content, "format": "yaml"})
    assert val_err.status_code == 200
    assert val_err.json()["valid"] is False

    # Test policy dry run match
    test_match = {
        "policy_content": valid_yaml,
        "event_type": "FILE_READ",
        "action": "READ",
        "target": "/etc/shadow",
    }
    match_resp = client.post("/api/v1/policies/test", json=test_match)
    assert match_resp.status_code == 200
    assert match_resp.json()["matched"] is True
    assert match_resp.json()["decision"] == "BLOCK"


# ============================================================================
# 8. Approvals API Tests
# ============================================================================


def test_approvals_endpoints(client: TestClient, tmp_path):
    store = ApprovalStore(persistence_path=str(tmp_path / "approvals_v1.json"))
    set_default_approval_store(store)
    sample_req = ApprovalRequest(
        request_id="req-api-v1-test",
        event_id="ev-appr-1",
        agent_id="test-agent",
        action={"action_type": "shell", "command": "git push --force"},
        risk="HIGH",
        reason="Force push requires human authorization",
        expiration=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    store.save_request(sample_req)

    # List approvals (array format)
    resp_arr = client.get("/api/v1/approvals")
    assert resp_arr.status_code == 200
    assert isinstance(resp_arr.json(), list)
    assert any(r["request_id"] == "req-api-v1-test" for r in resp_arr.json())

    # List approvals (paginated format)
    resp_pag = client.get("/api/v1/approvals", params={"page": 1, "page_size": 10})
    assert resp_pag.status_code == 200
    assert "items" in resp_pag.json()

    # Get single approval
    resp_single = client.get("/api/v1/approvals/req-api-v1-test")
    assert resp_single.status_code == 200
    assert resp_single.json()["status"] == "PENDING"

    # Approve request
    resp_appr = client.post(
        "/api/v1/approvals/req-api-v1-test/approve",
        json={"user": "sec-lead", "reason": "Authorized for hotfix"},
    )
    assert resp_appr.status_code == 200
    assert resp_appr.json()["status"] == "APPROVED"

    # Replay attempt -> 409 Conflict
    resp_dup = client.post(
        "/api/v1/approvals/req-api-v1-test/approve",
        json={"user": "sec-lead", "reason": "Re-approving"},
    )
    assert resp_dup.status_code == 409

    # Check audit log
    resp_audit = client.get("/api/v1/approvals/req-api-v1-test/audit")
    assert resp_audit.status_code == 200
    assert len(resp_audit.json()) >= 2


# ============================================================================
# 9. Audit API Tests
# ============================================================================


def test_audit_endpoints(client: TestClient):
    audit_service = get_default_audit_service()
    rec = audit_service.log_event(
        summary="Audit test event emission",
        agent_id="audit-agent-1",
        session_id="sess-audit-1",
        trace_id="tr-audit-100",
        details={"status": "executed"},
    )

    # List audit records with pagination & filtering
    resp_list = client.get(
        "/api/v1/audit",
        params={"agent_id": "audit-agent-1", "page": 1, "page_size": 10},
    )
    assert resp_list.status_code == 200
    data = resp_list.json()
    assert data["total"] >= 1
    assert any(r["record_id"] == rec.record_id for r in data["items"])

    # Get single audit record
    resp_get = client.get(f"/api/v1/audit/{rec.record_id}")
    assert resp_get.status_code == 200
    assert resp_get.json()["record_id"] == rec.record_id

    # 404 for missing audit record
    resp_miss = client.get("/api/v1/audit/ffffffff-ffff-ffff-ffff-ffffffffffff")
    assert resp_miss.status_code == 404

    # Prune audit records
    resp_prune = client.post(
        "/api/v1/audit/prune",
        json={"max_records": 1000},
    )
    assert resp_prune.status_code == 200
    assert "pruned_records" in resp_prune.json()


# ============================================================================
# 10. Authentication & Authorization Abstraction Tests
# ============================================================================


def test_api_key_auth_provider(client: TestClient):
    key_provider = ApiKeyAuthProvider()
    key_provider.register_key(
        api_key="valid-secret-key-12345",
        user_id="operator-alice",
        roles=[Role.OPERATOR.value],
    )
    set_auth_provider(key_provider)

    # 1. Unauthenticated request without key -> 401
    resp_no_key = client.get("/api/v1/policies")
    assert resp_no_key.status_code == 401
    assert "Missing API Key" in resp_no_key.json()["error"]["message"]

    # 2. Invalid API key -> 401
    resp_bad_key = client.get("/api/v1/policies", headers={"X-API-Key": "wrong-key"})
    assert resp_bad_key.status_code == 401
    assert "Invalid API Key" in resp_bad_key.json()["error"]["message"]

    # 3. Valid API key -> 200
    resp_valid = client.get("/api/v1/policies", headers={"X-API-Key": "valid-secret-key-12345"})
    assert resp_valid.status_code == 200


def test_oidc_auth_provider_keycloak(client: TestClient):
    # Configure OIDC provider with audience and issuer checks
    oidc = OIDCAuthProvider(
        issuer="https://keycloak.company.org/realms/production",
        audience="runtimeverify-api",
    )
    set_auth_provider(oidc)

    def make_jwt(payload: Dict[str, Any]) -> str:
        h = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        return f"{h}.{p}.fake_sig"

    # Valid Keycloak admin token
    valid_claims = {
        "sub": "user-uuid-101",
        "preferred_username": "bob-security",
        "iss": "https://keycloak.company.org/realms/production",
        "aud": "runtimeverify-api",
        "exp": time.time() + 3600,
        "realm_access": {"roles": ["admin"]},
    }
    jwt_token = make_jwt(valid_claims)
    resp = client.get("/api/v1/policies", headers={"Authorization": f"Bearer {jwt_token}"})
    assert resp.status_code == 200

    # Expired token -> 401
    expired_claims = dict(valid_claims)
    expired_claims["exp"] = time.time() - 100
    resp_exp = client.get("/api/v1/policies", headers={"Authorization": f"Bearer {make_jwt(expired_claims)}"})
    assert resp_exp.status_code == 401
    assert "expired" in resp_exp.json()["error"]["message"].lower()

    # Issuer mismatch -> 401
    bad_iss_claims = dict(valid_claims)
    bad_iss_claims["iss"] = "https://untrusted-issuer.org"
    resp_iss = client.get("/api/v1/policies", headers={"Authorization": f"Bearer {make_jwt(bad_iss_claims)}"})
    assert resp_iss.status_code == 401
    assert "issuer mismatch" in resp_iss.json()["error"]["message"].lower()


def test_rbac_permission_enforcement(client: TestClient):
    # Register an agent key that only has EVENTS_WRITE and DECISIONS_EVALUATE
    key_provider = ApiKeyAuthProvider()
    key_provider.register_key(
        api_key="agent-restricted-key",
        user_id="bot-99",
        roles=[Role.AGENT.value],
    )
    set_auth_provider(key_provider)

    headers = {"X-API-Key": "agent-restricted-key"}

    # Allowed: evaluate decision
    resp_eval = client.post(
        "/api/v1/decisions/evaluate",
        headers=headers,
        json={"action_type": "shell", "target": "ls"},
    )
    assert resp_eval.status_code == 200

    # Forbidden: attempt to prune audit logs (requires AUDIT_ADMIN) -> 403
    resp_forbid = client.post(
        "/api/v1/audit/prune",
        headers=headers,
        json={"max_records": 10},
    )
    assert resp_forbid.status_code == 403
    assert "Forbidden" in resp_forbid.json()["error"]["message"]


# ============================================================================
# 11. Secret Redaction on API Responses
# ============================================================================


def test_api_response_secret_redaction(client: TestClient):
    # Ingest event containing sensitive OpenAI API key in payload
    payload = {
        "id": "ev-secret-leak-test",
        "session_id": "sess-leak-test",
        "agent_id": "test-agent",
        "type": "llm",
        "target": "gpt-4",
        "status": "success",
        "payload": {
            "prompt": "Here is my OpenAI key sk-proj-1234567890123456789012345678901234567890",
            "password": "plain-text-db-password",
        },
    }
    resp = client.post("/api/v1/events", json=payload)
    assert resp.status_code == 201

    # Query event back via API
    get_resp = client.get("/api/v1/events/ev-secret-leak-test")
    assert get_resp.status_code == 200
    raw_text = get_resp.text

    # Verify credentials never leak in raw HTTP response text
    assert "sk-proj-1234567890" not in raw_text
    assert "[REDACTED_OPENAI_KEY]" in raw_text
    assert "plain-text-db-password" not in raw_text
    assert "[REDACTED]" in raw_text


# ============================================================================
# 12. Rate Limiting Tests
# ============================================================================


def test_rate_limiter_exceeded(client: TestClient):
    limiter = InMemoryRateLimiter(max_requests=3, window_seconds=10.0)
    assert limiter.is_allowed("test-client")[0] is True
    assert limiter.is_allowed("test-client")[0] is True
    assert limiter.is_allowed("test-client")[0] is True
    # 4th request must be rejected
    allowed, remaining, retry_after = limiter.is_allowed("test-client")
    assert allowed is False
    assert remaining == 0
    assert retry_after > 0


# ============================================================================
# 13. Structured Error Response Envelope
# ============================================================================


def test_structured_error_responses(client: TestClient):
    # 404 Error
    resp_404 = client.get("/api/v1/events/missing-id-000")
    assert resp_404.status_code == 404
    body_404 = resp_404.json()
    assert "error" in body_404
    assert body_404["error"]["code"] == "HTTP_404"
    assert "correlation_id" in body_404["error"]
    assert "timestamp" in body_404["error"]

    # 422 Unprocessable Entity (Schema Validation Error)
    resp_422 = client.post("/api/v1/events", json={"invalid": "payload"})
    assert resp_422.status_code == 422
    body_422 = resp_422.json()
    assert body_422["error"]["code"] == "VALIDATION_ERROR"
    assert "validation_errors" in body_422["error"]["details"]
