"""
Unit & Integration Tests for Phase 12: Runtime Security Dashboard.
Validates static asset serving, single-page application structure,
status distinctions, evidence rendering, and API integration.
"""

from fastapi.testclient import TestClient
import pytest

from runtimeverify.api.app import app, decisions_cache
from runtimeverify.approvals import get_default_approval_store


@pytest.fixture
def client():
    return TestClient(app)


def test_dashboard_static_serving(client: TestClient):
    """Asserts that GET / serves the dashboard HTML with HTTP 200."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "<!DOCTYPE html>" in response.text
    assert "RuntimeVerify" in response.text


def test_dashboard_views_architecture(client: TestClient):
    """Asserts that all 7 required core operational views are present in the DOM."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    # View 1: Overview
    assert 'id="view-overview"' in html
    assert 'id="metric-active-agents"' in html
    assert 'id="metric-total-events"' in html
    assert 'id="metric-allowed"' in html
    assert 'id="metric-review"' in html
    assert 'id="metric-blocked"' in html
    assert 'id="metric-anomaly-rate"' in html

    # View 2: Agents view
    assert 'id="view-agents"' in html
    assert 'id="agents-table-body"' in html

    # View 3: Event timeline
    assert 'id="view-events"' in html
    assert 'id="events-table-body"' in html

    # View 4: Decision details
    assert 'id="view-decisions"' in html
    assert 'id="decisions-table-body"' in html
    assert 'id="detail-drawer"' in html

    # View 5: Approval queue
    assert 'id="view-approvals"' in html
    assert 'id="approvals-table-body"' in html

    # View 6: Policy management
    assert 'id="view-policies"' in html
    assert 'id="policies-table-body"' in html
    assert 'id="policy-yaml-input"' in html

    # View 7: Audit log
    assert 'id="view-audit"' in html
    assert 'id="audit-table-body"' in html


def test_dashboard_security_disclaimer(client: TestClient):
    """
    Asserts that the UI does NOT claim absolute security and provides
    clear, realistic defense-in-depth risk mitigation statements.
    """
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    assert "Continuous risk mitigation" in html
    assert "does not claim absolute" in html or "does not guarantee absolute" in html


def test_dashboard_status_distinctions(client: TestClient):
    """
    Asserts that the UI explicitly differentiates between:
    - Observed
    - Evaluated
    - Blocked
    - Allowed
    - Awaiting Approval
    """
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    assert "Observed" in html
    assert "Evaluated" in html
    assert "Blocked" in html
    assert "Allowed" in html
    assert "Awaiting Approval" in html


def test_dashboard_modals_and_evidence(client: TestClient):
    """Asserts that simulation modals, auth modals, and multi-engine evidence tabs exist."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    # Modals
    assert 'id="simulation-modal"' in html
    assert 'id="auth-modal"' in html
    assert 'id="prune-modal"' in html

    # 4-tier verification evidence containers in detail drawer
    assert "1. Deterministic Policy Engine" in html
    assert "2. Semantic Intent Classifier" in html
    assert "3. Behavioral Markov Model" in html
    assert "4. Sequential Hypothesis (SPRT)" in html


def test_dashboard_taste_skill_design_read(client: TestClient):
    """Asserts that taste-skill anti-slop guidelines and design read are present."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    assert "Design Read:" in html
    assert "VARIANCE=" in html
    assert "DENSITY=" in html


def test_live_evaluation_caches_for_dashboard(client: TestClient):
    """
    Verifies that calling /api/v1/decisions/evaluate with dry_run=False
    persists into decisions_cache and is immediately readable by GET /api/v1/decisions.
    """
    payload = {
        "action_type": "shell",
        "target": "cat /tmp/test_file.txt",
        "agent_id": "dashboard-test-agent",
        "session_id": "dashboard-test-session",
        "params": {"command": "cat /tmp/test_file.txt"},
        "dry_run": False,
    }

    eval_resp = client.post("/api/v1/decisions/evaluate", json=payload)
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    verif_id = eval_data["verification_id"]
    assert verif_id in decisions_cache

    # Query decisions endpoint (which dashboard polls)
    list_resp = client.get("/api/v1/decisions", params={"agent_id": "dashboard-test-agent"})
    assert list_resp.status_code == 200
    items = list_resp.json()["items"]
    assert any(item["verification_id"] == verif_id for item in items)


def test_live_evaluation_review_creates_approval(client: TestClient):
    """
    Verifies that a live action resulting in REVIEW automatically queues
    an ApprovalRequest in ApprovalStore for the dashboard to display.
    """
    payload = {
        "action_type": "git",
        "target": "git push origin main",
        "agent_id": "dashboard-git-agent",
        "session_id": "dashboard-git-session",
        "params": {"command": "git push origin main"},
        "dry_run": False,
    }

    eval_resp = client.post("/api/v1/decisions/evaluate", json=payload)
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()

    if eval_data["decision"] == "REVIEW":
        store = get_default_approval_store()
        requests = store.list_requests()
        assert any(r.agent_id == "dashboard-git-agent" for r in requests)

        # Ensure GET /api/v1/approvals returns it
        appr_resp = client.get("/api/v1/approvals")
        assert appr_resp.status_code == 200
        appr_list = appr_resp.json()
        assert any(r.get("agent_id") == "dashboard-git-agent" for r in appr_list)
