import pytest
from fastapi.testclient import TestClient
from runtimeverify.api.app import app

client = TestClient(app)

def test_api_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_api_metrics():
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "total_events_processed" in response.json()
    assert "anomalies_detected" in response.json()

def test_api_monitor():
    # Construct a simple telemetry event payload dictionary
    event_payload = {
        "id": "event_api_test_123",
        "session_id": "session_api_test",
        "agent_id": "agent_api_test",
        "type": "generic",
        "metadata": {}
    }
    
    # Send monitor request
    response = client.post("/monitor", json=event_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["session_id"] == "session_api_test"
    assert data["status"] == "ALLOW"
    
    # Query history
    history_resp = client.get("/session/session_api_test")
    assert history_resp.status_code == 200
    history = history_resp.json()
    assert len(history) == 1
    assert history[0]["event"]["id"] == "event_api_test_123"
