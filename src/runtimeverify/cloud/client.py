import time
import requests
from typing import Dict, Any

class CloudVerificationClient:
    """
    Enterprise Cloud Verification Client.
    Streamingly pushes local decision metrics and transition alerts to the hosted verify cloud platform.
    """
    
    def __init__(self, endpoint: str, api_key: str):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        })

    def push_decision(self, session_id: str, agent_id: str, decision: Dict[str, Any]) -> bool:
        """
        Pushes a locally computed pipeline decision payload to the verify Cloud dashboard.
        """
        payload = {
            "session_id": session_id,
            "agent_id": agent_id,
            "timestamp": time.time(),
            "decision": decision
        }
        
        try:
            response = self.session.post(f"{self.endpoint}/v1/metrics", json=payload, timeout=5)
            return response.status_code == 200
        except Exception:
            # Silently degrade gracefully to prevent cloud push errors from interrupting local execution
            return False

    def push_alert(self, session_id: str, agent_id: str, policy_name: str, evidence: Dict[str, Any]) -> bool:
        """
        Pushes a critical security intervention warning to the central incident response dashboard.
        """
        payload = {
            "session_id": session_id,
            "agent_id": agent_id,
            "policy_violated": policy_name,
            "evidence": evidence,
            "timestamp": time.time()
        }
        
        try:
            response = self.session.post(f"{self.endpoint}/v1/alerts", json=payload, timeout=5)
            return response.status_code == 201
        except Exception:
            return False
