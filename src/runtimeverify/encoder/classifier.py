from typing import Dict, Any
from runtimeverify.encoder.base import ResourceClassifier

class DefaultResourceClassifier(ResourceClassifier):
    """
    Standard rule-based Resource Classifier. Inspects targets and tools 
    to determine semantic classification (e.g. system files vs source files), 
    required permission scopes, and baseline execution risk levels.
    """
    
    def classify(self, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
        classified = normalized_event.copy()
        resource = classified.get("resource")
        event_type = classified.get("type")
        action = classified.get("action", "unknown")
        
        resource_type = "unknown"
        risk_level = "low"
        permission_level = "read"

        if event_type == "filesystem" and resource:
            path = str(resource).lower()
            if path.startswith("/etc") or "shadow" in path or "passwd" in path or ".env" in path:
                resource_type = "system_secret"
                risk_level = "critical"
                permission_level = "admin"
            elif path.endswith(".py") or path.endswith(".js") or path.endswith(".go") or path.endswith(".ts"):
                resource_type = "source_code"
                risk_level = "medium"
                permission_level = "write" if action in ["write", "delete", "create"] else "read"
            elif path.endswith(".json") or path.endswith(".yaml") or path.endswith(".yml") or path.endswith(".toml"):
                resource_type = "config"
                risk_level = "medium"
                permission_level = "write" if action in ["write", "delete", "create"] else "read"
            else:
                resource_type = "general_file"
                risk_level = "low"
        elif event_type == "network" and resource:
            url = str(resource).lower()
            if "github.com" in url or "gitlab.com" in url:
                resource_type = "source_repository"
                risk_level = "medium"
            elif "localhost" in url or "127.0.0.1" in url:
                resource_type = "local_network"
                risk_level = "low"
            else:
                resource_type = "external_api"
                risk_level = "high"
        elif event_type == "tool" and resource:
            tool_name = str(resource).lower()
            if tool_name in ["run_command", "execute_shell", "execute_command", "bash", "sh", "cmd"]:
                resource_type = "shell"
                risk_level = "high"
                permission_level = "write"
            else:
                resource_type = "utility"
                risk_level = "low"

        classified["resource_type"] = resource_type
        classified["risk_level"] = risk_level
        classified["permission_level"] = permission_level
        return classified
