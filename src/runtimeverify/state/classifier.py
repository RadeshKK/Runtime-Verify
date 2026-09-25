from abc import ABC, abstractmethod
import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional, Set
import urllib.parse

from runtimeverify.events.base import Event
from runtimeverify.events.enums import EventAction, EventType
from runtimeverify.state.context import StateContext
from runtimeverify.state.security import SecurityState
from runtimeverify.state.taxonomy import (
    DEFAULT_SECURITY_RISK_MAP,
    SecurityRiskLevel,
    SecurityStateCategory,
    get_default_category,
    get_default_hierarchy,
)

logger = logging.getLogger(__name__)


class BaseEventClassifier(ABC):
    """
    Abstract interface defining the event classification contract.
    Transforms a runtime telemetry Event into a normalized SecurityState.
    """

    @abstractmethod
    def classify(self, event: Event) -> SecurityState:
        """
        Classifies an Event into a SecurityState.

        Args:
            event: The runtime telemetry event to classify.

        Returns:
            The resolved SecurityState.
        """
        pass


class BaseStateEnricher(ABC):
    """
    Abstract interface for post-classification semantic enrichment.
    Allows future semantic classifiers (such as Laya) or custom security rules
    to enrich, re-score, or refine a SecurityState without replacing the deterministic foundation.
    """

    @property
    @abstractmethod
    def enricher_name(self) -> str:
        """Unique identifier name for this enricher."""
        pass

    @abstractmethod
    def enrich(self, state: SecurityState, event: Event) -> SecurityState:
        """
        Enriches or refines an existing SecurityState.

        Args:
            state: The SecurityState produced by the base classifier or previous enricher.
            event: The original source Event.

        Returns:
            An updated SecurityState (can be the same or a new enriched instance).
        """
        pass


class DeterministicSecurityClassifier(BaseEventClassifier):
    """
    Rule-based, zero-LLM deterministic security classifier.
    Maps canonical and legacy events into the 27 canonical SecurityState categories
    using pattern matching, URL analysis, and event semantics.
    """

    DEFAULT_TRUSTED_DOMAINS: Set[str] = {
        "api.openai.com",
        "api.anthropic.com",
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "huggingface.co",
    }

    DEFAULT_SENSITIVE_HOSTS: Set[str] = {
        "169.254.169.254",  # AWS / Azure / GCP IMDS endpoint
        "metadata.google.internal",
        "169.254.169.123",
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
    }

    # Shell regex patterns
    DESTRUCTIVE_SHELL_PATTERNS = [
        re.compile(r"\brm\s+.*(-[a-zA-Z]*[rf][a-zA-Z]*|--recursive|--force)\b", re.IGNORECASE),
        re.compile(r"\b(mkfs(\.[a-z0-9]+)?|fdisk|parted|shred|wipefs)\b", re.IGNORECASE),
        re.compile(r"\bdd\s+.*(if=|of=)", re.IGNORECASE),
        re.compile(r"\bformat\s+[a-zA-Z]:", re.IGNORECASE),
        re.compile(r"\b(del|rmdir)\s+/[sqf]", re.IGNORECASE),
        re.compile(r">\s*/dev/sd[a-z0-9]", re.IGNORECASE),
        re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),
    ]

    PRIVILEGED_SHELL_PATTERNS = [
        re.compile(r"\b(sudo|su|doas|visudo|runas)\b", re.IGNORECASE),
        re.compile(r"\bchmod\s+([0-7]{3,4}|\+[rwxXst]+)", re.IGNORECASE),
        re.compile(r"\b(chown|chgrp|setfacl)\b", re.IGNORECASE),
        re.compile(r"\bnet\s+(localgroup|user)\s+.*", re.IGNORECASE),
    ]

    NETWORK_SHELL_PATTERNS = [
        re.compile(
            r"\b(curl|wget|nc|netcat|ncat|ssh|scp|sftp|ftp|telnet|ping|traceroute|nmap|socat|rsync)\b", re.IGNORECASE
        ),
    ]

    # Sensitive secret file path patterns
    SECRET_TARGET_PATTERNS = [
        re.compile(
            r"(\.env(\.[a-zA-Z0-9_-]+)?|\.aws/credentials|\.ssh/id_rsa|\.ssh/id_ed25519|credentials\.json|\.netrc|shadow|master\.passwd|\.npmrc|\.dockercfg|kube/config)$",
            re.IGNORECASE,
        ),
        re.compile(r".*(id_rsa|id_dsa|id_ed25519|private_key\.pem|secret_key|\.pfx|\.p12)", re.IGNORECASE),
    ]

    def __init__(
        self,
        trusted_domains: Optional[Set[str]] = None,
        sensitive_hosts: Optional[Set[str]] = None,
    ):
        self.trusted_domains = (
            set(trusted_domains) if trusted_domains is not None else set(self.DEFAULT_TRUSTED_DOMAINS)
        )
        self.sensitive_hosts = (
            set(sensitive_hosts) if sensitive_hosts is not None else set(self.DEFAULT_SENSITIVE_HOSTS)
        )

    def classify(self, event: Event) -> SecurityState:
        """Classifies a runtime telemetry event into a SecurityState."""
        sec_category, attributes = self._determine_category_and_attributes(event)
        risk_level = self._evaluate_risk(sec_category, attributes, event)

        context = StateContext(
            agent_id=event.agent_id,
            session_id=event.session_id,
            resource_id=event.target,
            resource_type=self._get_event_type_str(event),
            timestamp=event.timestamp,
        )

        return SecurityState(
            security_category=sec_category,
            risk_level=risk_level,
            category=get_default_category(sec_category),
            hierarchy=get_default_hierarchy(sec_category),
            context=context,
            confidence=1.0,
            attributes=attributes,
            source_event_id=event.event_id,
            source_event_type=self._get_event_type_str(event),
            classifier_source="deterministic",
        )

    def _get_event_type_str(self, event: Event) -> str:
        et = event.event_type
        return et.value if hasattr(et, "value") else str(et)

    def _get_action_str(self, event: Event) -> str:
        action = event.action
        if action is None:
            return ""
        return (action.value if hasattr(action, "value") else str(action)).upper()

    def _determine_category_and_attributes(self, event: Event) -> tuple[SecurityStateCategory, Dict[str, Any]]:
        event_type_str = self._get_event_type_str(event).upper()
        action_str = self._get_action_str(event)
        target = str(event.target or "")
        attributes: Dict[str, Any] = {}

        # 1. Shell commands
        if event_type_str == EventType.SHELL_COMMAND.value.upper() or action_str in (
            EventAction.EXECUTE.value.upper(),
            "EXECUTE",
            "RUN",
            "SHELL",
        ):
            command = getattr(event, "command", None) or target or event.metadata.get("command", "")
            attributes["command"] = command
            sec_cat = self._classify_shell_command(command)
            return sec_cat, attributes

        # 2. Network requests
        if event_type_str == EventType.NETWORK_REQUEST.value.upper() or action_str in (
            EventAction.CONNECT.value.upper(),
            "NETWORK",
            "HTTP",
        ):
            url = getattr(event, "url", None) or target or event.metadata.get("url", "")
            method = getattr(event, "method", None) or event.metadata.get("method", "GET")
            attributes["url"] = url
            attributes["method"] = method
            sec_cat = self._classify_network_target(url)
            return sec_cat, attributes

        # 3. Filesystem operations
        if event_type_str in (
            EventType.FILESYSTEM_READ.value.upper(),
            EventType.FILESYSTEM_WRITE.value.upper(),
            EventType.FILESYSTEM_DELETE.value.upper(),
        ) or action_str in (
            EventAction.READ.value.upper(),
            EventAction.WRITE.value.upper(),
            EventAction.DELETE.value.upper(),
            "MODIFY",
            "REMOVE",
        ):
            path = getattr(event, "path", None) or target
            attributes["path"] = path

            # Check if this file access targets credentials or secrets
            if self._is_secret_path(path):
                attributes["is_secret_path"] = True
                return SecurityStateCategory.SECRET_ACCESS, attributes

            if event_type_str == EventType.FILESYSTEM_DELETE.value.upper() or action_str in (
                EventAction.DELETE.value.upper(),
                "REMOVE",
                "DROP",
                "UNLINK",
            ):
                return SecurityStateCategory.FILE_DELETE, attributes
            elif event_type_str == EventType.FILESYSTEM_WRITE.value.upper() or action_str in (
                EventAction.WRITE.value.upper(),
                "MODIFY",
                "APPEND",
                "TOUCH",
            ):
                return SecurityStateCategory.FILE_WRITE, attributes
            else:
                return SecurityStateCategory.FILE_READ, attributes

        # 4. Git operations
        if event_type_str == EventType.GIT_OPERATION.value.upper():
            operation = (getattr(event, "operation", None) or action_str or event.metadata.get("operation", "")).upper()
            attributes["git_operation"] = operation

            if "COMMIT" in operation:
                return SecurityStateCategory.GIT_COMMIT, attributes
            elif "PUSH" in operation:
                return SecurityStateCategory.GIT_PUSH, attributes
            else:
                return SecurityStateCategory.GIT_READ, attributes

        # 5. Process Lifecycle
        if event_type_str == EventType.PROCESS_CREATION.value.upper() or action_str in (
            EventAction.SPAWN.value.upper(),
            "CREATE",
            "START",
            "SPAWN",
        ):
            cmd = getattr(event, "command_line", None) or target
            attributes["command_line"] = cmd
            return SecurityStateCategory.PROCESS_CREATE, attributes

        if event_type_str in ("PROCESS_TERMINATION", "PROCESS.TERMINATION") or action_str in (
            "KILL",
            "STOP",
            "TERMINATE",
            "ABORT",
        ):
            attributes["target_process"] = target
            return SecurityStateCategory.PROCESS_TERMINATE, attributes

        # 6. Credentials & Secrets
        if event_type_str == EventType.CREDENTIAL_ACCESS.value.upper() or action_str == "CREDENTIAL":
            cred_type = getattr(event, "credential_type", None) or event.metadata.get("credential_type", "")
            attributes["credential_type"] = cred_type
            if "SECRET" in str(cred_type).upper() or "SECRET" in target.upper():
                return SecurityStateCategory.SECRET_ACCESS, attributes
            return SecurityStateCategory.CREDENTIAL_ACCESS, attributes

        # 7. LLM requests and responses
        if event_type_str == EventType.LLM_REQUEST.value.upper():
            attributes["model"] = getattr(event, "model", None) or event.metadata.get("model")
            return SecurityStateCategory.LLM_REQUEST, attributes

        if event_type_str == EventType.LLM_RESPONSE.value.upper():
            attributes["model"] = getattr(event, "model", None) or event.metadata.get("model")
            return SecurityStateCategory.LLM_RESPONSE, attributes

        # 8. Tool Calls and Results
        if event_type_str == EventType.TOOL_CALL.value.upper() or action_str in (
            EventAction.CALL.value.upper(),
            "INVOKE",
        ):
            tool_name = getattr(event, "tool_name", None) or target or event.metadata.get("tool_name", "")
            attributes["tool_name"] = tool_name
            return SecurityStateCategory.TOOL_CALL, attributes

        if event_type_str == EventType.TOOL_RESULT.value.upper() or action_str in (
            EventAction.RESULT.value.upper(),
            "COMPLETE",
            "ERROR",
        ):
            tool_name = getattr(event, "tool_name", None) or target or event.metadata.get("tool_name", "")
            attributes["tool_name"] = tool_name
            return SecurityStateCategory.TOOL_RESULT, attributes

        # 9. Multi-Agent Communication
        if event_type_str == EventType.AGENT_COMMUNICATION.value.upper() or action_str in (
            EventAction.SEND.value.upper(),
            EventAction.RECEIVE.value.upper(),
        ):
            msg_type = (
                getattr(event, "message_type", None) or event.metadata.get("message_type", "") or action_str
            ).upper()
            attributes["message_type"] = msg_type
            if "HANDOFF" in msg_type or "TRANSFER" in msg_type or event.metadata.get("handoff"):
                return SecurityStateCategory.AGENT_HANDOFF, attributes
            return SecurityStateCategory.AGENT_MESSAGE, attributes

        # 10. Human Approvals
        if event_type_str == EventType.HUMAN_APPROVAL.value.upper() or action_str in (
            EventAction.APPROVE.value.upper(),
            "APPROVAL",
        ):
            status = getattr(event, "status", None) or event.metadata.get("status", "")
            attributes["approval_status"] = status
            return SecurityStateCategory.HUMAN_APPROVAL, attributes

        # 11. Policy Decisions
        if event_type_str == EventType.POLICY_DECISION.value.upper() or action_str in (
            EventAction.ALLOW.value.upper(),
            EventAction.BLOCK.value.upper(),
            EventAction.REVIEW.value.upper(),
        ):
            decision = (getattr(event, "decision", None) or event.metadata.get("decision", "") or target).upper()
            attributes["policy_decision"] = decision

            if decision in ("ALLOW", "PERMIT", "PASS"):
                return SecurityStateCategory.POLICY_ALLOW, attributes
            elif decision in ("BLOCK", "DENY", "REJECT"):
                return SecurityStateCategory.POLICY_BLOCK, attributes
            elif decision in ("REVIEW", "WARN", "AUDIT", "ESCALATE"):
                return SecurityStateCategory.POLICY_REVIEW, attributes
            else:
                return SecurityStateCategory.POLICY_ALLOW, attributes

        # 12. Fallback check on EventAction
        if action_str == EventAction.CONNECT.value.upper():
            attributes["target"] = target
            return self._classify_network_target(target), attributes

        return SecurityStateCategory.UNKNOWN, attributes

    def _classify_shell_command(self, command: str) -> SecurityStateCategory:
        """Evaluates shell command string against safety profiles."""
        cmd = command.strip()

        # Check destructive first (highest priority)
        for pattern in self.DESTRUCTIVE_SHELL_PATTERNS:
            if pattern.search(cmd):
                return SecurityStateCategory.SHELL_DESTRUCTIVE

        # Check privileged
        for pattern in self.PRIVILEGED_SHELL_PATTERNS:
            if pattern.search(cmd):
                return SecurityStateCategory.SHELL_PRIVILEGED

        # Check network
        for pattern in self.NETWORK_SHELL_PATTERNS:
            if pattern.search(cmd):
                return SecurityStateCategory.SHELL_NETWORK

        return SecurityStateCategory.SHELL_SAFE

    def _classify_network_target(self, url_or_host: str) -> SecurityStateCategory:
        """Evaluates network target for sensitive, trusted, or unknown destination."""
        target = url_or_host.strip()
        if not target:
            return SecurityStateCategory.NETWORK_UNKNOWN

        # Extract hostname
        host = self._extract_host(target).lower()

        # 1. Sensitive checks (cloud metadata or localhost/private IPs)
        if host in self.sensitive_hosts:
            return SecurityStateCategory.NETWORK_SENSITIVE

        try:
            ip = ipaddress.ip_address(host)
            if ip.is_loopback or ip.is_private or ip.is_link_local:
                return SecurityStateCategory.NETWORK_SENSITIVE
        except ValueError:
            # Not an IP literal, continue with domain check
            pass

        # 2. Trusted domain checks
        for trusted in self.trusted_domains:
            trusted_lower = trusted.lower()
            if host == trusted_lower or host.endswith("." + trusted_lower):
                return SecurityStateCategory.NETWORK_TRUSTED

        # 3. Default to unknown
        return SecurityStateCategory.NETWORK_UNKNOWN

    def _extract_host(self, url: str) -> str:
        """Extracts the host component safely from a URL or raw host string."""
        if "://" not in url and not url.startswith("//"):
            url = "//" + url
        try:
            parsed = urllib.parse.urlsplit(url)
            host = parsed.hostname or parsed.netloc.split(":")[0]
            return host.strip() if host else url.strip()
        except Exception:
            return url.strip()

    def _is_secret_path(self, path: Optional[str]) -> bool:
        """Checks if a file path targets secret or credential artifacts."""
        if not path:
            return False
        normalized_path = path.replace("\\", "/")
        for pattern in self.SECRET_TARGET_PATTERNS:
            if pattern.search(normalized_path):
                return True
        return False

    def _evaluate_risk(
        self,
        category: SecurityStateCategory,
        attributes: Dict[str, Any],
        event: Event,
    ) -> SecurityRiskLevel:
        """Resolves risk level, defaulting to baseline taxonomy risk."""
        return DEFAULT_SECURITY_RISK_MAP.get(category, SecurityRiskLevel.INFO)


class SecurityClassificationPipeline:
    """
    State classification pipeline that chains a base deterministic classifier
    with optional post-classification enrichers (such as future semantic classifiers like Laya).
    """

    def __init__(
        self,
        base_classifier: Optional[BaseEventClassifier] = None,
        enrichers: Optional[List[BaseStateEnricher]] = None,
    ):
        self.base_classifier: BaseEventClassifier = base_classifier or DeterministicSecurityClassifier()
        self._enrichers: List[BaseStateEnricher] = list(enrichers or [])

    def add_enricher(self, enricher: BaseStateEnricher) -> None:
        """Appends a new semantic enricher to the pipeline."""
        self._enrichers.append(enricher)

    def remove_enricher(self, enricher_name: str) -> bool:
        """Removes an enricher by its name identifier."""
        initial_len = len(self._enrichers)
        self._enrichers = [e for e in self._enrichers if e.enricher_name != enricher_name]
        return len(self._enrichers) < initial_len

    def list_enrichers(self) -> List[str]:
        """Returns the ordered list of registered enricher names."""
        return [e.enricher_name for e in self._enrichers]

    def classify(self, event: Event) -> SecurityState:
        """
        Executes deterministic classification followed by the sequential enricher chain.
        Ensures that enricher failures do not disrupt core classification.
        """
        # Step 1: Base deterministic classification (zero LLM dependency)
        state = self.base_classifier.classify(event)

        # Step 2: Post-enrichment (semantic classifiers / Laya / rules)
        for enricher in self._enrichers:
            try:
                state = enricher.enrich(state, event)
            except Exception as e:
                logger.warning(
                    "Security state enricher '%s' failed on event '%s': %s",
                    enricher.enricher_name,
                    getattr(event, "event_id", "unknown"),
                    e,
                )

        return state

    def __call__(self, event: Event) -> SecurityState:
        """Allows the pipeline to be invoked directly as a callable."""
        return self.classify(event)


class SecurityClassifierRegistry:
    """
    Extensible central registry for classifiers and enrichers.
    Allows runtime configuration, plugin hooks, and custom policy rules.
    """

    def __init__(self):
        self._default_pipeline = SecurityClassificationPipeline()
        self._custom_classifiers: Dict[str, BaseEventClassifier] = {}

    def get_pipeline(self) -> SecurityClassificationPipeline:
        """Returns the default classification pipeline."""
        return self._default_pipeline

    def register_enricher(self, enricher: BaseStateEnricher) -> None:
        """Registers a global enricher into the default pipeline."""
        self._default_pipeline.add_enricher(enricher)

    def register_classifier(self, name: str, classifier: BaseEventClassifier) -> None:
        """Registers a custom named classifier."""
        self._custom_classifiers[name] = classifier

    def get_classifier(self, name: str) -> Optional[BaseEventClassifier]:
        """Retrieves a named custom classifier."""
        return self._custom_classifiers.get(name)


# Global singleton registry instance
_default_registry = SecurityClassifierRegistry()


def get_default_pipeline() -> SecurityClassificationPipeline:
    """Convenience accessor for the default classification pipeline."""
    return _default_registry.get_pipeline()


def classify_event(event: Event) -> SecurityState:
    """
    High-level convenience function: maps an Event directly to a SecurityState
    using the default classification pipeline.
    """
    return _default_registry.get_pipeline().classify(event)
