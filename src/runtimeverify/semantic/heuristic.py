"""
Heuristic Semantic Decision Engine for RuntimeVerify.
Provides semantic intent categorization, prompt injection detection,
and risk classification without external model weight downloads.
"""

import re
import time
from typing import Any, Dict, List, Optional

from runtimeverify.runtime.context import ExecutionContext
from runtimeverify.semantic.base import DecisionEngine
from runtimeverify.semantic.models import (
    DecisionSignal,
    DecisionSignalType,
    RiskClassification,
    SemanticEngineConfig,
)


class HeuristicSemanticEngine(DecisionEngine):
    """
    Pattern-driven and contextual heuristic semantic decision engine.
    Analyzes action target, parameters, prompt texts, and metadata to classify:
    - action category (shell, filesystem, prompt_injection, exfiltration, privilege_escalation, etc.)
    - semantic risk level (LOW, MEDIUM, HIGH, CRITICAL)
    - calibrated confidence score
    - decision signal (ALLOW, REVIEW, BLOCK)
    """

    def __init__(self, config: Optional[SemanticEngineConfig] = None):
        super().__init__(config=config)

        # Compiled regex patterns for intent classification
        self._prompt_injection_patterns: List[re.Pattern] = [
            re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
            re.compile(r"system\s+(override|prompt|bypass)", re.IGNORECASE),
            re.compile(r"you\s+are\s+now\s+(dan|unrestricted|jailbroken)", re.IGNORECASE),
            re.compile(r"(reveal|dump|leak|print)\s+(the\s+)?(system\s+prompt|secret|api[_\s-]?key)", re.IGNORECASE),
            re.compile(r"forget\s+(your\s+)?(rules|instructions|constraints)", re.IGNORECASE),
            re.compile(r"disregard\s+prior\s+guidelines", re.IGNORECASE),
        ]

        self._exfiltration_patterns: List[re.Pattern] = [
            re.compile(
                r"curl\s+.*(-d|--data|--data-binary|--upload-file|-F)\s+.*(@\.env|@~?/\.aws|@~?/\.ssh)", re.IGNORECASE
            ),
            re.compile(r"nc\s+.*(-e|\/bin\/(ba)?sh)", re.IGNORECASE),
            re.compile(r"(base64|openssl|xxd)\s+.*\|\s*(curl|wget|nc)", re.IGNORECASE),
            re.compile(r"curl\s+.*https?://.*(exfil|attacker|leak|webhook|evil)", re.IGNORECASE),
        ]

        self._destructive_patterns: List[re.Pattern] = [
            re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b\s+[/~]", re.IGNORECASE),
            re.compile(r"\bmkfs\.[a-z0-9]+\s+/dev/", re.IGNORECASE),
            re.compile(r"\bdd\s+if=/dev/zero\s+of=/dev/", re.IGNORECASE),
            re.compile(r"\bchmod\s+(-R\s+)?777\s+/", re.IGNORECASE),
            re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),  # Fork bomb
        ]

        self._suspicious_network_patterns: List[re.Pattern] = [
            re.compile(r"(curl|wget)\s+.*\|\s*(bash|sh|zsh|python|perl)", re.IGNORECASE),
            re.compile(r"nmap\s+-[sS|pP|A]", re.IGNORECASE),
            re.compile(r"bash\s+-i\s+>&?\s+/dev/tcp/", re.IGNORECASE),
            re.compile(r"powershell\s+.*-enc(odedcommand)?", re.IGNORECASE),
        ]

        self._privilege_escalation_patterns: List[re.Pattern] = [
            re.compile(r"\bsudo\s+(su|bash|sh|passwd|visudo)\b", re.IGNORECASE),
            re.compile(r"/etc/sudoers", re.IGNORECASE),
            re.compile(r"chmod\s+\+s\b", re.IGNORECASE),
            re.compile(r"chown\s+root", re.IGNORECASE),
        ]

        self._credential_patterns: List[re.Pattern] = [
            re.compile(r"(\.aws/credentials|\.ssh/id_|\.env\b|/etc/shadow|/etc/passwd)", re.IGNORECASE),
            re.compile(r"(api[_\s-]?key|secret[_\s-]?key|access[_\s-]?token|private[_\s-]?key)", re.IGNORECASE),
        ]

        self._abnormal_tool_patterns: List[re.Pattern] = [
            re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
            re.compile(r"\bdelete\s+from\b\s+[a-zA-Z0-9_]+\s*(;|--|$)", re.IGNORECASE),
            re.compile(r"\bexec\(|\beval\(", re.IGNORECASE),
        ]

        self._agent_abuse_patterns: List[re.Pattern] = [
            re.compile(r"(unauthorized_delegate|poison_subagent|tamper_message)", re.IGNORECASE),
            re.compile(r"send_to_subagent.*(exfiltrate|delete|bypass)", re.IGNORECASE),
        ]

    @property
    def name(self) -> str:
        return "heuristic"

    def is_available(self) -> bool:
        return True

    def evaluate(
        self,
        event_or_action: Any,
        context: Optional[ExecutionContext] = None,
    ) -> DecisionSignal:
        start_time = time.perf_counter()
        text_rep = self.extract_text_representation(event_or_action, context)
        metadata = self._extract_metadata(event_or_action)
        if metadata:
            text_rep += " " + " ".join(f"{k}:{v}" for k, v in metadata.items())

        # 1. Check for Prompt Injection
        for pat in self._prompt_injection_patterns:
            if pat.search(text_rep):
                return self._build_signal(
                    category="prompt_injection",
                    risk=RiskClassification.CRITICAL,
                    signal=DecisionSignalType.BLOCK,
                    confidence=0.96,
                    reason=f"Detected prompt injection pattern: {pat.pattern}",
                    start_time=start_time,
                )

        # 2. Check for Destructive Shell Execution
        for pat in self._destructive_patterns:
            if pat.search(text_rep):
                return self._build_signal(
                    category="destructive_shell",
                    risk=RiskClassification.CRITICAL,
                    signal=DecisionSignalType.BLOCK,
                    confidence=0.98,
                    reason=f"Detected catastrophic destructive shell command: {pat.pattern}",
                    start_time=start_time,
                )

        # 3. Check for Secret Exfiltration
        for pat in self._exfiltration_patterns:
            if pat.search(text_rep):
                return self._build_signal(
                    category="secret_exfiltration",
                    risk=RiskClassification.CRITICAL,
                    signal=DecisionSignalType.BLOCK,
                    confidence=0.95,
                    reason=f"Detected external secret exfiltration pattern: {pat.pattern}",
                    start_time=start_time,
                )

        # 4. Check for Credential Access
        for pat in self._credential_patterns:
            if pat.search(text_rep):
                return self._build_signal(
                    category="credential_access",
                    risk=RiskClassification.CRITICAL,
                    signal=DecisionSignalType.BLOCK,
                    confidence=0.94,
                    reason=f"Detected unauthorized credential target: {pat.pattern}",
                    start_time=start_time,
                )

        # 5. Check for Suspicious Network Activity
        for pat in self._suspicious_network_patterns:
            if pat.search(text_rep):
                return self._build_signal(
                    category="suspicious_network",
                    risk=RiskClassification.HIGH,
                    signal=DecisionSignalType.BLOCK,
                    confidence=0.92,
                    reason=f"Detected dangerous or unauthorized network activity: {pat.pattern}",
                    start_time=start_time,
                )

        # 6. Check for Privilege Escalation
        for pat in self._privilege_escalation_patterns:
            if pat.search(text_rep):
                return self._build_signal(
                    category="privilege_escalation",
                    risk=RiskClassification.HIGH,
                    signal=DecisionSignalType.BLOCK,
                    confidence=0.91,
                    reason=f"Detected privilege escalation pattern: {pat.pattern}",
                    start_time=start_time,
                )

        # 7. Check for Abnormal Tool Misuse
        for pat in self._abnormal_tool_patterns:
            if pat.search(text_rep):
                return self._build_signal(
                    category="abnormal_tool_usage",
                    risk=RiskClassification.HIGH,
                    signal=DecisionSignalType.REVIEW,
                    confidence=0.88,
                    reason=f"Detected aberrant or hazardous tool operation: {pat.pattern}",
                    start_time=start_time,
                )

        # 8. Check for Agent-to-Agent Abuse
        for pat in self._agent_abuse_patterns:
            if pat.search(text_rep):
                return self._build_signal(
                    category="agent_to_agent_abuse",
                    risk=RiskClassification.HIGH,
                    signal=DecisionSignalType.REVIEW,
                    confidence=0.89,
                    reason=f"Detected inter-agent delegation abuse or message tampering: {pat.pattern}",
                    start_time=start_time,
                )

        # 9. Default: Normal Benign Action
        category = self._infer_benign_category(event_or_action, text_rep)
        return self._build_signal(
            category=category,
            risk=RiskClassification.LOW,
            signal=DecisionSignalType.ALLOW,
            confidence=0.95,
            reason="Semantic intent matches standard developer or benign operational profile",
            start_time=start_time,
        )

    def _build_signal(
        self,
        category: str,
        risk: RiskClassification,
        signal: DecisionSignalType,
        confidence: float,
        reason: str,
        start_time: float,
    ) -> DecisionSignal:
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        return DecisionSignal(
            engine_name=self.name,
            action_category=category,
            risk_level=risk,
            confidence=confidence,
            decision_signal=signal,
            reason=reason,
            latency_ms=round(latency_ms, 3),
        )

    def _extract_metadata(self, event_or_action: Any) -> Dict[str, Any]:
        if hasattr(event_or_action, "params") and isinstance(event_or_action.params, dict):
            return dict(event_or_action.params)
        if hasattr(event_or_action, "metadata") and isinstance(event_or_action.metadata, dict):
            return dict(event_or_action.metadata)
        if isinstance(event_or_action, dict):
            return event_or_action.get("params") or event_or_action.get("metadata") or {}
        return {}

    def _infer_benign_category(self, event_or_action: Any, text_rep: str) -> str:
        act_type = getattr(event_or_action, "action_type", None) or getattr(event_or_action, "type", None)
        if act_type:
            val = act_type.value if hasattr(act_type, "value") else str(act_type)
            return val.lower()
        if "git" in text_rep.lower():
            return "git"
        if "pytest" in text_rep.lower() or "test" in text_rep.lower():
            return "testing"
        if "read" in text_rep.lower():
            return "filesystem_read"
        if "write" in text_rep.lower():
            return "filesystem_write"
        return "normal_coding"
