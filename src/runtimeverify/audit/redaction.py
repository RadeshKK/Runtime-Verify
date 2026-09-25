"""
Secret Redaction Engine for RuntimeVerify (Phase 8).
Guarantees that credentials, tokens, private keys, and sensitive environment variables
are sanitized before audit records are emitted or persisted.
"""

from copy import deepcopy
import re
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple


class SecretRedactor:
    """
    Sanitizes sensitive security credentials from audit payloads.
    Protects against credential leakage in logs via key-name matching and regex value scanning.
    """

    DEFAULT_REDACTION_MARKER = "[REDACTED]"

    # Sensitive key names (case-insensitive substring/equality matching)
    DEFAULT_SENSITIVE_KEYS: Set[str] = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "api_key",
        "apikey",
        "token",
        "access_token",
        "auth",
        "authorization",
        "private_key",
        "privkey",
        "bearer",
        "credential",
        "credentials",
        "client_secret",
        "secret_key",
        "secret_access_key",
        "jwt",
        "id_rsa",
        "id_ed25519",
        "connection_string",
        "db_password",
        "ssh_key",
        "pgpassword",
    }

    # Sensitive pattern matchers for values
    DEFAULT_VALUE_PATTERNS: List[Tuple[Pattern[str], str]] = [
        # Private Keys (RSA, OpenSSH, EC, DSA)
        (
            re.compile(
                r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
                re.MULTILINE,
            ),
            "[REDACTED_PRIVATE_KEY]",
        ),
        # Anthropic API Keys (must precede OpenAI sk- prefix matching)
        (
            re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),
            "[REDACTED_ANTHROPIC_KEY]",
        ),
        # OpenAI API Keys
        (
            re.compile(r"sk-(?:proj-)?[a-zA-Z0-9_-]{20,}", re.IGNORECASE),
            "[REDACTED_OPENAI_KEY]",
        ),
        # Google Gemini / Cloud API Keys
        (
            re.compile(r"AIza[0-9A-Za-z\-_]{30,35}"),
            "[REDACTED_GOOGLE_KEY]",
        ),
        # Stripe Secret Keys
        (
            re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
            "[REDACTED_STRIPE_KEY]",
        ),
        # HuggingFace Access Tokens
        (
            re.compile(r"hf_[a-zA-Z0-9]{34,}"),
            "[REDACTED_HUGGINGFACE_TOKEN]",
        ),
        # JWT Tokens
        (
            re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
            "[REDACTED_JWT_TOKEN]",
        ),
        # AWS Access Key IDs
        (
            re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
            "[REDACTED_AWS_KEY_ID]",
        ),
        # GitHub Personal Access Tokens (classic and fine-grained)
        (
            re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}"),
            "[REDACTED_GITHUB_TOKEN]",
        ),
        (
            re.compile(r"github_pat_[0-9a-zA-Z_]{22,}"),
            "[REDACTED_GITHUB_PAT]",
        ),
        # Slack Tokens
        (
            re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
            "[REDACTED_SLACK_TOKEN]",
        ),
        # Bearer Authorization headers
        (
            re.compile(r"(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*"),
            "Bearer [REDACTED_BEARER_TOKEN]",
        ),
        # Database URIs with embedded passwords (e.g. postgresql://user:pass@host:5432/db)
        (
            re.compile(r"(://[^:\s]+:)([^@\s]+)(@)"),
            r"\1[REDACTED_PASSWORD]\3",
        ),
        # Generic assignment patterns (e.g. API_KEY=xyz, password="xyz")
        (
            re.compile(
                r"(?i)(api[_-]?key|secret[_-]?access[_-]?key|secret|password|passwd|auth[_-]?token|bearer[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_!#$%&*+\-/=?^`{|}~.]{8,})['\"]?"
            ),
            r"\1=[REDACTED]",
        ),
    ]

    def __init__(
        self,
        sensitive_keys: Optional[Set[str]] = None,
        custom_patterns: Optional[List[Tuple[Pattern[str], str]]] = None,
        redaction_marker: str = DEFAULT_REDACTION_MARKER,
    ):
        self.sensitive_keys = sensitive_keys or set(self.DEFAULT_SENSITIVE_KEYS)
        self.value_patterns = list(self.DEFAULT_VALUE_PATTERNS)
        if custom_patterns:
            self.value_patterns.extend(custom_patterns)
        self.redaction_marker = redaction_marker

    EXCLUDED_SAFE_KEYS: Set[str] = {
        "authenticated",
        "author",
        "authors",
        "authority",
    }

    def is_sensitive_key(self, key_name: str) -> bool:
        """Determines if a key name matches any known sensitive keyword."""
        clean_key = str(key_name).lower().strip()
        if clean_key in self.EXCLUDED_SAFE_KEYS:
            return False
        if clean_key in self.sensitive_keys:
            return True
        for sens in self.sensitive_keys:
            if sens in clean_key:
                return True
        return False

    def redact_string(self, text: str) -> Tuple[str, bool]:
        """Scans and redacts matching sensitive regex patterns in a string."""
        if not text:
            return text, False

        redacted_text = text
        was_modified = False

        for pattern, replacement in self.value_patterns:
            if pattern.search(redacted_text):
                redacted_text = pattern.sub(replacement, redacted_text)
                was_modified = True

        return redacted_text, was_modified

    def redact(self, data: Any) -> Tuple[Any, bool]:
        """
        Recursively redacts dictionary, list, string, or primitive values.
        Returns a sanitized copy and a boolean flag indicating if redactions occurred.
        """
        modified = False

        if isinstance(data, dict):
            sanitized_dict: Dict[str, Any] = {}
            for k, v in data.items():
                if self.is_sensitive_key(str(k)):
                    sanitized_dict[k] = self.redaction_marker
                    modified = True
                else:
                    val_redacted, val_mod = self.redact(v)
                    sanitized_dict[k] = val_redacted
                    if val_mod:
                        modified = True
            return sanitized_dict, modified

        elif isinstance(data, list):
            sanitized_list = []
            for item in data:
                item_redacted, item_mod = self.redact(item)
                sanitized_list.append(item_redacted)
                if item_mod:
                    modified = True
            return sanitized_list, modified

        elif isinstance(data, tuple):
            sanitized_items = []
            for item in data:
                item_redacted, item_mod = self.redact(item)
                sanitized_items.append(item_redacted)
                if item_mod:
                    modified = True
            return tuple(sanitized_items), modified

        elif isinstance(data, str):
            return self.redact_string(data)

        return deepcopy(data), False

    # Alias for dictionary-specific redaction
    redact_dict = redact


# Default shared redactor instance
_default_redactor = SecretRedactor()


def redact_secrets(data: Any) -> Tuple[Any, bool]:
    """Convenience helper utilizing the default SecretRedactor."""
    return _default_redactor.redact(data)
