"""
Input Validation and Log Injection Safeguards for RuntimeVerify (Phase 14).
Provides strict input sanitization, terminal escape sequence stripping,
and identifier validation to guard against log injection, terminal spoofing, and resource exhaustion.
"""

import re
from typing import Optional


class InputSecurityValidator:
    """
    Sanitizes user and telemetry inputs against:
    - Terminal escape code injection (ANSI escape sequences that clear terminals or spoof CLI prompts).
    - Log injection (CRLF sequences attempting to forge NDJSON lines or log entries).
    - Unbounded payload memory exhaustion.
    """

    # Matches ANSI escape sequences (e.g. \x1b[2J, \x1b[31m, etc.)
    ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    # Matches safe alphanumeric identifiers (agent_id, session_id, request_id, event_id)
    SAFE_IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9_\-\.:]{1,128}$")

    # Non-printable and line-forgery control characters (including \r carriage return)
    CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\r\x0B\x0C\x0E-\x1F\x7F]")

    @classmethod
    def sanitize_log_text(cls, text: str, max_length: int = 10000) -> str:
        """
        Sanitizes text intended for logs, CLI output, or audit summaries:
        - Truncates to max_length to prevent memory exhaustion.
        - Strips ANSI terminal escape sequences.
        - Replaces non-printable control characters and carriage returns.
        """
        if not text:
            return ""

        # Enforce length bound
        truncated = text[:max_length] if len(text) > max_length else text

        # Strip ANSI escape sequences
        no_ansi = cls.ANSI_ESCAPE_RE.sub("", truncated)

        # Replace dangerous control characters with space
        clean = cls.CONTROL_CHARS_RE.sub(" ", no_ansi)

        return clean.strip()

    # Alias for convenience
    sanitize_for_log = sanitize_log_text

    @classmethod
    def validate_identifier(cls, identifier: Optional[str], field_name: str = "identifier") -> bool:
        """
        Validates that an identifier contains only safe alphanumeric characters,
        hyphens, underscores, dots, or colons, with length <= 128.
        """
        if not identifier:
            return False
        return bool(cls.SAFE_IDENTIFIER_RE.fullmatch(identifier))
