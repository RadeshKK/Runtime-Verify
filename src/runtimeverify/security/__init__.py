"""
Security Hardening and Defense-in-Depth Package for RuntimeVerify (Phase 14).
Provides path canonicalization, command parsing safeguards, SSRF prevention,
cryptographic audit integrity, approval replay protection, and input sanitization.
"""

from runtimeverify.security.approval_tokens import ApprovalTokenManager
from runtimeverify.security.audit_integrity import AuditIntegrityEngine
from runtimeverify.security.commands import (
    CommandPipelineParser,
    SubCommand,
    check_dangerous_constructs,
    parse_command_pipeline,
)
from runtimeverify.security.input_validation import InputSecurityValidator
from runtimeverify.security.network import (
    NetworkDestinationValidator,
    validate_network_target,
)
from runtimeverify.security.paths import (
    SecurePathNormalizer,
    SecurityPathError,
    is_path_traversal,
    normalize_secure_path,
)

__all__ = [
    "ApprovalTokenManager",
    "AuditIntegrityEngine",
    "CommandPipelineParser",
    "InputSecurityValidator",
    "NetworkDestinationValidator",
    "SecurePathNormalizer",
    "SecurityPathError",
    "SubCommand",
    "check_dangerous_constructs",
    "is_path_traversal",
    "normalize_secure_path",
    "parse_command_pipeline",
    "validate_network_target",
]
