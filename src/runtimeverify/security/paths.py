"""
Security Path Normalization and Traversal Defense for RuntimeVerify (Phase 14).
Provides strict path canonicalization, traversal detection, directory containment verification,
and cross-platform slash handling to prevent policy bypasses.
"""

import posixpath
import re
import urllib.parse


class SecurityPathError(ValueError):
    """Raised when a path fails security normalization or contains illegal sequences."""

    pass


class SecurePathNormalizer:
    r"""
    Hardened path normalizer and validator that guards against:
    - Path traversal attacks (../, ..\, %2e%2e, null byte injection)
    - Slash confusion (mixed \\ and /)
    - Trailing dot/slash evasion
    - Redundant path component obfuscation (/a/b/../../c)
    """

    # Matches raw traversal sequences
    RAW_TRAVERSAL_RE = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")
    # Matches encoded traversal sequences (%2e%2e, %252e, etc.)
    ENCODED_DOT_RE = re.compile(r"%(?:2e|252e)", re.IGNORECASE)

    @classmethod
    def contains_traversal(cls, path_str: str) -> bool:
        """
        Determines whether path contains directory traversal sequences,
        either raw or URL-encoded.
        """
        if not path_str:
            return False

        # Check raw sequences
        if ".." in path_str:
            norm = path_str.replace("\\", "/")
            if (
                cls.RAW_TRAVERSAL_RE.search(norm)
                or norm == ".."
                or norm.startswith("../")
                or norm.endswith("/..")
                or "/../" in norm
            ):
                return True

        # Check URL-encoded sequences
        if "%" in path_str:
            unquoted = urllib.parse.unquote(path_str)
            if ".." in unquoted:
                norm_unquoted = unquoted.replace("\\", "/")
                if cls.RAW_TRAVERSAL_RE.search(norm_unquoted) or norm_unquoted == ".." or "/../" in norm_unquoted:
                    return True

        return False

    @classmethod
    def normalize(
        cls,
        path_str: str,
        allow_tilde: bool = True,
        reject_traversal: bool = False,
    ) -> str:
        """
        Canonicalizes a filesystem path for security policy evaluation.

        Operations:
        1. Checks and rejects null bytes (\\0, %00).
        2. Decodes URL-encoded characters.
        3. Normalizes all backslashes to forward slashes.
        4. Rejects traversal sequences if reject_traversal is True.
        5. Resolves relative '.' and '..' segments safely.
        6. Removes redundant adjacent slashes.
        7. Strips trailing slashes (except root).

        Args:
            path_str: The raw path string from telemetry or user input.
            allow_tilde: Whether to preserve or expand tilde (~) home directory syntax.
            reject_traversal: If True, raises SecurityPathError when traversal is detected.

        Returns:
            Normalized forward-slash path string.

        Raises:
            SecurityPathError: If null bytes or prohibited traversal sequences are detected.
        """
        if not path_str:
            return ""

        # 1. Null byte detection (critical injection vector)
        if "\0" in path_str or "%00" in path_str.lower():
            raise SecurityPathError(f"Null byte detected in path: '{path_str}'")

        # 2. Decode URL encoding if present
        decoded = urllib.parse.unquote(path_str) if "%" in path_str else path_str

        # Check for traversal if rejection requested
        if reject_traversal and cls.contains_traversal(decoded):
            raise SecurityPathError(f"Directory traversal detected in path: '{path_str}'")

        # 3. Standardize slashes to forward slashes
        clean = decoded.strip().replace("\\", "/")

        # Preserve tilde prefix if present and requested
        has_tilde = clean.startswith("~/") or clean == "~"
        tilde_prefix = ""
        if has_tilde and allow_tilde:
            tilde_prefix = "~"
            clean = clean[1:]  # strip leading '~'

        # 4. Resolve relative dots using POSIX normalization
        # Leading slash ensures posixpath.normpath treats absolute paths appropriately
        is_absolute = clean.startswith("/")
        normalized = posixpath.normpath(clean)

        # Re-attach tilde prefix if applicable
        if tilde_prefix:
            if normalized == "." or normalized == "/":
                normalized = "~"
            elif normalized.startswith("/"):
                normalized = f"~{normalized}"
            else:
                normalized = f"~/{normalized}"
        elif is_absolute and not normalized.startswith("/"):
            normalized = f"/{normalized}"

        return normalized

    @classmethod
    def is_contained_in(cls, target_path: str, base_directory: str) -> bool:
        """
        Verifies whether target_path resides strictly within base_directory.
        Prevents breakout attacks where paths traverse outside the designated workspace.
        """
        try:
            norm_target = cls.normalize(target_path, allow_tilde=False)
            norm_base = cls.normalize(base_directory, allow_tilde=False)

            # Ensure trailing slash on base for prefix containment
            base_prefix = norm_base if norm_base.endswith("/") else norm_base + "/"
            target_with_slash = norm_target if norm_target.endswith("/") else norm_target + "/"

            return target_with_slash.startswith(base_prefix) or norm_target == norm_base
        except Exception:
            return False


def normalize_secure_path(path_str: str, reject_traversal: bool = False) -> str:
    """Convenience functional wrapper for SecurePathNormalizer.normalize."""
    return SecurePathNormalizer.normalize(path_str, reject_traversal=reject_traversal)


def is_path_traversal(path_str: str) -> bool:
    """Convenience functional wrapper for SecurePathNormalizer.contains_traversal."""
    return SecurePathNormalizer.contains_traversal(path_str)
