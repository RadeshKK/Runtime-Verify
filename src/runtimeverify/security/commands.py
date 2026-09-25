"""
Command Parsing Safeguards and Chained Pipeline Decomposition for RuntimeVerify (Phase 14).
Safely decomposes complex shell commands (chaining with ;, &&, ||, |, &, newlines, and subshells)
into discrete sub-commands so that policy evaluators can prevent command injection evasion.
"""

from dataclasses import dataclass
import re
import shlex
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class SubCommand:
    """Represents an individual executable segment within a compound shell pipeline."""

    raw: str
    executable: str
    args: List[str]
    operator: Optional[str] = None  # ';', '&&', '||', '|', '&', '\n', etc.


class CommandPipelineParser:
    """
    Parses compound shell commands into constituent sub-commands.
    Guards against injection evasion techniques where a malicious payload
    (e.g., 'rm -rf /' or 'curl evil.com') is hidden behind a benign command
    using operators such as ';', '&&', '||', '|', '&', newlines, or subshells.
    """

    # Delimiters for chained shell commands
    OPERATOR_SPLIT_RE = re.compile(r"(&&|\|\||;|\||&|\n)")

    # Command substitution patterns: $(cmd) or `cmd`
    SUBSHELL_DOLLAR_RE = re.compile(r"\$\(([^)]+)\)")
    SUBSHELL_BACKTICK_RE = re.compile(r"`([^`]+)`")

    # Pipe-to-shell patterns (e.g. curl ... | bash)
    PIPE_TO_SHELL_RE = re.compile(
        r"\|\s*(ba|z|da|k|c)?sh\b|\|\s*python[0-9.]*\b|\|\s*perl\b|\|\s*ruby\b",
        re.IGNORECASE,
    )

    # Suspicious environment variable overrides before commands (e.g. LD_PRELOAD=...)
    ENV_INJECTION_RE = re.compile(
        r"\b(LD_PRELOAD|DYLD_INSERT_LIBRARIES|PYTHONPATH|NODE_OPTIONS|PERL5OPT)\s*=",
        re.IGNORECASE,
    )

    @classmethod
    def decompose(cls, command_str: str) -> List[SubCommand]:
        """
        Decomposes a compound shell command into individual SubCommand instances,
        including extracted nested subshell commands ($(cmd) and `cmd`).
        """
        if not command_str or not command_str.strip():
            return []

        clean_cmd = command_str.strip()
        subcommands: List[SubCommand] = []

        # 1. Extract nested command substitutions first
        for match in cls.SUBSHELL_DOLLAR_RE.finditer(clean_cmd):
            inner = match.group(1).strip()
            if inner:
                subcommands.extend(cls._parse_simple_or_compound(inner, operator="$()"))

        for match in cls.SUBSHELL_BACKTICK_RE.finditer(clean_cmd):
            inner = match.group(1).strip()
            if inner:
                subcommands.extend(cls._parse_simple_or_compound(inner, operator="``"))

        # 2. Parse top-level compound commands
        subcommands.extend(cls._parse_simple_or_compound(clean_cmd))

        return subcommands

    @classmethod
    def _parse_simple_or_compound(cls, cmd_segment: str, operator: Optional[str] = None) -> List[SubCommand]:
        """Splits a command segment by shell operators and yields SubCommand instances."""
        tokens = cls.OPERATOR_SPLIT_RE.split(cmd_segment)
        results: List[SubCommand] = []

        current_cmd = ""
        current_op = operator

        for token in tokens:
            if cls.OPERATOR_SPLIT_RE.fullmatch(token):
                # Operator encountered: flush preceding command
                if current_cmd.strip():
                    parsed = cls._parse_single(current_cmd.strip(), current_op)
                    if parsed:
                        results.append(parsed)
                    current_cmd = ""
                current_op = token
            else:
                current_cmd += token

        # Flush final command
        if current_cmd.strip():
            parsed = cls._parse_single(current_cmd.strip(), current_op)
            if parsed:
                results.append(parsed)

        return results

    @classmethod
    def _parse_single(cls, single_cmd: str, operator: Optional[str] = None) -> Optional[SubCommand]:
        """Extracts executable and arguments from a single atomic shell command string."""
        raw = single_cmd.strip()
        if not raw:
            return None

        # Handle environment variable prefixes e.g. "FOO=bar cmd arg"
        words: List[str] = []
        try:
            # POSIX shlex splitting handles quotes correctly
            words = shlex.split(raw, posix=True)
        except ValueError:
            # Fallback on naive whitespace splitting if unclosed quotes
            words = raw.split()

        # Filter out leading env assignments (e.g. VAR=val)
        exec_idx = 0
        while exec_idx < len(words) and "=" in words[exec_idx] and not words[exec_idx].startswith(("-", "/")):
            exec_idx += 1

        if exec_idx >= len(words):
            # Only environment assignments or empty
            exe = words[0] if words else "shell"
            args = words[1:] if len(words) > 1 else []
        else:
            exe = words[exec_idx]
            args = words[exec_idx + 1 :]

        return SubCommand(
            raw=raw,
            executable=exe,
            args=args,
            operator=operator,
        )

    @classmethod
    def check_dangerous_constructs(cls, command_str: str) -> Tuple[bool, List[str]]:
        """
        Scans command string for high-risk shell evasion or exploitation constructs.
        Returns (is_dangerous: bool, warnings: List[str]).
        """
        warnings: List[str] = []

        # 1. Pipe to shell
        if cls.PIPE_TO_SHELL_RE.search(command_str):
            warnings.append("Pipe-to-shell construct detected (e.g. 'curl ... | bash')")

        # 2. Environment injection
        if cls.ENV_INJECTION_RE.search(command_str):
            warnings.append("Sensitive environment variable injection detected (e.g. 'LD_PRELOAD=')")

        # 3. Multiple command chaining (informational)
        subcmds = cls.decompose(command_str)
        if len(subcmds) > 1:
            warnings.append(f"Compound command contains {len(subcmds)} chained sub-operations")

        return len(warnings) > 0, warnings


def parse_command_pipeline(command_str: str) -> List[SubCommand]:
    """Convenience functional wrapper for CommandPipelineParser.decompose."""
    return CommandPipelineParser.decompose(command_str)


def check_dangerous_constructs(command_str: str) -> Tuple[bool, List[str]]:
    """Convenience functional wrapper for CommandPipelineParser.check_dangerous_constructs."""
    return CommandPipelineParser.check_dangerous_constructs(command_str)
