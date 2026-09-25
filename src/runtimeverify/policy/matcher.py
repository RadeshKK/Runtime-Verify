import fnmatch
import ipaddress
import logging
import os
import re
from typing import Any, Dict, Optional, Tuple, Union
import urllib.parse

from runtimeverify.events.base import Event
from runtimeverify.policy.models import (
    AgentPattern,
    CredentialPattern,
    GitPattern,
    NetworkPattern,
    PathPattern,
    Policy,
    ProcessPattern,
    ShellPattern,
    StringPattern,
    ToolPattern,
)
from runtimeverify.security.commands import CommandPipelineParser
from runtimeverify.security.network import NetworkDestinationValidator
from runtimeverify.security.paths import SecurePathNormalizer
from runtimeverify.state.classifier import DeterministicSecurityClassifier
from runtimeverify.state.security import SecurityState

logger = logging.getLogger(__name__)


class PolicyMatcher:
    """
    Deterministic rule matcher that evaluates runtime telemetry events against Policy criteria.
    Purely deterministic, explainable, and zero-LLM.
    """

    # Pipe to shell detection regex (e.g. curl http://... | bash)
    PIPE_TO_SHELL_PATTERN = re.compile(
        r"\|\s*(ba|z|da|k|c)?sh\b|\|\s*python[0-9.]*\b|\|\s*perl\b|\|\s*ruby\b",
        re.IGNORECASE,
    )

    # Directory traversal detection
    TRAVERSAL_PATTERN = re.compile(r"(\.\.[/\\]|[/\\]\.\.$|^\.\.$)")

    _deterministic_classifier = DeterministicSecurityClassifier()

    @classmethod
    def matches_event(
        cls,
        policy: Policy,
        event: Event,
        security_state: Optional[SecurityState] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Evaluates whether an event satisfies all criteria in a policy's match block.

        Args:
            policy: The Policy rule being evaluated.
            event: The runtime telemetry event.
            security_state: Optional pre-computed SecurityState for the event.

        Returns:
            Tuple of (matches: bool, match_reason: Optional[str]).
        """
        if not policy.enabled:
            return False, None

        criteria = policy.match

        # Resolve security state lazily if needed
        state = security_state
        if state is None and (criteria.security_categories or criteria.risk_levels):
            state = cls._deterministic_classifier.classify(event)

        # 1. Check event types
        if criteria.event_types:
            ev_type_str = (
                event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
            ).lower()
            allowed_types = {t.lower() for t in criteria.event_types}
            # Also allow matching state name e.g. "FILE_READ"
            matched_type = (
                ev_type_str in allowed_types
                or (state and state.name.lower() in allowed_types)
                or (state and state.security_category.value.lower() in allowed_types)
            )
            if not matched_type:
                return False, None

        # 2. Check security categories
        if criteria.security_categories:
            if not state:
                state = cls._deterministic_classifier.classify(event)
            sec_cat_name = state.security_category.value.upper()
            allowed_cats = {c.upper() for c in criteria.security_categories}
            if sec_cat_name not in allowed_cats:
                return False, None

        # 3. Check risk levels
        if criteria.risk_levels:
            if not state:
                state = cls._deterministic_classifier.classify(event)
            risk_val = state.risk_level.value.upper()
            allowed_risks = {r.upper() for r in criteria.risk_levels}
            if risk_val not in allowed_risks:
                return False, None

        # 4. Check environments
        if criteria.environments:
            env = getattr(event, "environment", None)
            env_str = (env.value if env is not None and hasattr(env, "value") else str(env or "")).lower()
            allowed_envs = {e.lower() for e in criteria.environments}
            if env_str not in allowed_envs:
                return False, None

        # 5. Check filesystem path
        if criteria.path is not None:
            path_val = getattr(event, "path", None) or event.metadata.get("path")
            if not path_val and hasattr(event, "target") and event.target:
                ev_t = (event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)).lower()
                if (
                    "file" in ev_t
                    or "secret" in ev_t
                    or "credential" in ev_t
                    or "/" in str(event.target)
                    or "\\" in str(event.target)
                ):
                    path_val = event.target
            if not path_val and event.context:
                ctx_tags = getattr(event.context, "tags", None) or getattr(event.context, "extra", None) or {}
                if isinstance(ctx_tags, dict):
                    path_val = ctx_tags.get("path")
            if not path_val or not cls.matches_path(str(path_val), criteria.path):
                return False, None

        # 6. Check shell command
        if criteria.command is not None:
            cmd_val = getattr(event, "command", None) or event.metadata.get("command")
            if not cmd_val and hasattr(event, "target") and event.target:
                ev_t = (event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)).lower()
                if "shell" in ev_t or "process" in ev_t or "exec" in ev_t:
                    cmd_val = event.target
            if not cmd_val or not cls.matches_shell(str(cmd_val), criteria.command, state):
                return False, None

        # 7. Check network destination
        if criteria.network is not None:
            net_val = getattr(event, "url", None) or event.metadata.get("url") or event.metadata.get("host")
            if not net_val and hasattr(event, "target") and event.target:
                ev_t = (event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)).lower()
                if "network" in ev_t or "http" in str(event.target).lower() or "://" in str(event.target):
                    net_val = event.target
            if not net_val or not cls.matches_network(str(net_val), criteria.network, state):
                return False, None

        # 8. Check git operations
        if criteria.git is not None:
            if not cls.matches_git(event, criteria.git):
                return False, None

        # 9. Check process execution
        if criteria.process is not None:
            proc_val = getattr(event, "command_line", None) or getattr(event, "executable", None) or event.target
            if not proc_val or not cls.matches_process(str(proc_val), criteria.process):
                return False, None

        # 10. Check credential access
        if criteria.credential is not None:
            if not cls.matches_credential(event, criteria.credential):
                return False, None

        # 11. Check tool usage
        if criteria.tool is not None:
            tool_name = getattr(event, "tool_name", None) or event.target or event.metadata.get("tool_name")
            tool_args = getattr(event, "arguments", None) or event.metadata.get("arguments", {})
            if not tool_name or not cls.matches_tool(str(tool_name), tool_args, criteria.tool):
                return False, None

        # 12. Check agent identity
        if criteria.agent is not None:
            if not cls.matches_agent(event, criteria.agent):
                return False, None

        reason = policy.reason or f"Triggered policy rule '{policy.id}' ({policy.decision.value})"
        return True, reason

    @classmethod
    def matches_string_pattern(
        cls,
        value: Optional[str],
        pattern: Union[StringPattern, str],
    ) -> bool:
        """Evaluates whether a string value matches a StringPattern or raw string."""
        if value is None:
            return False

        if isinstance(pattern, str):
            # Default raw string match checks exact (case-insensitive) or glob wildcard
            if any(char in pattern for char in "*?[]"):
                return fnmatch.fnmatch(value.lower(), pattern.lower())
            return value.strip().lower() == pattern.strip().lower()

        val = value if pattern.case_sensitive else value.lower()

        # 1. Exact
        if pattern.exact is not None:
            target = pattern.exact if pattern.case_sensitive else pattern.exact.lower()
            if val != target:
                return False

        # 2. Prefix
        if pattern.prefix is not None:
            prefix = pattern.prefix if pattern.case_sensitive else pattern.prefix.lower()
            if not val.startswith(prefix):
                return False

        # 3. Contains
        if pattern.contains is not None:
            contains = pattern.contains if pattern.case_sensitive else pattern.contains.lower()
            if contains not in val:
                return False

        # 4. Any of
        if pattern.any_of is not None:
            allowed = set(pattern.any_of) if pattern.case_sensitive else {s.lower() for s in pattern.any_of}
            if val not in allowed:
                return False

        # 5. Regex
        if pattern.regex is not None:
            regex_str = pattern.regex
            if (regex_str.startswith('r"') and regex_str.endswith('"')) or (
                regex_str.startswith("r'") and regex_str.endswith("'")
            ):
                regex_str = regex_str[2:-1]
            flags = 0 if pattern.case_sensitive else re.IGNORECASE
            try:
                if not re.search(regex_str, value, flags=flags):
                    return False
            except re.error as e:
                logger.warning("Invalid regex '%s' in pattern: %s", pattern.regex, e)
                return False

        # 6. Glob
        if pattern.glob is not None:
            target_glob = pattern.glob if pattern.case_sensitive else pattern.glob.lower()
            if not fnmatch.fnmatch(val, target_glob):
                return False

        return True

    @classmethod
    def matches_path(
        cls,
        path_str: str,
        pattern: Union[PathPattern, StringPattern, str],
    ) -> bool:
        """
        Evaluates a filesystem path pattern, including tilde expansion,
        directory traversal detection, cross-platform slashes, and path canonicalization.
        """
        raw_path = path_str.strip()
        norm_path = raw_path.replace("\\", "/")

        # Check directory traversal
        has_traversal = (
            cls.TRAVERSAL_PATTERN.search(norm_path)
            or "../" in norm_path
            or "/.." in norm_path
            or SecurePathNormalizer.contains_traversal(raw_path)
        )
        if has_traversal and isinstance(pattern, PathPattern) and pattern.block_traversal:
            return True

        canonical_path = SecurePathNormalizer.normalize(raw_path)

        if isinstance(pattern, str):
            pat_str = pattern.strip()
            return cls._path_glob_or_match(norm_path, pat_str, case_sensitive=False) or cls._path_glob_or_match(
                canonical_path, pat_str, case_sensitive=False
            )

        case_sensitive = getattr(pattern, "case_sensitive", False)
        compare_path = norm_path if case_sensitive else norm_path.lower()
        compare_canonical = canonical_path if case_sensitive else canonical_path.lower()

        # Check glob
        if pattern.glob is not None:
            match_raw = cls._path_glob_or_match(compare_path, pattern.glob, case_sensitive)
            match_canon = cls._path_glob_or_match(compare_canonical, pattern.glob, case_sensitive)
            if not (match_raw or match_canon):
                return False

        # Check regex
        if pattern.regex is not None:
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                match_raw = bool(re.search(pattern.regex, raw_path, flags=flags))
                match_canon = bool(re.search(pattern.regex, canonical_path, flags=flags))
                if not (match_raw or match_canon):
                    return False
            except re.error as e:
                logger.warning("Invalid path regex '%s': %s", pattern.regex, e)
                return False

        # Check exact
        if pattern.exact is not None:
            target_exact = pattern.exact.replace("\\", "/")
            if not case_sensitive:
                target_exact = target_exact.lower()
            if compare_path != target_exact and compare_canonical != target_exact:
                return False

        # Check prefix
        if pattern.prefix is not None:
            target_prefix = pattern.prefix.replace("\\", "/")
            if not case_sensitive:
                target_prefix = target_prefix.lower()
            if not (compare_path.startswith(target_prefix) or compare_canonical.startswith(target_prefix)):
                return False

        # Check contains
        if pattern.contains is not None:
            target_contains = pattern.contains.replace("\\", "/")
            if not case_sensitive:
                target_contains = target_contains.lower()
            if target_contains not in compare_path and target_contains not in compare_canonical:
                return False

        # Check any_of
        if pattern.any_of is not None:
            targets = [p.replace("\\", "/") if case_sensitive else p.replace("\\", "/").lower() for p in pattern.any_of]
            if compare_path not in targets and compare_canonical not in targets:
                return False

        return True

    @classmethod
    def _path_glob_or_match(cls, norm_path: str, glob_pattern: str, case_sensitive: bool) -> bool:
        """Internal helper for path glob matching with ~ expansion and dot-file handling."""
        pat = glob_pattern.replace("\\", "/")
        if not case_sensitive:
            pat = pat.lower()
            norm_path = norm_path.lower()

        # Handle tilde patterns like ~/.ssh/* or ~/.aws/*
        if pat.startswith("~/"):
            suffix = pat[2:]  # e.g. .ssh/* or .aws/*
            # Matches if path ends with /.ssh/... or contains /.ssh/... or starts with expanded home
            if (
                fnmatch.fnmatch(norm_path, f"*/{suffix}")
                or fnmatch.fnmatch(norm_path, f"*\\{suffix}")
                or norm_path.endswith(f"/{suffix.rstrip('*')}")
                or f"/{suffix.rstrip('*')}" in norm_path
                or fnmatch.fnmatch(norm_path, os.path.expanduser(pat).replace("\\", "/"))
            ):
                return True

        # Standard glob match
        if fnmatch.fnmatch(norm_path, pat):
            return True

        # Check if matching against base filename
        base_name = os.path.basename(norm_path)
        if fnmatch.fnmatch(base_name, pat):
            return True

        return False

    @classmethod
    def matches_shell(
        cls,
        command_str: str,
        pattern: Union[ShellPattern, StringPattern, str],
        security_state: Optional[SecurityState] = None,
        _is_subcommand: bool = False,
    ) -> bool:
        """
        Evaluates a shell command string against safety profiles and string patterns.
        Automatically decomposes compound command pipelines (;, &&, ||, |, &, $(), ``)
        to prevent command injection evasion.
        """
        cmd = command_str.strip()

        # If this is a compound command and not already evaluating subcommands,
        # decompose it and check if any constituent subcommand triggers the rule.
        if not _is_subcommand:
            subcmds = CommandPipelineParser.decompose(cmd)
            if len(subcmds) > 1:
                for sc in subcmds:
                    if cls.matches_shell(sc.raw, pattern, security_state=security_state, _is_subcommand=True):
                        return True

        if isinstance(pattern, str):
            return cls.matches_string_pattern(cmd, pattern)

        if isinstance(pattern, StringPattern):
            return cls.matches_string_pattern(cmd, pattern)

        # Pipe to shell detection (e.g. curl | bash)
        if pattern.pipe_to_shell is not None:
            has_pipe = bool(cls.PIPE_TO_SHELL_PATTERN.search(cmd))
            if has_pipe != pattern.pipe_to_shell:
                return False

        # Destructive command check
        if pattern.destructive is not None:
            is_destr = any(p.search(cmd) for p in cls._deterministic_classifier.DESTRUCTIVE_SHELL_PATTERNS)
            if is_destr != pattern.destructive:
                return False

        # Privileged command check
        if pattern.privileged is not None:
            is_priv = any(p.search(cmd) for p in cls._deterministic_classifier.PRIVILEGED_SHELL_PATTERNS)
            if is_priv != pattern.privileged:
                return False

        # Network command check
        if pattern.network is not None:
            is_net = any(p.search(cmd) for p in cls._deterministic_classifier.NETWORK_SHELL_PATTERNS)
            if is_net != pattern.network:
                return False

        # Inner command string pattern
        if pattern.command is not None:
            if not cls.matches_string_pattern(cmd, pattern.command):
                return False

        return True

    @classmethod
    def matches_network(
        cls,
        url_or_host: str,
        pattern: Union[NetworkPattern, StringPattern, str],
        security_state: Optional[SecurityState] = None,
    ) -> bool:
        """Evaluates a network target against domain lists, CIDR blocks, or sensitive checks."""
        raw_target = url_or_host.strip()

        if isinstance(pattern, str):
            return cls.matches_string_pattern(raw_target, pattern)

        if isinstance(pattern, StringPattern):
            return cls.matches_string_pattern(raw_target, pattern)

        # Extract host and port
        host, port = cls._extract_host_and_port(raw_target)

        # 1. Sensitive endpoints check (IMDS / localhost / private IP)
        if pattern.sensitive_only is not None:
            is_sensitive = cls._is_sensitive_host(host)
            if is_sensitive != pattern.sensitive_only:
                return False

        # 2. Unknown destination check
        if pattern.unknown_only is not None:
            is_trusted = cls._is_trusted_host(host)
            is_sensitive = cls._is_sensitive_host(host)
            is_unknown = not is_trusted and not is_sensitive
            if is_unknown != pattern.unknown_only:
                return False

        # 3. Domains
        if pattern.domains is not None:
            matched_domain = any(cls.matches_string_pattern(host, d) for d in pattern.domains)
            if not matched_domain:
                return False

        # 4. URLs
        if pattern.urls is not None:
            matched_url = any(cls.matches_string_pattern(raw_target, u) for u in pattern.urls)
            if not matched_url:
                return False

        # 5. IP CIDR ranges
        if pattern.ip_ranges is not None:
            try:
                ip = ipaddress.ip_address(host)
                matched_cidr = False
                for cidr in pattern.ip_ranges:
                    if ip in ipaddress.ip_network(cidr, strict=False):
                        matched_cidr = True
                        break
                if not matched_cidr:
                    return False
            except ValueError:
                # Host is a domain name, not an IP literal
                return False

        # 6. Ports
        if pattern.ports is not None:
            if port not in pattern.ports:
                return False

        return True

    @classmethod
    def matches_git(
        cls,
        event: Event,
        pattern: Union[GitPattern, str],
    ) -> bool:
        """Evaluates git operations and branches."""
        act_str = (
            event.action.value
            if (event.action is not None and hasattr(event.action, "value"))
            else str(event.action or "")
        )
        op_val = (getattr(event, "operation", None) or event.metadata.get("operation") or act_str).lower()

        branch_val = getattr(event, "branch", None) or event.metadata.get("branch") or event.target

        if isinstance(pattern, str):
            return op_val == pattern.lower() or cls.matches_string_pattern(str(branch_val), pattern)

        if pattern.operations is not None:
            allowed_ops = {o.lower() for o in pattern.operations}
            if op_val not in allowed_ops:
                return False

        if pattern.branches is not None:
            if not branch_val:
                return False
            matched_branch = any(cls.matches_string_pattern(str(branch_val), b) for b in pattern.branches)
            if not matched_branch:
                return False

        return True

    @classmethod
    def matches_process(
        cls,
        cmd_or_exec: str,
        pattern: Union[ProcessPattern, StringPattern, str],
    ) -> bool:
        """Evaluates process command line or executable name."""
        if isinstance(pattern, (str, StringPattern)):
            return cls.matches_string_pattern(cmd_or_exec, pattern)

        if pattern.command_line is not None:
            if not cls.matches_string_pattern(cmd_or_exec, pattern.command_line):
                return False

        if pattern.executable is not None:
            exe_name = os.path.basename(cmd_or_exec.split()[0]) if cmd_or_exec else ""
            if not cls.matches_string_pattern(exe_name, pattern.executable):
                return False

        return True

    @classmethod
    def matches_credential(
        cls,
        event: Event,
        pattern: Union[CredentialPattern, str],
    ) -> bool:
        """Evaluates credential type and target."""
        cred_type = getattr(event, "credential_type", None) or event.metadata.get("credential_type", "")
        target = str(event.target or "")

        if isinstance(pattern, str):
            return cred_type.lower() == pattern.lower() or cls.matches_string_pattern(target, pattern)

        if pattern.credential_types is not None:
            allowed = {c.lower() for c in pattern.credential_types}
            if str(cred_type).lower() not in allowed:
                return False

        if pattern.target is not None:
            if not cls.matches_string_pattern(target, pattern.target):
                return False

        return True

    @classmethod
    def matches_tool(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        pattern: Union[ToolPattern, str],
    ) -> bool:
        """Evaluates tool name and argument filters."""
        if isinstance(pattern, str):
            return tool_name.lower() == pattern.lower()

        if pattern.names is not None:
            allowed = {n.lower() for n in pattern.names}
            if tool_name.lower() not in allowed:
                return False

        if pattern.arguments is not None:
            for k, expected_v in pattern.arguments.items():
                if k not in arguments or arguments[k] != expected_v:
                    return False

        return True

    @classmethod
    def matches_agent(
        cls,
        event: Event,
        pattern: Union[AgentPattern, str],
    ) -> bool:
        """Evaluates agent ID or role archetype."""
        agent_id = event.agent_id
        agent_type = getattr(event, "agent_type", None) or (
            getattr(event.context, "agent_type", None) if event.context else None
        )
        agent_type_str = (
            agent_type.value if (agent_type is not None and hasattr(agent_type, "value")) else str(agent_type or "")
        ).lower()

        if isinstance(pattern, str):
            return agent_id == pattern or agent_type_str == pattern.lower()

        if pattern.agent_ids is not None:
            if agent_id not in pattern.agent_ids:
                return False

        if pattern.agent_types is not None:
            allowed = {t.lower() for t in pattern.agent_types}
            if agent_type_str not in allowed:
                return False

        return True

    @classmethod
    def _extract_host_and_port(cls, url: str) -> Tuple[str, Optional[int]]:
        """Extracts the host string and optional port number."""
        target = url.strip()
        if "://" not in target and not target.startswith("//"):
            target = "//" + target
        try:
            parsed = urllib.parse.urlsplit(target)
            host = (parsed.hostname or parsed.netloc.split(":")[0]).lower()
            port = parsed.port
            return host, port
        except Exception:
            return target.split(":")[0].lower(), None

    @classmethod
    def _is_sensitive_host(cls, host: str) -> bool:
        """Checks if host is an IMDS metadata endpoint, loopback, or private RFC1918 IP."""
        if host in cls._deterministic_classifier.sensitive_hosts:
            return True
        if host in NetworkDestinationValidator.METADATA_HOSTS or host in NetworkDestinationValidator.LOCAL_HOSTNAMES:
            return True
        parsed_ip = NetworkDestinationValidator._parse_ip(host)
        if parsed_ip is not None:
            return parsed_ip.is_loopback or parsed_ip.is_private or parsed_ip.is_link_local or parsed_ip.is_unspecified
        return False

    @classmethod
    def _is_trusted_host(cls, host: str) -> bool:
        """Checks if host is in the trusted domain set."""
        for trusted in cls._deterministic_classifier.trusted_domains:
            trusted_lower = trusted.lower()
            if host == trusted_lower or host.endswith("." + trusted_lower):
                return True
        return False
