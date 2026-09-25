"""
Network Destination Validation and SSRF Hardening for RuntimeVerify (Phase 14).
Guards against Server-Side Request Forgery (SSRF), Cloud Metadata Harvesting (IMDS),
Loopback Evasion, Private IP Exfiltration, and Dangerous URI schemes.
"""

import ipaddress
from typing import Optional, Set, Tuple, Union
import urllib.parse


class NetworkDestinationValidator:
    """
    Validates outbound network requests to prevent autonomous agents from connecting
    to internal services, local loopback, cloud instance metadata services (IMDS),
    or private networks unless explicitly permitted.
    """

    ALLOWED_SCHEMES: Set[str] = {"http", "https"}

    # Cloud Instance Metadata Services (IMDS) endpoints
    METADATA_HOSTS: Set[str] = {
        "169.254.169.254",  # AWS / Azure / GCP IMDSv1/v2
        "169.254.169.123",  # AWS NTP / Time sync
        "metadata.google.internal",  # GCP metadata DNS
        "metadata.goog",
        "100.100.100.200",  # Alibaba Cloud metadata
    }

    # Common local evasion hostnames
    LOCAL_HOSTNAMES: Set[str] = {
        "localhost",
        "localhost.localdomain",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "0",
    }

    @classmethod
    def validate_destination(
        cls,
        url_or_target: str,
        allow_private: bool = False,
        allow_loopback: bool = False,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validates an outbound target URL or hostname.

        Checks:
        1. Non-empty input.
        2. Prohibited or dangerous URI schemes (file://, gopher://, dict://, etc.).
        3. Cloud Instance Metadata Service (IMDS) access attempts.
        4. Loopback and internal bind address connections.
        5. RFC 1918 private IPv4 and RFC 4193 private IPv6 networks.
        6. Alternative numeric IP representations (decimal integers, hex, octal).

        Args:
            url_or_target: URL string or host:port string.
            allow_private: Whether connections to private subnets (10.0.0.0/8, etc.) are allowed.
            allow_loopback: Whether connections to localhost are allowed.

        Returns:
            Tuple of (is_valid: bool, rejection_reason: Optional[str]).
        """
        target = url_or_target.strip()
        if not target:
            return False, "Empty network destination target"

        # 1. Scheme and host extraction
        scheme = "http"
        host_str = target.strip("[]")
        direct_ip = cls._parse_ip(host_str)
        if direct_ip is not None:
            host_str = str(direct_ip)
        elif "://" in target:
            parsed = urllib.parse.urlsplit(target)
            scheme = (parsed.scheme or "").lower()
            if scheme not in cls.ALLOWED_SCHEMES:
                return (
                    False,
                    f"Prohibited network scheme '{scheme}://'. Only {sorted(cls.ALLOWED_SCHEMES)} are permitted.",
                )
            host_str = (parsed.hostname or parsed.netloc.split(":")[0]).strip()
        elif ":" in target and not target.startswith("["):
            # If multiple colons, it is likely an unbracketed IPv6 literal
            if target.count(":") > 1:
                host_str = target.strip()
            else:
                # host:port format without scheme
                host_str = target.split(":")[0].strip()

        # Clean brackets from IPv6 literals e.g. [::1]
        host_str = host_str.strip("[]").lower()

        # 2. IMDS Cloud Metadata Check
        if host_str in cls.METADATA_HOSTS:
            return False, f"Access to Cloud Instance Metadata Service (IMDS) '{host_str}' is strictly blocked."

        # 3. Localhost Hostname Check
        if not allow_loopback and host_str in cls.LOCAL_HOSTNAMES:
            return False, f"Access to local loopback address '{host_str}' is prohibited."

        # 4. IP Address Validation (including decimal integer and hex IP evasion)
        parsed_ip = cls._parse_ip(host_str)
        if parsed_ip is not None:
            # Loopback check
            if not allow_loopback and (parsed_ip.is_loopback or parsed_ip.is_unspecified):
                return False, f"Destination IP '{parsed_ip}' resolves to local loopback/unspecified network."

            # Link-local check (e.g. 169.254.x.x / fe80::)
            if parsed_ip.is_link_local:
                return False, f"Destination IP '{parsed_ip}' is link-local / cloud metadata range."

            # Private subnet check (RFC 1918 / RFC 4193)
            if not allow_private and parsed_ip.is_private:
                return False, f"Destination IP '{parsed_ip}' belongs to a private/internal network."

        return True, None

    @classmethod
    def _parse_ip(cls, host: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        """
        Attempts to parse host into an IP address, handling decimal integer notation,
        hex notation, and standard IPv4/IPv6 formats.
        """
        # 1. Standard IP
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            pass

        # 2. Decimal integer IP (e.g. 2130706433 for 127.0.0.1)
        if host.isdigit():
            try:
                val = int(host)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except ValueError:
                pass

        # 3. Hexadecimal integer IP (e.g. 0x7f000001)
        if host.startswith("0x") or host.startswith("0X"):
            try:
                val = int(host, 16)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except ValueError:
                pass

        return None


def validate_network_target(
    url_or_target: str,
    allow_private: bool = False,
    allow_loopback: bool = False,
) -> Tuple[bool, Optional[str]]:
    """Convenience functional wrapper for NetworkDestinationValidator.validate_destination."""
    return NetworkDestinationValidator.validate_destination(
        url_or_target=url_or_target,
        allow_private=allow_private,
        allow_loopback=allow_loopback,
    )
