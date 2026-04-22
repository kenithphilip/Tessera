"""tessera.ssrf_guard: deny outbound URLs that resolve to internal targets.

A URL is unsafe to fetch when it resolves (after parsing, decoding, and
DNS) to any of: loopback, RFC1918 private space, link-local, cloud
metadata endpoints, or other special-use ranges. The naive checks (look
at the hostname string, deny if it starts with "10.") miss every
interesting attack: decimal-encoded IPs, octal/hex octets, IPv4-mapped
IPv6, hostnames that resolve to private space (DNS rebinding pinning).

This module is a checker, not an HTTP client. It returns a verdict;
the caller decides whether to fetch. If the caller follows redirects,
it MUST re-check after each hop, otherwise an attacker controlling a
public endpoint can 302 to ``http://169.254.169.254/`` and bypass the
front-door check.

What the defaults block
-----------------------
- Schemes outside ``{http, https}``. This kills ``file://``, ``ftp://``,
  ``gopher://``, ``dict://``, ``ldap://``, ``jar:``, etc.
- IPv4: 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10 (CGNAT), 127.0.0.0/8,
  169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
  192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
  224.0.0.0/4, 240.0.0.0/4.
- IPv6: ::/128, ::1/128, 100::/64, 2001::/23, 2001:db8::/32, fc00::/7,
  fe80::/10, ff00::/8.
- Cloud metadata IPs get a more specific rule_id when matched directly.

What the defaults do NOT cover
------------------------------
- Public-but-sensitive endpoints (your cloud's public IP that hosts an
  admin panel). Add those via ``blocked_hostnames`` or run in
  ``allowlist_hostnames`` mode.
- Time-of-check / time-of-use races against the underlying HTTP client.
  The caller's HTTP stack must use the same resolver path or pin the
  resolved IP it dialed.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from tessera.scanners import ScanFinding, ScanResult


# ---------------------------------------------------------------------------
# Default blocked CIDRs and cloud metadata IPs
# ---------------------------------------------------------------------------


_DEFAULT_BLOCKED_CIDRS_V4: tuple[str, ...] = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
)

_DEFAULT_BLOCKED_CIDRS_V6: tuple[str, ...] = (
    "::/128",
    "::1/128",
    "100::/64",
    "2001::/23",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)

_CIDR_CATEGORY: dict[str, str] = {
    "0.0.0.0/8": "this_network",
    "10.0.0.0/8": "private_ip",
    "100.64.0.0/10": "cgnat",
    "127.0.0.0/8": "loopback",
    "169.254.0.0/16": "link_local",
    "172.16.0.0/12": "private_ip",
    "192.0.0.0/24": "ietf_protocol",
    "192.0.2.0/24": "documentation",
    "192.168.0.0/16": "private_ip",
    "198.18.0.0/15": "benchmark",
    "198.51.100.0/24": "documentation",
    "203.0.113.0/24": "documentation",
    "224.0.0.0/4": "multicast",
    "240.0.0.0/4": "reserved",
    "::/128": "unspecified",
    "::1/128": "loopback",
    "100::/64": "discard",
    "2001::/23": "ietf_protocol",
    "2001:db8::/32": "documentation",
    "fc00::/7": "unique_local",
    "fe80::/10": "link_local",
    "ff00::/8": "multicast",
}

# IPs that are specifically known cloud metadata endpoints. The CIDR
# check would catch these too, but a specific rule_id is more useful
# for audit and triage. Order matters: more specific labels first.
_CLOUD_METADATA_IPS: tuple[tuple[str, str], ...] = (
    ("169.254.169.254", "aws_gcp_azure_oci"),
    ("100.100.100.200", "alibaba"),
    ("fd00:ec2::254", "aws_ipv6"),
)

_DEFAULT_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# A loose URL detector for the scan() entry point. Strict validation
# happens in check_url(); this just filters which strings are worth
# checking. Anchored on scheme to avoid false positives on prose.
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'<>`]+")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SSRFFinding:
    """One reason a URL was rejected.

    Attributes:
        rule_id: Stable id for audit logs (``ssrf.loopback``,
            ``ssrf.cloud_metadata.aws_gcp_azure_oci``, ...).
        category: Coarse grouping (``private_ip``, ``loopback``,
            ``link_local``, ``cloud_metadata``, ``scheme``, ...).
        message: Human-readable explanation.
        url: The URL that was checked.
        resolved_ip: The IP the URL resolved to, when applicable.
        arg_path: Where in the args structure the URL came from.
    """

    rule_id: str
    category: str
    message: str
    url: str
    resolved_ip: str | None = None
    arg_path: str = ""


@dataclass(frozen=True)
class SSRFCheckResult:
    """Verdict for a single URL or a collection of args."""

    allowed: bool
    findings: tuple[SSRFFinding, ...] = field(default_factory=tuple)
    source: str = "tessera.ssrf_guard"

    @property
    def primary_reason(self) -> str:
        if self.allowed or not self.findings:
            return ""
        f = self.findings[0]
        return f"{f.rule_id}: {f.message}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _try_parse_ip(host: str) -> ipaddress._BaseAddress | None:
    """Parse ``host`` as an IPv4 or IPv6 literal in any common encoding.

    Accepts standard dotted IPv4, bracketed or bare IPv6, decimal
    integer (``"2130706433"``), hex integer (``"0x7f000001"``), and
    dotted-quad with octal or hex octets (``"0177.0.0.1"``,
    ``"0x7f.0.0.1"``). Returns the canonical address object, or None
    if the host doesn't look like an IP literal.
    """
    if not host:
        return None
    h = host.strip("[]")
    # Standard form (handles IPv6 with zone id when stripped, IPv4
    # dotted-quad, etc.).
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    # Pure decimal integer (e.g. "2130706433" == 127.0.0.1).
    if h.isdigit():
        try:
            n = int(h)
            if 0 <= n <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(n)
        except (ValueError, ipaddress.AddressValueError):
            pass
    # Hex integer ("0x7f000001").
    if h.lower().startswith("0x"):
        try:
            n = int(h, 16)
            if 0 <= n <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(n)
        except (ValueError, ipaddress.AddressValueError):
            pass
    # Dotted-quad with non-decimal octets ("0177.0.0.1", "0x7f.0.0.1").
    parts = h.split(".")
    if len(parts) == 4:
        try:
            octets: list[int] = []
            for p in parts:
                if not p:
                    raise ValueError("empty octet")
                if p.lower().startswith("0x"):
                    octets.append(int(p, 16))
                elif p.startswith("0") and len(p) > 1:
                    octets.append(int(p, 8))
                else:
                    octets.append(int(p))
            if all(0 <= o <= 255 for o in octets):
                return ipaddress.IPv4Address(
                    ".".join(str(o) for o in octets)
                )
        except ValueError:
            pass
    return None


def _default_resolver(host: str) -> list[str]:
    """Resolve ``host`` to a list of IP strings via socket.getaddrinfo.

    Returns both IPv4 and IPv6 results (deduplicated, original order
    preserved). Raises whatever the underlying resolver raises; the
    guard converts that into a deny finding.
    """
    import socket
    seen: list[str] = []
    for entry in socket.getaddrinfo(host, None):
        sockaddr = entry[4]
        ip = sockaddr[0] if sockaddr else None
        if ip and ip not in seen:
            seen.append(ip)
    return seen


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------


class SSRFGuard:
    """Decide whether a URL is safe to fetch.

    Args:
        allowed_schemes: URL schemes that may pass. Default
            ``{"http", "https"}``.
        blocked_cidrs: Extra CIDRs to block in addition to the defaults.
        replace_default_cidrs: Pass True with ``blocked_cidrs`` to
            replace the defaults entirely.
        blocked_hostnames: Hostnames denied without resolution. Useful
            for blocking specific public endpoints.
        allowlist_hostnames: When non-None, switches to deny-by-default;
            only hostnames in this set may pass (after IP checks).
        resolver: Callable mapping hostname -> list of IP strings. The
            default uses ``socket.getaddrinfo`` for both v4 and v6.
            Inject a fake one in tests.
    """

    name = "tessera.ssrf_guard"

    def __init__(
        self,
        *,
        allowed_schemes: Iterable[str] = _DEFAULT_ALLOWED_SCHEMES,
        blocked_cidrs: Iterable[str] | None = None,
        replace_default_cidrs: bool = False,
        blocked_hostnames: Iterable[str] | None = None,
        allowlist_hostnames: Iterable[str] | None = None,
        resolver: Callable[[str], list[str]] | None = None,
    ) -> None:
        self._allowed_schemes = frozenset(s.lower() for s in allowed_schemes)
        cidr_strs: list[str] = []
        if not replace_default_cidrs:
            cidr_strs.extend(_DEFAULT_BLOCKED_CIDRS_V4)
            cidr_strs.extend(_DEFAULT_BLOCKED_CIDRS_V6)
        if blocked_cidrs:
            cidr_strs.extend(blocked_cidrs)
        self._blocked_cidrs: tuple[ipaddress._BaseNetwork, ...] = tuple(
            ipaddress.ip_network(c, strict=False) for c in cidr_strs
        )
        self._cidr_str_lookup: dict[str, str] = {
            str(net): _CIDR_CATEGORY.get(str(net), "blocked_cidr")
            for net in self._blocked_cidrs
        }
        self._blocked_hostnames: frozenset[str] = (
            frozenset(h.lower() for h in blocked_hostnames)
            if blocked_hostnames else frozenset()
        )
        self._allowlist_hostnames: frozenset[str] | None = (
            frozenset(h.lower() for h in allowlist_hostnames)
            if allowlist_hostnames is not None else None
        )
        self._resolver = resolver or _default_resolver
        self._cloud_metadata_ips: tuple[
            tuple[ipaddress._BaseAddress, str], ...
        ] = tuple(
            (ipaddress.ip_address(ip), label)
            for ip, label in _CLOUD_METADATA_IPS
        )

    def check_url(
        self,
        url: str,
        *,
        arg_path: str = "",
    ) -> SSRFCheckResult:
        """Check a single URL string. See module docstring for what's blocked."""
        if not url or not isinstance(url, str):
            return SSRFCheckResult(
                allowed=False,
                findings=(SSRFFinding(
                    rule_id="ssrf.malformed_url",
                    category="malformed",
                    message="URL is empty or non-string",
                    url=str(url) if url is not None else "",
                    arg_path=arg_path,
                ),),
            )

        try:
            parsed = urlparse(url)
        except Exception as e:  # noqa: BLE001
            return SSRFCheckResult(
                allowed=False,
                findings=(SSRFFinding(
                    rule_id="ssrf.malformed_url",
                    category="malformed",
                    message=f"unparseable URL: {type(e).__name__}: {e}",
                    url=url, arg_path=arg_path,
                ),),
            )

        scheme = (parsed.scheme or "").lower()
        if scheme not in self._allowed_schemes:
            return SSRFCheckResult(
                allowed=False,
                findings=(SSRFFinding(
                    rule_id=f"ssrf.scheme.{scheme or 'empty'}",
                    category="scheme",
                    message=(
                        f"scheme not allowed: {scheme!r} "
                        f"(allowed: {sorted(self._allowed_schemes)})"
                    ),
                    url=url, arg_path=arg_path,
                ),),
            )

        try:
            host = parsed.hostname
        except Exception:
            host = None
        if not host:
            return SSRFCheckResult(
                allowed=False,
                findings=(SSRFFinding(
                    rule_id="ssrf.no_host",
                    category="malformed",
                    message="URL has no host component",
                    url=url, arg_path=arg_path,
                ),),
            )

        host_lc = host.lower()

        if host_lc in self._blocked_hostnames:
            return SSRFCheckResult(
                allowed=False,
                findings=(SSRFFinding(
                    rule_id="ssrf.blocked_hostname",
                    category="hostname_denylist",
                    message=f"hostname is in deny list: {host_lc}",
                    url=url, arg_path=arg_path,
                ),),
            )

        # Direct IP literal: skip DNS, check the IP we can already see.
        # This catches decimal/hex/octal-encoded forms that bypass naive
        # string checks.
        direct_ip = _try_parse_ip(host)
        if direct_ip is not None:
            finding = self._check_ip(direct_ip, url, arg_path)
            if finding is not None:
                return SSRFCheckResult(allowed=False, findings=(finding,))
            # The hostname-allowlist still applies even for IP literals;
            # if the operator ran in allowlist mode, raw IPs should not
            # bypass it.
            if (
                self._allowlist_hostnames is not None
                and host_lc not in self._allowlist_hostnames
            ):
                return SSRFCheckResult(
                    allowed=False,
                    findings=(SSRFFinding(
                        rule_id="ssrf.not_in_allowlist",
                        category="hostname_allowlist",
                        message=f"host not in allowlist: {host_lc}",
                        url=url, resolved_ip=str(direct_ip),
                        arg_path=arg_path,
                    ),),
                )
            return SSRFCheckResult(allowed=True)

        # Hostname (not an IP literal). Allowlist applies before resolution.
        if (
            self._allowlist_hostnames is not None
            and host_lc not in self._allowlist_hostnames
        ):
            return SSRFCheckResult(
                allowed=False,
                findings=(SSRFFinding(
                    rule_id="ssrf.not_in_allowlist",
                    category="hostname_allowlist",
                    message=f"hostname not in allowlist: {host_lc}",
                    url=url, arg_path=arg_path,
                ),),
            )

        # Resolve and check every returned IP. Fail closed on resolver
        # errors; an attacker who can break our DNS should not get a
        # green light.
        try:
            ips = self._resolver(host)
        except Exception as e:  # noqa: BLE001
            return SSRFCheckResult(
                allowed=False,
                findings=(SSRFFinding(
                    rule_id="ssrf.resolution_failed",
                    category="resolution",
                    message=(
                        f"hostname resolution failed: "
                        f"{type(e).__name__}: {e}"
                    ),
                    url=url, arg_path=arg_path,
                ),),
            )

        if not ips:
            return SSRFCheckResult(
                allowed=False,
                findings=(SSRFFinding(
                    rule_id="ssrf.resolution_empty",
                    category="resolution",
                    message=f"hostname did not resolve: {host}",
                    url=url, arg_path=arg_path,
                ),),
            )

        bad: list[SSRFFinding] = []
        for ip_str in ips:
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                bad.append(SSRFFinding(
                    rule_id="ssrf.invalid_resolution",
                    category="resolution",
                    message=f"resolver returned non-IP: {ip_str!r}",
                    url=url, resolved_ip=ip_str, arg_path=arg_path,
                ))
                continue
            finding = self._check_ip(ip, url, arg_path)
            if finding is not None:
                bad.append(finding)

        if bad:
            return SSRFCheckResult(allowed=False, findings=tuple(bad))
        return SSRFCheckResult(allowed=True)

    def _check_ip(
        self,
        ip: ipaddress._BaseAddress,
        url: str,
        arg_path: str,
    ) -> SSRFFinding | None:
        """Return a finding if ``ip`` is blocked, else None."""
        # Unwrap IPv4-mapped IPv6 (::ffff:127.0.0.1 etc.) so the v4
        # CIDR list catches it.
        if isinstance(ip, ipaddress.IPv6Address):
            mapped = ip.ipv4_mapped
            if mapped is not None:
                ip = mapped
        # Specific cloud metadata IPs first.
        for meta_ip, label in self._cloud_metadata_ips:
            if ip == meta_ip:
                return SSRFFinding(
                    rule_id=f"ssrf.cloud_metadata.{label}",
                    category="cloud_metadata",
                    message=f"cloud metadata endpoint: {ip} ({label})",
                    url=url,
                    resolved_ip=str(ip),
                    arg_path=arg_path,
                )
        # Then the CIDR deny list.
        for net in self._blocked_cidrs:
            if ip.version != net.version:
                continue
            if ip in net:
                category = self._cidr_str_lookup.get(str(net), "blocked_cidr")
                return SSRFFinding(
                    rule_id=f"ssrf.{category}",
                    category=category,
                    message=f"IP in blocked range {net}: {ip}",
                    url=url,
                    resolved_ip=str(ip),
                    arg_path=arg_path,
                )
        return None

    def scan(
        self,
        *,
        tool_name: str,
        args: Any,
        trajectory_id: str = "",
    ) -> ScanResult:
        """Walk ``args`` for URL-shaped strings and check each one.

        Implements the :class:`tessera.scanners.Scanner` protocol so this
        guard composes with the rest of the scanner suite.
        """
        findings: list[ScanFinding] = []
        for path, text in _flatten_args(args):
            for match in _URL_RE.finditer(text):
                url = match.group(0)
                result = self.check_url(url, arg_path=path)
                if result.allowed:
                    continue
                for f in result.findings:
                    findings.append(ScanFinding(
                        rule_id=f.rule_id,
                        severity="high",
                        message=f.message,
                        arg_path=f.arg_path or path,
                        evidence=url[:200],
                        metadata={
                            "category": f.category,
                            "resolved_ip": f.resolved_ip,
                        },
                    ))
        return ScanResult(
            scanner=self.name,
            allowed=not findings,
            findings=tuple(findings),
        )


def _flatten_args(
    args: str | Mapping[str, Any] | Sequence[Any] | Any,
    prefix: str = "",
) -> Iterable[tuple[str, str]]:
    """Yield ``(arg_path, text)`` pairs over nested args."""
    if args is None:
        return
    if isinstance(args, str):
        yield (prefix or "$", args)
        return
    if isinstance(args, (bytes, bytearray)):
        try:
            yield (prefix or "$", bytes(args).decode("utf-8", errors="replace"))
        except Exception:
            return
        return
    if isinstance(args, Mapping):
        for k, v in args.items():
            child = f"{prefix}.{k}" if prefix else str(k)
            yield from _flatten_args(v, child)
        return
    if isinstance(args, (list, tuple)):
        for i, v in enumerate(args):
            child = f"{prefix}[{i}]" if prefix else f"[{i}]"
            yield from _flatten_args(v, child)
        return
    try:
        yield (prefix or "$", json.dumps(args, default=str))
    except Exception:
        yield (prefix or "$", str(args))


__all__ = [
    "SSRFFinding",
    "SSRFCheckResult",
    "SSRFGuard",
]
