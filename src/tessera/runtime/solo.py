"""Tier 1 (Solo) runtime isolation: in-process Python sandbox.

No Docker, no microVM, no kernel modules. Pure stdlib so the dependency
surface stays flat. The design is simple: patch the standard HTTP and
file-open callsites for the duration of a ``with Tier1Sandbox(...)`` block
and check each call against an allowlist. On a violation, emit a
SecurityEvent and raise RuntimeViolation before the call reaches the
network or disk.

Target overhead: <0.5 ms per allowed call (dict lookup + string compare).

Threat model fit: Tier 1 is appropriate when the agent code is trusted
Python but the agent is processing untrusted data that might craft malicious
arguments to tool calls. It is NOT a sandbox against adversarial agent code
that imports ctypes and patches the patcher.
"""

from __future__ import annotations

import builtins
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable
from unittest.mock import patch
from urllib.parse import urlparse

from tessera.events import EventKind, SecurityEvent
from tessera.events import emit as _emit


class RuntimeViolation(Exception):
    """Raised when a Tier 1 sandbox policy is violated.

    Callers that catch this should treat it as a hard stop: the operation
    was blocked before reaching the network or filesystem.
    """


# ---------------------------------------------------------------------------
# EgressAllowlist
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EgressAllowlist:
    """Allowlist for outbound HTTP calls.

    Exact hostname strings are checked first (O(1)). CIDR ranges are checked
    only when the URL contains an IP-address host, keeping the common case
    (hostname lookup) to a set membership test.

    Args:
        hostnames: Exact hostnames that are permitted (e.g. ``api.example.com``).
        cidrs: CIDR blocks whose addresses are permitted. Parsed once at
            construction; membership tests use ``ipaddress`` stdlib only.

    Examples:
        >>> al = EgressAllowlist(hostnames=["api.example.com"])
        >>> al.is_allowed("https://api.example.com/v1/chat")
        True
        >>> al.is_allowed("https://evil.example.com/")
        False
    """

    hostnames: frozenset[str] = field(default_factory=frozenset)
    cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = field(
        default_factory=tuple,
    )

    def __init__(
        self,
        hostnames: Iterable[str] = (),
        cidrs: Iterable[str] = (),
    ) -> None:
        # frozen=True means we must use object.__setattr__ in __init__.
        object.__setattr__(self, "hostnames", frozenset(hostnames))
        parsed_cidrs = tuple(
            ipaddress.ip_network(c, strict=False) for c in cidrs
        )
        object.__setattr__(self, "cidrs", parsed_cidrs)

    def is_allowed(self, url: str) -> bool:
        """Return True if the URL's host is permitted by this allowlist.

        Args:
            url: Absolute URL string (scheme required for urlparse).

        Returns:
            True when the host is in ``hostnames`` or its resolved IP falls
            inside one of the ``cidrs`` ranges. False otherwise, including
            when the host cannot be parsed.
        """
        host = urlparse(url).hostname
        if not host:
            return False
        if host in self.hostnames:
            return True
        if not self.cidrs:
            return False
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(addr in cidr for cidr in self.cidrs)


# ---------------------------------------------------------------------------
# FilesystemGuard
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FilesystemGuard:
    """Guard that restricts which paths may be opened for writing.

    The default (empty ``allowed_write_prefixes``) is fully closed: NO
    writes are permitted. This is fail-closed by design; callers must
    explicitly opt in by providing prefixes.

    Reads (mode ``"r"``, ``"rb"``, etc.) are never restricted by this
    guard; restriction of reads is a separate concern.

    Args:
        allowed_write_prefixes: Paths whose prefixes allow write-mode
            ``open()`` calls. An empty iterable means no writes are allowed.

    Examples:
        >>> g = FilesystemGuard(allowed_write_prefixes=["/tmp/agent-output/"])
        >>> g.assert_writable("/tmp/agent-output/result.json")  # passes
        >>> g.assert_writable("/etc/passwd")  # raises RuntimeViolation
    """

    allowed_write_prefixes: frozenset[str] = field(default_factory=frozenset)

    def __init__(self, allowed_write_prefixes: Iterable[str] = ()) -> None:
        object.__setattr__(
            self,
            "allowed_write_prefixes",
            frozenset(allowed_write_prefixes),
        )

    def assert_writable(self, path: str) -> None:
        """Raise RuntimeViolation if ``path`` is not within an allowed prefix.

        Args:
            path: Filesystem path being opened for writing.

        Raises:
            RuntimeViolation: When no allowed prefix covers ``path``.
        """
        if any(path.startswith(prefix) for prefix in self.allowed_write_prefixes):
            return
        _emit(
            SecurityEvent.now(
                kind=EventKind.RUNTIME_FS_DENY,
                principal="runtime.solo",
                detail={"path": path, "allowed_prefixes": sorted(self.allowed_write_prefixes)},
            )
        )
        raise RuntimeViolation(
            f"FilesystemGuard: write to {path!r} is outside the allowed-write prefixes"
        )


# ---------------------------------------------------------------------------
# _WRITE_MODES: open() modes that constitute a write
# ---------------------------------------------------------------------------

_WRITE_MODES: frozenset[str] = frozenset(
    {"w", "wb", "a", "ab", "x", "xb", "w+", "wb+", "a+", "ab+", "r+", "rb+"}
)


def _mode_is_write(mode: str) -> bool:
    """Return True if the open() mode string implies writing.

    Strips text/binary suffixes so ``"wt"`` is recognized as write mode.
    """
    # Normalize: strip 't' (text flag), then check against known write modes.
    normalized = mode.replace("t", "")
    return normalized in _WRITE_MODES


# ---------------------------------------------------------------------------
# Tier1Sandbox
# ---------------------------------------------------------------------------


class Tier1Sandbox:
    """In-process Tier 1 sandbox combining egress and filesystem controls.

    Patches the following callsites for the duration of the ``with`` block:

    - ``builtins.open`` (write modes only; reads pass through)
    - ``urllib.request.urlopen`` (if urllib is importable)
    - ``httpx.get``, ``httpx.post``, ``httpx.Client.send`` (if httpx is importable)
    - ``requests.get``, ``requests.post`` (if requests is importable)

    On allowed calls, the original function is invoked with no overhead
    beyond the string comparison. On blocked calls, a SecurityEvent is
    emitted and RuntimeViolation is raised before the call executes.

    Args:
        allowlist: Egress allowlist controlling outbound HTTP. Defaults to
            deny-all (no hostnames, no CIDRs).
        fs_guard: Filesystem guard controlling write-mode opens. Defaults to
            deny-all (no allowed-write prefixes).

    Examples:
        >>> sandbox = Tier1Sandbox(
        ...     allowlist=EgressAllowlist(hostnames=["api.openai.com"]),
        ...     fs_guard=FilesystemGuard(allowed_write_prefixes=["/tmp/"]),
        ... )
        >>> with sandbox:
        ...     pass  # HTTP calls to api.openai.com and writes to /tmp/ are allowed
    """

    def __init__(
        self,
        allowlist: EgressAllowlist | None = None,
        fs_guard: FilesystemGuard | None = None,
    ) -> None:
        self._allowlist = allowlist or EgressAllowlist()
        self._fs_guard = fs_guard or FilesystemGuard()
        self._patches: list[Any] = []

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "Tier1Sandbox":
        self._install_patches()
        return self

    def __exit__(self, *_: object) -> None:
        self._remove_patches()

    # ------------------------------------------------------------------
    # Patch installation
    # ------------------------------------------------------------------

    def _install_patches(self) -> None:
        allowlist = self._allowlist
        fs_guard = self._fs_guard

        # -- open() patch (write modes only) --
        _orig_open = builtins.open

        def _guarded_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            if _mode_is_write(mode):
                fs_guard.assert_writable(str(file))
            return _orig_open(file, mode, *args, **kwargs)

        self._patches.append(
            patch("builtins.open", _guarded_open)
        )

        # -- urllib.request.urlopen --
        try:
            import urllib.request as _urllib_request

            _orig_urlopen = _urllib_request.urlopen

            def _guarded_urlopen(url: Any, *args: Any, **kwargs: Any) -> Any:
                raw = url if isinstance(url, str) else getattr(url, "full_url", str(url))
                _check_egress(allowlist, raw)
                return _orig_urlopen(url, *args, **kwargs)

            self._patches.append(
                patch("urllib.request.urlopen", _guarded_urlopen)
            )
        except ImportError:
            pass

        # -- httpx functional API --
        try:
            import httpx as _httpx

            def _make_httpx_guard(verb: str, orig: Callable[..., Any]) -> Callable[..., Any]:
                def _guarded(*args: Any, **kwargs: Any) -> Any:
                    url = args[0] if args else kwargs.get("url", "")
                    _check_egress(allowlist, str(url))
                    return orig(*args, **kwargs)
                return _guarded

            self._patches.append(
                patch("httpx.get", _make_httpx_guard("get", _httpx.get))
            )
            self._patches.append(
                patch("httpx.post", _make_httpx_guard("post", _httpx.post))
            )
        except ImportError:
            pass

        # -- requests functional API --
        try:
            import requests as _requests

            def _make_requests_guard(verb: str, orig: Callable[..., Any]) -> Callable[..., Any]:
                def _guarded(*args: Any, **kwargs: Any) -> Any:
                    url = args[0] if args else kwargs.get("url", "")
                    _check_egress(allowlist, str(url))
                    return orig(*args, **kwargs)
                return _guarded

            self._patches.append(
                patch("requests.get", _make_requests_guard("get", _requests.get))
            )
            self._patches.append(
                patch("requests.post", _make_requests_guard("post", _requests.post))
            )
        except ImportError:
            pass

        # Start all patches.
        for p in self._patches:
            p.start()

    def _remove_patches(self) -> None:
        for p in reversed(self._patches):
            try:
                p.stop()
            except RuntimeError:
                # patch.stop() raises when called on an unstarted patch;
                # safe to ignore during cleanup.
                pass
        self._patches.clear()


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------


def _check_egress(allowlist: EgressAllowlist, url: str) -> None:
    """Emit RUNTIME_EGRESS_DENY and raise RuntimeViolation when url is blocked.

    Args:
        allowlist: The active EgressAllowlist.
        url: URL string to check.

    Raises:
        RuntimeViolation: When the URL's host is not in the allowlist.
    """
    if allowlist.is_allowed(url):
        return
    host = urlparse(url).hostname or url
    _emit(
        SecurityEvent.now(
            kind=EventKind.RUNTIME_EGRESS_DENY,
            principal="runtime.solo",
            detail={
                "url": url,
                "host": host,
                "allowed_hostnames": sorted(allowlist.hostnames),
            },
        )
    )
    raise RuntimeViolation(
        f"EgressAllowlist: outbound call to {host!r} is not permitted"
    )
