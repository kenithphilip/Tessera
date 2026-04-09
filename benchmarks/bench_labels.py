"""Benchmarks for ``tessera.labels``.

Measures HMAC sign and verify against both short and long content. The
signing path is what every inbound context segment goes through at the
proxy, so its per-call cost bounds the minimum overhead Tessera can impose.
"""

from __future__ import annotations

from tessera.labels import (
    Origin,
    TrustLabel,
    TrustLevel,
    sign_label,
    verify_label,
)

KEY = b"0" * 32
SHORT_CONTENT = "hello, world. " * 8  # ~112 bytes
LONG_CONTENT = "x" * 10_000  # 10 KB

_BASE_LABEL = TrustLabel(
    origin=Origin.WEB,
    principal="user@example.com",
    trust_level=TrustLevel.UNTRUSTED,
)

_SIGNED_SHORT = sign_label(_BASE_LABEL, SHORT_CONTENT, KEY)
_SIGNED_LONG = sign_label(_BASE_LABEL, LONG_CONTENT, KEY)


def _sign_short() -> None:
    sign_label(_BASE_LABEL, SHORT_CONTENT, KEY)


def _sign_long() -> None:
    sign_label(_BASE_LABEL, LONG_CONTENT, KEY)


def _verify_short() -> None:
    verify_label(_SIGNED_SHORT, SHORT_CONTENT, KEY)


def _verify_long() -> None:
    verify_label(_SIGNED_LONG, LONG_CONTENT, KEY)


BENCHMARKS = [
    ("sign_label, 112 B content", _sign_short),
    ("sign_label, 10 KB content", _sign_long),
    ("verify_label, 112 B content", _verify_short),
    ("verify_label, 10 KB content", _verify_long),
]
