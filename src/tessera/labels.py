"""Signed provenance labels for context segments.

A TrustLabel is the unit of identity for content entering an LLM. Every
segment of context carries one, and the signature binds the label to the
exact bytes of the content. Tampering with either the content or the label
invalidates the signature.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass, field, replace
from enum import IntEnum, StrEnum
from hashlib import sha256


class Origin(StrEnum):
    """Where a segment of context came from."""

    USER = "user"
    SYSTEM = "system"
    TOOL = "tool"
    MEMORY = "memory"
    WEB = "web"


class TrustLevel(IntEnum):
    """Ordered trust levels. Higher values dominate lower in taint tracking.

    UNTRUSTED is for anything that could be attacker-controlled: scraped web
    pages, retrieved documents, arbitrary tool outputs. TOOL is for outputs
    from tools the operator has vetted. USER is reserved for instructions
    typed by the authenticated human principal. SYSTEM is for the operator's
    own system prompt.
    """

    UNTRUSTED = 0
    TOOL = 50
    USER = 100
    SYSTEM = 200


# Default origin -> trust level mapping. Override per-segment when needed.
DEFAULT_TRUST: dict[Origin, TrustLevel] = {
    Origin.WEB: TrustLevel.UNTRUSTED,
    Origin.MEMORY: TrustLevel.UNTRUSTED,
    Origin.TOOL: TrustLevel.TOOL,
    Origin.USER: TrustLevel.USER,
    Origin.SYSTEM: TrustLevel.SYSTEM,
}


@dataclass(frozen=True)
class TrustLabel:
    """Provenance label bound to a specific content blob by HMAC signature.

    The signature covers origin, principal, trust_level, nonce, and the
    SHA-256 of the content. Verifying a label requires the content it was
    issued for.
    """

    origin: Origin
    principal: str
    trust_level: TrustLevel
    nonce: str = field(default_factory=lambda: secrets.token_hex(16))
    signature: str = ""

    def canonical(self, content: str) -> bytes:
        """Return the bytes that the signature covers."""
        content_digest = sha256(content.encode("utf-8")).hexdigest()
        return (
            f"{self.origin}|{self.principal}|{int(self.trust_level)}|"
            f"{self.nonce}|{content_digest}"
        ).encode("utf-8")


def sign_label(label: TrustLabel, content: str, key: bytes) -> TrustLabel:
    """Return a copy of label with a fresh HMAC-SHA256 signature over content."""
    mac = hmac.new(key, label.canonical(content), sha256).hexdigest()
    return replace(label, signature=mac)


def verify_label(label: TrustLabel, content: str, key: bytes) -> bool:
    """Constant-time verification of a label against its content.

    Returns False for any mismatch: wrong content, wrong key, tampered label,
    or missing signature.
    """
    if not label.signature:
        return False
    expected = hmac.new(key, label.canonical(content), sha256).hexdigest()
    return hmac.compare_digest(expected, label.signature)
