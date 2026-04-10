"""Delegation tokens for binding user intent to an agent session.

A DelegationToken is a small, content-bound credential that says one
principal delegated a bounded set of actions to one agent for one
audience and session until a specific expiry time. This module provides
the v0 symmetric signing path via HMAC-SHA256 so the proxy and policy
layer can fail closed before richer OAuth or JWT-based profiles land.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any


def _utc(value: datetime) -> datetime:
    """Normalize datetimes to timezone-aware UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class DelegationToken:
    """A signed delegation from one principal to one agent.

    The signature covers the delegating subject, delegated agent, target
    audience, authorized actions, constraints, session identifier, and
    expiry. Verification also enforces expiry and, when supplied, the
    expected audience.
    """

    subject: str
    delegate: str
    audience: str
    authorized_actions: tuple[str, ...] = field(default_factory=tuple)
    constraints: dict[str, Any] = field(default_factory=dict)
    session_id: str = ""
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    signature: str = ""

    def canonical(self) -> bytes:
        """Return the deterministic bytes covered by the signature."""
        payload = {
            "subject": self.subject,
            "delegate": self.delegate,
            "audience": self.audience,
            "authorized_actions": sorted(self.authorized_actions),
            "constraints": self.constraints,
            "session_id": self.session_id,
            "expires_at": _utc(self.expires_at).isoformat(),
        }
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return True when the token is expired at the given time."""
        effective_now = _utc(now or datetime.now(timezone.utc))
        return effective_now >= _utc(self.expires_at)


def sign_delegation(token: DelegationToken, key: bytes) -> DelegationToken:
    """Return a signed copy of the delegation token."""
    mac = hmac.new(key, token.canonical(), sha256).hexdigest()
    return replace(token, signature=mac)


def verify_delegation(
    token: DelegationToken,
    key: bytes,
    *,
    audience: str | None = None,
    now: datetime | None = None,
) -> bool:
    """Return True only for a valid, unexpired token with matching audience.

    Verification fails closed for missing signatures, wrong keys, expired
    tokens, tampered fields, or audience mismatches.
    """
    if not token.signature:
        return False
    if token.is_expired(now):
        return False
    if audience is not None and token.audience != audience:
        return False
    expected = hmac.new(key, token.canonical(), sha256).hexdigest()
    return hmac.compare_digest(expected, token.signature)
