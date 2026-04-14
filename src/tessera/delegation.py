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


class DelegationNarrowingViolation(ValueError):
    """Raised when a child delegation attempts to widen parent scope."""


def narrow_delegation(
    parent: DelegationToken,
    *,
    delegate: str,
    authorized_actions: tuple[str, ...] | None = None,
    constraints: dict[str, Any] | None = None,
    expires_at: datetime | None = None,
    session_id: str = "",
) -> DelegationToken:
    """Create a child delegation that narrows the parent scope.

    Enforces monotonic narrowing:
    - Child authorized_actions must be a subset of parent's.
    - Child max_cost_usd constraint (if set) must not exceed parent's.
    - Child expires_at must not be later than parent's.
    - Parent's read_only constraint is sticky (cannot be removed).

    Args:
        parent: The parent delegation token.
        delegate: The agent receiving the narrowed delegation.
        authorized_actions: Subset of parent's actions. Defaults to parent's full set.
        constraints: Child constraints. Must not widen parent constraints.
        expires_at: Must be at or before parent's expiry.
        session_id: Session identifier for the child.

    Returns:
        An unsigned child DelegationToken.

    Raises:
        DelegationNarrowingViolation: If any constraint is widened.
    """
    child_actions = authorized_actions if authorized_actions is not None else parent.authorized_actions
    child_constraints = dict(constraints) if constraints else dict(parent.constraints)
    child_expires = expires_at if expires_at is not None else parent.expires_at

    # Actions must be a subset.
    parent_set = set(parent.authorized_actions)
    child_set = set(child_actions)
    if parent_set and not child_set.issubset(parent_set):
        extra = child_set - parent_set
        raise DelegationNarrowingViolation(
            f"child actions {extra} not in parent's authorized_actions"
        )

    # Expiry must not extend.
    if _utc(child_expires) > _utc(parent.expires_at):
        raise DelegationNarrowingViolation(
            "child expires_at cannot be later than parent's"
        )

    # max_cost_usd: cannot exceed parent's.
    parent_cost = parent.constraints.get("max_cost_usd")
    child_cost = child_constraints.get("max_cost_usd")
    if parent_cost is not None and child_cost is not None:
        if float(child_cost) > float(parent_cost):
            raise DelegationNarrowingViolation(
                f"child max_cost_usd ({child_cost}) exceeds parent's ({parent_cost})"
            )

    # read_only is sticky: if parent is read_only, child must be too.
    if parent.constraints.get("read_only"):
        child_constraints["read_only"] = True

    return DelegationToken(
        subject=parent.subject,
        delegate=delegate,
        audience=parent.audience,
        authorized_actions=tuple(sorted(child_actions)),
        constraints=child_constraints,
        session_id=session_id,
        expires_at=child_expires,
    )


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
