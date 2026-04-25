"""Trust tiers for MCP servers.

Each registered MCP server falls into one of three tiers based on
the quality of evidence behind it:

- :class:`TrustTier.COMMUNITY`: present in a public registry but
  no signed manifest. Treated as untrusted by default; tools may
  be invoked only with explicit user opt-in.
- :class:`TrustTier.VERIFIED`: ships a Sigstore-signed manifest
  whose subject digest matches the running artifact, but the
  signing identity is not on the operator's allowlist.
- :class:`TrustTier.ATTESTED`: signed manifest whose Fulcio cert's
  OIDC identity matches an operator-managed allowlist (e.g.
  ``https://github.com/anthropic-mcp/*``). The strictest tier.

Operators set the minimum acceptable tier via
``TESSERA_MCP_MIN_TIER`` or the ``--min-tier`` CLI flag. Tools from
servers below that tier are denied at policy evaluation time and
emit :attr:`tessera.events.EventKind.MCP_MANIFEST_SIG_INVALID`.

Reference
---------

- :mod:`tessera.mcp.manifest` (signing + verification)
- ``docs/strategy/2026-04-engineering-brief.md`` Section 3.3
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import IntEnum

from tessera.mcp.manifest import (
    SignedManifest,
    SigningMethod,
    VerificationResult,
    verify,
)


class TrustTier(IntEnum):
    """Tiers; numerically ordered most-permissive to most-strict."""

    COMMUNITY = 0
    VERIFIED = 1
    ATTESTED = 2


def get_min_tier() -> TrustTier:
    """Return the configured minimum tier from ``TESSERA_MCP_MIN_TIER``.

    Defaults to :attr:`TrustTier.COMMUNITY` (no enforcement) so the
    addition of trust tiers in v0.13 does not break existing
    deployments. Operators opt in by setting the env var.
    """
    raw = os.environ.get("TESSERA_MCP_MIN_TIER", "community").strip().lower()
    try:
        return TrustTier[raw.upper()]
    except KeyError:
        return TrustTier.COMMUNITY


@dataclass(frozen=True, slots=True)
class TierPolicy:
    """Per-tier policy knobs.

    Attributes:
        attested_identity_allowlist: Set of OIDC identity patterns
            that elevate a VERIFIED server to ATTESTED. Each entry
            is a glob (fnmatch) over the Fulcio cert's
            ``subjectAlternativeName`` URI.
        require_rekor_for_verified: When True, a SignedManifest
            without a Rekor inclusion proof cannot reach the
            VERIFIED tier even if its signature checks out.
        community_tools_allowed: When False, tools from COMMUNITY-
            tier servers are denied outright. Default True so the
            tier system is opt-in.
    """

    attested_identity_allowlist: frozenset[str] = field(
        default_factory=frozenset
    )
    require_rekor_for_verified: bool = True
    community_tools_allowed: bool = True


_DEFAULT_POLICY = TierPolicy()


def set_default_policy(policy: TierPolicy) -> None:
    """Replace the process-wide default :class:`TierPolicy`."""
    global _DEFAULT_POLICY
    _DEFAULT_POLICY = policy


def get_default_policy() -> TierPolicy:
    return _DEFAULT_POLICY


@dataclass(frozen=True, slots=True)
class TierAssignment:
    """The tier assigned to one MCP server + the reason."""

    tier: TrustTier
    reason: str
    verification: VerificationResult | None = None


def _identity_matches_allowlist(
    identity: str | None, allowlist: frozenset[str]
) -> bool:
    """Return True when ``identity`` matches any allowlist glob.

    Globs use ``fnmatch`` semantics. ``None`` identity never matches.
    """
    if identity is None:
        return False
    if not allowlist:
        return False
    import fnmatch

    return any(fnmatch.fnmatchcase(identity, pat) for pat in allowlist)


def _extract_identity(manifest: SignedManifest) -> str | None:
    """Pull the signing identity from the first cert.

    Returns the SAN URI when present; falls back to the cert subject
    or None when the cert is absent (HMAC-only envelopes).
    """
    for sig in manifest.signatures:
        if sig.cert is None:
            continue
        # Real cert parsing happens via cryptography lib; for this
        # wave we expose the cert blob as the identity stand-in so
        # the allowlist matching API is exercised. Phase 2A.real
        # wires the cryptography-based parse.
        return f"cert:{sig.keyid}"
    return None


def assign_tier(
    manifest: SignedManifest,
    *,
    policy: TierPolicy | None = None,
    hmac_key: bytes | None = None,
    expected_subject_digests: dict[str, str] | None = None,
) -> TierAssignment:
    """Assign a :class:`TrustTier` to a :class:`SignedManifest`.

    The decision tree:

    1. If verification fails for any reason -> COMMUNITY tier with
       the failure reason.
    2. If verification succeeds but ``method == HMAC`` -> COMMUNITY
       (HMAC is only for tests / air-gapped paths; production
       deployments treat HMAC envelopes as community-grade).
    3. If verification succeeds with SIGSTORE method but no Rekor
       proof and ``require_rekor_for_verified`` is True ->
       COMMUNITY.
    4. If verification succeeds and the signing identity matches
       the allowlist -> ATTESTED. Otherwise -> VERIFIED.
    """
    chosen = policy or _DEFAULT_POLICY
    result = verify(
        manifest,
        hmac_key=hmac_key,
        expected_subject_digests=expected_subject_digests,
        require_rekor=chosen.require_rekor_for_verified
        and manifest.method == SigningMethod.SIGSTORE,
    )
    if not result:
        return TierAssignment(
            tier=TrustTier.COMMUNITY,
            reason=f"verification failed: {result.reason}",
            verification=result,
        )
    if manifest.method == SigningMethod.HMAC:
        return TierAssignment(
            tier=TrustTier.COMMUNITY,
            reason="hmac envelope is community-tier in production",
            verification=result,
        )
    if (
        chosen.require_rekor_for_verified
        and manifest.rekor is None
    ):
        return TierAssignment(
            tier=TrustTier.COMMUNITY,
            reason="missing Rekor inclusion proof",
            verification=result,
        )
    identity = _extract_identity(manifest)
    if _identity_matches_allowlist(
        identity, chosen.attested_identity_allowlist
    ):
        return TierAssignment(
            tier=TrustTier.ATTESTED,
            reason=f"identity {identity!r} matches allowlist",
            verification=result,
        )
    return TierAssignment(
        tier=TrustTier.VERIFIED,
        reason="signature valid; identity not in allowlist",
        verification=result,
    )


def tier_allows(
    assignment: TierAssignment, *, min_tier: TrustTier | None = None
) -> bool:
    """Return True when the assigned tier meets the minimum.

    Args:
        assignment: Output of :func:`assign_tier`.
        min_tier: The minimum acceptable tier. Defaults to
            :func:`get_min_tier` (which reads ``TESSERA_MCP_MIN_TIER``).

    Returns:
        True when the assigned tier is at or above the minimum.
    """
    threshold = min_tier if min_tier is not None else get_min_tier()
    if (
        threshold == TrustTier.COMMUNITY
        and not _DEFAULT_POLICY.community_tools_allowed
    ):
        # Community tools disabled even when threshold is COMMUNITY;
        # require >= VERIFIED.
        return assignment.tier >= TrustTier.VERIFIED
    return assignment.tier >= threshold


__all__ = [
    "TierAssignment",
    "TierPolicy",
    "TrustTier",
    "assign_tier",
    "get_default_policy",
    "get_min_tier",
    "set_default_policy",
    "tier_allows",
]
