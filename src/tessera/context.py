"""Labeled context segments and context assembly with spotlighting.

A Context is an ordered list of LabeledSegments. When rendered for an LLM,
untrusted regions are wrapped in explicit delimiters (spotlighting) so the
model sees a structural boundary between user instructions and scraped or
retrieved content. The real enforcement still happens in the policy engine,
but spotlighting is cheap defense-in-depth.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from typing import TYPE_CHECKING, Union

from tessera.labels import (
    DEFAULT_TRUST,
    Origin,
    TrustLabel,
    TrustLevel,
    sign_label,
    verify_label,
)

if TYPE_CHECKING:
    from tessera.signing import LabelSigner, LabelVerifier


@dataclass(frozen=True)
class LabeledSegment:
    """A chunk of content paired with its signed provenance label."""

    content: str
    label: TrustLabel

    def verify(self, key_or_verifier: "Union[bytes, bytearray, LabelVerifier]") -> bool:
        """Verify the label's signature.

        Accepts either an HMAC key (bytes, the v0 path) or any object
        satisfying the `LabelVerifier` protocol (JWTVerifier, JWKSVerifier,
        HMACVerifier, or a custom implementation).
        """
        if isinstance(key_or_verifier, (bytes, bytearray)):
            return verify_label(self.label, self.content, bytes(key_or_verifier))
        return key_or_verifier.verify(self.label, self.content)


def make_segment(
    content: str,
    origin: Origin,
    principal: str,
    key: "bytes | None" = None,
    trust_level: TrustLevel | None = None,
    signer: "LabelSigner | None" = None,
) -> LabeledSegment:
    """Construct a segment with a freshly signed label.

    Exactly one of `key` or `signer` must be provided.

    Args:
        content: The raw text.
        origin: Where the content came from.
        principal: The identity the content belongs to.
        key: HMAC key for the v0 symmetric signing path.
        trust_level: Override the default trust level for the origin.
        signer: Any object satisfying `LabelSigner` (JWTSigner,
            HMACSigner, or a custom implementation). Use this instead of
            `key` when a workload holds a JWT-SVID and needs asymmetric
            signing.

    Returns:
        A LabeledSegment whose label signature covers content + metadata.

    Raises:
        ValueError: if neither or both of `key` and `signer` are given.
    """
    if (key is None) == (signer is None):
        raise ValueError(
            "make_segment requires exactly one of `key` (HMAC) or `signer` (LabelSigner)"
        )
    level = trust_level if trust_level is not None else DEFAULT_TRUST[origin]
    label = TrustLabel(origin=origin, principal=principal, trust_level=level)
    if signer is not None:
        label = signer.sign(label, content)
    else:
        label = sign_label(label, content, key)  # type: ignore[arg-type]
    return LabeledSegment(content=content, label=label)


# Delimiters used for spotlighting untrusted regions. These are visible to the
# model so it can learn to treat bracketed regions as data, not instructions.
_OPEN = "<<<TESSERA-UNTRUSTED>>>"
_CLOSE = "<<<END-TESSERA-UNTRUSTED>>>"


@dataclass
class Context:
    """Ordered collection of labeled segments forming one LLM request.

    The max_trust and min_trust properties drive taint tracking: a tool call
    that runs over this context inherits the minimum trust level of any
    segment that could have influenced it.
    """

    segments: list[LabeledSegment] = field(default_factory=list)

    def add(self, segment: LabeledSegment) -> None:
        self.segments.append(segment)

    def verify_all(self, key: bytes) -> bool:
        """Every segment must verify against the key or the context is rejected."""
        return all(s.verify(key) for s in self.segments)

    @property
    def max_trust(self) -> TrustLevel:
        if not self.segments:
            return TrustLevel.SYSTEM
        return max(s.label.trust_level for s in self.segments)

    @property
    def min_trust(self) -> TrustLevel:
        """Lowest trust level across all segments. This is the taint ceiling."""
        if not self.segments:
            return TrustLevel.SYSTEM
        return min(s.label.trust_level for s in self.segments)

    @property
    def principal(self) -> str | None:
        """Principal of the first USER segment in the context, if any.

        Used by security event emission so denied tool calls and schema
        violations can be attributed to a human identity without
        threading the principal through every call site.
        """
        for seg in self.segments:
            if seg.label.origin == Origin.USER:
                return seg.label.principal
        return None

    def render(self) -> str:
        """Assemble the segments into a prompt with untrusted regions spotlit."""
        parts: list[str] = []
        for seg in self.segments:
            if seg.label.trust_level < TrustLevel.TOOL:
                parts.append(
                    f"{_OPEN} origin={seg.label.origin}\n"
                    f"{seg.content}\n"
                    f"{_CLOSE}"
                )
            else:
                parts.append(seg.content)
        return "\n\n".join(parts)
