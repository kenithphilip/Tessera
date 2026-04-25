"""Tessera threat-intel feed schema (Wave 2J).

Defines the Pydantic models for the structured threat-intelligence feed
format. The feed carries three IOC kinds:

- ``MaliciousMcpServer``: a known-bad MCP server URI.
- ``InjectionPattern``: a regex / substring / embedding signature for
  prompt injection.
- ``ModelFingerprint``: a known model that carries elevated risk.

Feed hosting is explicitly out of scope per ADR-0002. Tessera ships
only the schema and a reference consumer.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Discriminator, Field, Tag, field_validator, model_validator


class IOCKind(StrEnum):
    """Discriminator for IOC sub-types."""

    MCP_SERVER_URI = "MCP_SERVER_URI"
    INJECTION_PATTERN = "INJECTION_PATTERN"
    MODEL_FINGERPRINT = "MODEL_FINGERPRINT"


class IOC(BaseModel, frozen=True):
    """Base indicator-of-compromise record.

    Attributes:
        ioc_id: UUID string uniquely identifying this IOC.
        kind: Discriminator for the IOC sub-type.
        value: Canonical string value of the indicator (URI, pattern text,
            model name).
        confidence: Analyst confidence in this IOC, 0.0 (unknown) to 1.0
            (confirmed).
        first_seen: UTC timestamp of first observation.
        last_seen: UTC timestamp of most recent observation.
        tags: Free-form classification tags (e.g. ``{"apt29", "supply-chain"}``).
        source: Human-readable description of the feed maintainer or
            original data source.
    """

    # Strict mode is intentionally not set here; IOC records are
    # deserialised from JSON dicts where strings, lists, and datetime
    # ISO strings all need standard Pydantic coercion. Immutability is
    # enforced via frozen=True on the class declaration.

    ioc_id: str = Field(default_factory=lambda: str(uuid4()))
    kind: IOCKind
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    tags: frozenset[str] = Field(default_factory=frozenset)
    source: str

    @field_validator("tags", mode="before")
    @classmethod
    def _coerce_tags(cls, v: Any) -> frozenset[str]:
        if isinstance(v, (list, tuple, set, frozenset)):
            return frozenset(v)
        if v is None:
            return frozenset()
        raise ValueError("tags must be a list, tuple, set, or frozenset")

    @model_validator(mode="after")
    def _last_not_before_first(self) -> IOC:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not be before first_seen")
        return self


class MaliciousMcpServer(IOC, frozen=True):
    """IOC for a known-bad MCP server URI.

    Attributes:
        domain: Registered domain of the server (e.g. ``evil.example.com``).
        protocol: Transport protocol the server advertises.
    """

    kind: Literal[IOCKind.MCP_SERVER_URI] = IOCKind.MCP_SERVER_URI
    domain: str
    protocol: Literal["http", "https", "mcp+ws", "mcp+stdio"]


class InjectionPattern(IOC, frozen=True):
    """IOC for a prompt injection signature.

    Attributes:
        pattern_type: How ``pattern_value`` should be interpreted.
        pattern_value: The regex, literal substring, or embedding descriptor.
        mitre_atlas_techniques: Tuple of AML.T* technique IDs this pattern
            relates to.
    """

    kind: Literal[IOCKind.INJECTION_PATTERN] = IOCKind.INJECTION_PATTERN
    pattern_type: Literal["regex", "substring", "embedding"]
    pattern_value: str
    mitre_atlas_techniques: tuple[str, ...] = ()

    @field_validator("mitre_atlas_techniques", mode="before")
    @classmethod
    def _coerce_list(cls, v: Any) -> tuple[str, ...]:
        if isinstance(v, (list, tuple)):
            return tuple(v)
        raise ValueError("mitre_atlas_techniques must be a list or tuple")


class ModelFingerprint(IOC, frozen=True):
    """IOC for a model with known elevated risk.

    Attributes:
        model_family: Model family name (e.g. ``"gpt-4o"``).
        weight_hash: SHA-256 of the weight file if known, else None.
        provider: Hosting provider or registry (e.g. ``"openai"``).
        risk_class: Qualitative risk rating.
    """

    kind: Literal[IOCKind.MODEL_FINGERPRINT] = IOCKind.MODEL_FINGERPRINT
    model_family: str
    weight_hash: str | None = None
    provider: str | None = None
    risk_class: Literal["low", "medium", "high", "critical"]


class ThreatIntelFeed(BaseModel, frozen=True):
    """Container for a complete threat-intel feed snapshot.

    Attributes:
        schema_version: Fixed string ``"tessera.threat_intel.v1"`` for
            forward compatibility checks.
        generated_at: UTC timestamp when this snapshot was produced.
        feed_id: UUID string identifying this feed instance.
        maintainer: Human-readable name of the feed maintainer or publisher.
        iocs: Tuple of IOC records (any mix of sub-types).
        signatures: Map of key-id to public key material (PEM or JWK JSON)
            that the maintainer uses to sign feed bundles.
    """

    model_config = {"strict": False}  # allow discriminated union coercion

    schema_version: Literal["tessera.threat_intel.v1"] = "tessera.threat_intel.v1"
    generated_at: datetime
    feed_id: str = Field(default_factory=lambda: str(uuid4()))
    maintainer: str
    iocs: tuple[
        Annotated[
            Annotated[MaliciousMcpServer, Tag(IOCKind.MCP_SERVER_URI)]
            | Annotated[InjectionPattern, Tag(IOCKind.INJECTION_PATTERN)]
            | Annotated[ModelFingerprint, Tag(IOCKind.MODEL_FINGERPRINT)],
            Discriminator(lambda v: v.get("kind") if isinstance(v, dict) else getattr(v, "kind", None)),
        ],
        ...,
    ]
    signatures: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Schema export and validation helpers
# ---------------------------------------------------------------------------


def feed_schema_v1() -> dict[str, Any]:
    """Return the JSON Schema document for ``ThreatIntelFeed``.

    Returns:
        A dict containing the JSON Schema for the v1 feed format.

    Example::

        schema = feed_schema_v1()
        print(schema["title"])  # "ThreatIntelFeed"
    """
    return ThreatIntelFeed.model_json_schema()


def validate_feed(payload: dict[str, Any] | str | bytes) -> ThreatIntelFeed:
    """Deserialise and validate a feed payload.

    Accepts dict, JSON string, or raw bytes. Raises
    ``pydantic.ValidationError`` if the payload does not conform to the
    ``ThreatIntelFeed`` schema.

    Args:
        payload: The feed data as a Python dict, JSON string, or UTF-8 bytes.

    Returns:
        A fully-validated ``ThreatIntelFeed`` instance.

    Raises:
        pydantic.ValidationError: If the payload fails schema validation.
        ValueError: If ``payload`` is bytes and cannot be decoded as UTF-8.

    Example::

        with open("feed.json") as f:
            feed = validate_feed(f.read())
    """
    if isinstance(payload, bytes):
        payload = payload.decode()
    if isinstance(payload, str):
        payload = json.loads(payload)
    return ThreatIntelFeed.model_validate(payload)
