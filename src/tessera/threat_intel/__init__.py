"""tessera.threat_intel

Structured threat-intelligence feed schema for known-bad MCP server URIs,
prompt injection signatures, and risky model fingerprints.

Feed *hosting* is out of scope per ADR-0002. This package defines only
the schema and a reference consumer. AgentMesh Cloud may host a live feed
against this schema.

Typical usage::

    from tessera.threat_intel import validate_feed, ThreatIntelFeed

    with open("my_feed.json") as f:
        feed: ThreatIntelFeed = validate_feed(f.read())

    for ioc in feed.iocs:
        print(ioc.kind, ioc.value, ioc.confidence)
"""

from __future__ import annotations

from tessera.threat_intel.schema import (
    IOC,
    IOCKind,
    InjectionPattern,
    MaliciousMcpServer,
    ModelFingerprint,
    ThreatIntelFeed,
    feed_schema_v1,
    validate_feed,
)

__all__ = [
    "IOC",
    "IOCKind",
    "InjectionPattern",
    "MaliciousMcpServer",
    "ModelFingerprint",
    "ThreatIntelFeed",
    "feed_schema_v1",
    "validate_feed",
]
