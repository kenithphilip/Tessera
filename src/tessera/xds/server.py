"""xDS-compatible resource distribution server.

Implements the Aggregated Discovery Service pattern with
state-of-the-world semantics. Resources are versioned with
content-addressed hashing (matching the control_plane.py
revision system).

Uses HTTP/JSON endpoints on the existing FastAPI control plane.
Subscriptions use Server-Sent Events (SSE) for push updates.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from typing import Any, AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse


# Well-known type URLs for Tessera xDS resources.
TYPE_POLICY_BUNDLE = "type.tessera.dev/tessera.xds.v1.PolicyBundle"
TYPE_TOOL_REGISTRY = "type.tessera.dev/tessera.xds.v1.ToolRegistry"
TYPE_TRUST_CONFIG = "type.tessera.dev/tessera.xds.v1.TrustConfig"


@dataclass(frozen=True)
class ResourceWrapper:
    """Single resource in a discovery response."""

    name: str
    version: str
    resource: dict[str, Any]


@dataclass(frozen=True)
class DiscoveryResponse:
    """State-of-the-world snapshot for a resource type."""

    version_info: str
    type_url: str
    resources: tuple[ResourceWrapper, ...]
    nonce: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "version_info": self.version_info,
            "type_url": self.type_url,
            "resources": [
                {"name": r.name, "version": r.version, "resource": r.resource}
                for r in self.resources
            ],
            "nonce": self.nonce,
        }


def _compute_version(resources: dict[str, Any]) -> str:
    """Content-addressed version derived from all resources of a type."""
    canonical = json.dumps(resources, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return f"xds-{digest[:16]}"


class XDSServer:
    """xDS resource distribution server.

    Stores resources by type URL and name, tracks versions, and
    notifies subscribers when resources change.
    """

    def __init__(self) -> None:
        self._resources: dict[str, dict[str, dict[str, Any]]] = {}
        self._versions: dict[str, str] = {}
        self._subscribers: dict[str, list[asyncio.Queue[DiscoveryResponse]]] = {}

    def set_resource(self, type_url: str, name: str, resource: dict[str, Any]) -> None:
        """Update a resource and notify subscribers."""
        if type_url not in self._resources:
            self._resources[type_url] = {}
        self._resources[type_url][name] = resource
        self._versions[type_url] = _compute_version(self._resources[type_url])

        snapshot = self.get_snapshot(type_url)
        for queue in self._subscribers.get(type_url, []):
            try:
                queue.put_nowait(snapshot)
            except asyncio.QueueFull:
                pass

    def get_snapshot(self, type_url: str) -> DiscoveryResponse:
        """Return current state-of-the-world for a resource type."""
        resources = self._resources.get(type_url, {})
        version = self._versions.get(type_url, "")
        wrappers = tuple(
            ResourceWrapper(name=name, version=version, resource=data)
            for name, data in sorted(resources.items())
        )
        return DiscoveryResponse(
            version_info=version,
            type_url=type_url,
            resources=wrappers,
            nonce=uuid.uuid4().hex[:16],
        )

    async def subscribe(self, type_url: str) -> AsyncIterator[DiscoveryResponse]:
        """Subscribe to resource updates. Yields snapshots on change."""
        queue: asyncio.Queue[DiscoveryResponse] = asyncio.Queue(maxsize=64)
        if type_url not in self._subscribers:
            self._subscribers[type_url] = []
        self._subscribers[type_url].append(queue)
        try:
            while True:
                response = await queue.get()
                yield response
        finally:
            self._subscribers[type_url].remove(queue)

    def add_to_app(self, app: FastAPI) -> None:
        """Mount xDS HTTP endpoints on an existing FastAPI app.

        GET  /xds/v1/{type_url:path}           - state of the world
        GET  /xds/v1/{type_url:path}/subscribe  - SSE stream for deltas
        """
        server = self

        @app.get("/xds/v1/{type_url:path}/subscribe")
        async def xds_subscribe(type_url: str, request: Request) -> StreamingResponse:
            async def event_stream() -> AsyncIterator[str]:
                # Send initial snapshot.
                snapshot = server.get_snapshot(type_url)
                yield f"data: {json.dumps(snapshot.to_dict())}\n\n"
                async for update in server.subscribe(type_url):
                    if await request.is_disconnected():
                        break
                    yield f"data: {json.dumps(update.to_dict())}\n\n"

            return StreamingResponse(
                event_stream(),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )

        @app.get("/xds/v1/{type_url:path}")
        async def xds_fetch(type_url: str) -> dict[str, Any]:
            snapshot = server.get_snapshot(type_url)
            return snapshot.to_dict()
