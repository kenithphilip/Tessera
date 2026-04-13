"""xDS client for agents to receive policy updates.

Fetches state-of-the-world snapshots and subscribes to SSE
streams for push updates from the xDS server.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import httpx


class XDSClient:
    """Client for the Tessera xDS resource distribution server."""

    def __init__(self, server_url: str, timeout: float = 10.0) -> None:
        self._server_url = server_url.rstrip("/")
        self._timeout = timeout

    async def fetch(self, type_url: str) -> dict[str, Any]:
        """Fetch current state of the world for a resource type."""
        url = f"{self._server_url}/xds/v1/{type_url}"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()

    async def subscribe(
        self, type_url: str, callback: Callable[[dict[str, Any]], None]
    ) -> None:
        """Subscribe to resource updates via SSE.

        Calls ``callback`` with each parsed DiscoveryResponse dict.
        Runs until the connection drops or the server closes the stream.
        """
        url = f"{self._server_url}/xds/v1/{type_url}/subscribe"
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("GET", url) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if line.startswith("data: "):
                        payload = json.loads(line[6:])
                        callback(payload)
