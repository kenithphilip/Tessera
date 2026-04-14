"""gRPC Aggregated Discovery Service server.

Wraps the HTTP/SSE XDSServer to serve the same resources over gRPC
bidirectional streaming. Shares one XDSServer instance with the HTTP/SSE
path, so both transports stay consistent with no duplication of state.

The AggregatedDiscoveryService implements two RPCs:

    FetchResources  (unary)             - state-of-the-world snapshot
    StreamResources (bidirectional)     - subscribe and receive pushes

StreamResources reads the first DiscoveryRequest to learn which type URL
to subscribe to, sends an initial snapshot, then pushes every update the
XDSServer emits. Client ACKs and NACKs are intentionally not processed in
this initial implementation (full delta-xDS is a v0.2 item).

Disconnect safety: the subscribe loop uses asyncio.wait_for with a 1-second
timeout so it can periodically check context.done() instead of blocking
forever on queue.get() after the client disconnects.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncIterator

import grpc
import grpc.aio

from tessera.xds.v1 import discovery_pb2
from tessera.xds.v1 import discovery_pb2_grpc
from tessera.xds.server import DiscoveryResponse, XDSServer


def _to_proto(snapshot: DiscoveryResponse) -> discovery_pb2.DiscoveryResponse:
    """Convert a Python DiscoveryResponse to the proto message."""
    wrappers = [
        discovery_pb2.ResourceWrapper(
            name=r.name,
            version=r.version,
            resource=json.dumps(r.resource, separators=(",", ":")).encode(),
        )
        for r in snapshot.resources
    ]
    return discovery_pb2.DiscoveryResponse(
        version_info=snapshot.version_info,
        type_url=snapshot.type_url,
        resources=wrappers,
        nonce=snapshot.nonce,
    )


class _Servicer(discovery_pb2_grpc.AggregatedDiscoveryServiceServicer):
    """gRPC ADS servicer backed by XDSServer."""

    def __init__(self, xds_server: XDSServer) -> None:
        self._xds = xds_server

    async def FetchResources(
        self,
        request: discovery_pb2.DiscoveryRequest,
        context: grpc.aio.ServicerContext,
    ) -> discovery_pb2.DiscoveryResponse:
        """Return a state-of-the-world snapshot for the requested type."""
        snapshot = self._xds.get_snapshot(request.resource_type)
        return _to_proto(snapshot)

    async def StreamResources(
        self,
        request_iterator: AsyncIterator[discovery_pb2.DiscoveryRequest],
        context: grpc.aio.ServicerContext,
    ) -> None:
        """Subscribe to resource updates and push them to the client.

        Reads the first DiscoveryRequest to learn which type URL to subscribe
        to. Sends the current snapshot immediately, then pushes every update.
        """
        try:
            first = await request_iterator.__anext__()
        except StopAsyncIteration:
            return

        type_url = first.resource_type
        await context.write(_to_proto(self._xds.get_snapshot(type_url)))

        # Register a queue directly (same pattern as XDSServer.subscribe)
        # but with a timeout so we can detect client disconnect.
        queue: asyncio.Queue[DiscoveryResponse] = asyncio.Queue(maxsize=64)
        subscribers = self._xds._subscribers.setdefault(type_url, [])
        subscribers.append(queue)
        try:
            while not context.done():
                try:
                    update = await asyncio.wait_for(queue.get(), timeout=1.0)
                    await context.write(_to_proto(update))
                except asyncio.TimeoutError:
                    continue
        finally:
            subscribers.remove(queue)


class GRPCXDSServer:
    """Lifecycle wrapper for the gRPC ADS server.

    Designed to share one XDSServer instance with the HTTP/SSE path.

    Usage::

        xds = XDSServer()
        grpc_srv = GRPCXDSServer(xds)
        port = await grpc_srv.start("[::]:50051")
        # ... run ...
        await grpc_srv.stop()
    """

    def __init__(self, xds_server: XDSServer) -> None:
        self._xds = xds_server
        self._server: grpc.aio.Server | None = None

    async def start(self, address: str = "[::]:50051") -> int:
        """Start the gRPC server and return the bound port number.

        Passing address ``"[::]:0"`` lets the OS choose a free port, which
        is useful in tests.
        """
        self._server = grpc.aio.server()
        discovery_pb2_grpc.add_AggregatedDiscoveryServiceServicer_to_server(
            _Servicer(self._xds), self._server
        )
        port = self._server.add_insecure_port(address)
        await self._server.start()
        return port

    async def stop(self, grace: float = 5.0) -> None:
        """Gracefully stop the gRPC server."""
        if self._server is not None:
            await self._server.stop(grace)
            self._server = None
