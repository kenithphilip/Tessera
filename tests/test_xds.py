"""Tests for xDS resource distribution server and client."""

from __future__ import annotations

import asyncio
import json

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tessera.xds.resources import (
    PolicyBundleResource,
    ToolRegistryEntryResource,
    ToolRegistryResource,
    ToolRequirementResource,
    TrustConfigResource,
)
from tessera.xds.server import (
    TYPE_POLICY_BUNDLE,
    TYPE_TOOL_REGISTRY,
    XDSServer,
)


# -- Resource serialization --------------------------------------------------


def test_policy_bundle_resource_serialization() -> None:
    bundle = PolicyBundleResource(
        version="1",
        revision="rev-abc",
        requirements=(
            ToolRequirementResource(name="send_email", resource_type="tool", required_trust=100),
        ),
        default_trust_level=50,
        human_approval_tools=("delete_account",),
    )
    as_dict = bundle.to_dict()
    roundtripped = PolicyBundleResource.from_dict(as_dict)
    assert roundtripped == bundle

    as_json = bundle.to_json()
    from_json = PolicyBundleResource.from_json(as_json)
    assert from_json == bundle


def test_tool_registry_resource_serialization() -> None:
    registry = ToolRegistryResource(
        version="1",
        revision="rev-def",
        tools=(
            ToolRegistryEntryResource(name="web_search", is_external=True),
            ToolRegistryEntryResource(name="calculator", is_external=False),
        ),
    )
    as_dict = registry.to_dict()
    roundtripped = ToolRegistryResource.from_dict(as_dict)
    assert roundtripped == registry

    as_json = registry.to_json()
    from_json = ToolRegistryResource.from_json(as_json)
    assert from_json == registry


def test_trust_config_resource_serialization() -> None:
    config = TrustConfigResource(
        version="1",
        revision="rev-ghi",
        trust_levels={"user": 100, "tool": 50, "untrusted": 0},
    )
    as_dict = config.to_dict()
    roundtripped = TrustConfigResource.from_dict(as_dict)
    assert roundtripped == config


# -- XDSServer unit tests ----------------------------------------------------


def test_xds_server_set_and_get_resource() -> None:
    server = XDSServer()
    resource = {"name": "test-policy", "default_trust_level": 100}
    server.set_resource(TYPE_POLICY_BUNDLE, "default", resource)

    snapshot = server.get_snapshot(TYPE_POLICY_BUNDLE)
    assert len(snapshot.resources) == 1
    assert snapshot.resources[0].name == "default"
    assert snapshot.resources[0].resource == resource
    assert snapshot.version_info != ""


def test_xds_server_version_increments_on_update() -> None:
    server = XDSServer()
    server.set_resource(TYPE_POLICY_BUNDLE, "default", {"v": 1})
    v1 = server.get_snapshot(TYPE_POLICY_BUNDLE).version_info

    server.set_resource(TYPE_POLICY_BUNDLE, "default", {"v": 2})
    v2 = server.get_snapshot(TYPE_POLICY_BUNDLE).version_info

    assert v1 != v2, "Version must change when resource content changes"


def test_xds_server_version_stable_for_same_content() -> None:
    server = XDSServer()
    server.set_resource(TYPE_POLICY_BUNDLE, "default", {"v": 1})
    v1 = server.get_snapshot(TYPE_POLICY_BUNDLE).version_info

    # Set same content again.
    server.set_resource(TYPE_POLICY_BUNDLE, "default", {"v": 1})
    v2 = server.get_snapshot(TYPE_POLICY_BUNDLE).version_info

    assert v1 == v2, "Version must be stable for identical content"


# -- HTTP endpoint tests (via TestClient) ------------------------------------


def _make_app_with_xds() -> tuple[FastAPI, XDSServer]:
    app = FastAPI()
    server = XDSServer()
    server.add_to_app(app)
    return app, server


def test_xds_server_fetch_resources_returns_snapshot() -> None:
    app, server = _make_app_with_xds()
    server.set_resource(TYPE_POLICY_BUNDLE, "default", {"trust": 100})

    client = TestClient(app)
    resp = client.get(f"/xds/v1/{TYPE_POLICY_BUNDLE}")
    assert resp.status_code == 200

    body = resp.json()
    assert body["type_url"] == TYPE_POLICY_BUNDLE
    assert len(body["resources"]) == 1
    assert body["resources"][0]["name"] == "default"
    assert body["resources"][0]["resource"]["trust"] == 100
    assert body["version_info"] != ""
    assert body["nonce"] != ""


def test_xds_client_fetch_from_server() -> None:
    """Use TestClient as a stand-in for httpx to verify the fetch path."""
    app, server = _make_app_with_xds()
    server.set_resource(TYPE_TOOL_REGISTRY, "tools", {"tools": ["a", "b"]})

    client = TestClient(app)
    resp = client.get(f"/xds/v1/{TYPE_TOOL_REGISTRY}")
    assert resp.status_code == 200

    body = resp.json()
    assert body["type_url"] == TYPE_TOOL_REGISTRY
    assert len(body["resources"]) == 1
    assert body["resources"][0]["resource"]["tools"] == ["a", "b"]


def test_xds_fetch_empty_type_returns_empty_resources() -> None:
    app, _server = _make_app_with_xds()
    client = TestClient(app)
    resp = client.get("/xds/v1/unknown.type")
    assert resp.status_code == 200
    body = resp.json()
    assert body["resources"] == []
    assert body["version_info"] == ""


# -- gRPC ADS tests ----------------------------------------------------------


@pytest.fixture()
async def grpc_server_and_stub() -> tuple:
    """Start a gRPC ADS server on a free port and return (server, stub, xds)."""
    grpc = pytest.importorskip("grpc")
    grpc_aio = pytest.importorskip("grpc.aio")

    from tessera.xds.v1 import discovery_pb2_grpc as pb2_grpc
    from tessera.xds.grpc_server import GRPCXDSServer

    xds = XDSServer()
    srv = GRPCXDSServer(xds)
    port = await srv.start("[::]:0")

    channel = grpc_aio.insecure_channel(f"localhost:{port}")
    stub = pb2_grpc.AggregatedDiscoveryServiceStub(channel)

    yield stub, xds

    await channel.close()
    await srv.stop(grace=0.5)


async def test_grpc_fetch_empty_type(grpc_server_and_stub: tuple) -> None:
    """FetchResources on an unknown type returns an empty resource list."""
    from tessera.xds.v1 import discovery_pb2 as pb2

    stub, _xds = grpc_server_and_stub
    response = await stub.FetchResources(
        pb2.DiscoveryRequest(resource_type="unknown.type")
    )
    assert response.version_info == ""
    assert len(response.resources) == 0


async def test_grpc_fetch_resources(grpc_server_and_stub: tuple) -> None:
    """FetchResources returns the current state for a known type."""
    from tessera.xds.v1 import discovery_pb2 as pb2

    stub, xds = grpc_server_and_stub
    xds.set_resource(TYPE_POLICY_BUNDLE, "default", {"trust": 100})

    response = await stub.FetchResources(
        pb2.DiscoveryRequest(resource_type=TYPE_POLICY_BUNDLE)
    )
    assert response.type_url == TYPE_POLICY_BUNDLE
    assert response.version_info != ""
    assert len(response.resources) == 1
    assert response.resources[0].name == "default"
    payload = json.loads(response.resources[0].resource)
    assert payload == {"trust": 100}


async def test_grpc_stream_initial_snapshot(grpc_server_and_stub: tuple) -> None:
    """StreamResources delivers the current snapshot as the first message."""
    from tessera.xds.v1 import discovery_pb2 as pb2

    stub, xds = grpc_server_and_stub
    xds.set_resource(TYPE_TOOL_REGISTRY, "tools", {"tools": ["a", "b"]})

    async def request_gen():
        yield pb2.DiscoveryRequest(resource_type=TYPE_TOOL_REGISTRY)
        # Keep the stream open briefly so the initial snapshot can arrive.
        await asyncio.sleep(0.2)

    stream = stub.StreamResources(request_gen())
    first = await stream.read()
    stream.cancel()

    assert first.type_url == TYPE_TOOL_REGISTRY
    assert len(first.resources) == 1
    assert first.resources[0].name == "tools"


async def test_grpc_stream_receives_update(grpc_server_and_stub: tuple) -> None:
    """StreamResources pushes updates when the resource store changes."""
    from tessera.xds.v1 import discovery_pb2 as pb2

    stub, xds = grpc_server_and_stub
    xds.set_resource(TYPE_POLICY_BUNDLE, "policy", {"v": 1})

    async def request_gen():
        yield pb2.DiscoveryRequest(resource_type=TYPE_POLICY_BUNDLE)
        await asyncio.sleep(1.0)  # keep stream alive for the update

    stream = stub.StreamResources(request_gen())

    # Read initial snapshot.
    initial = await stream.read()
    assert json.loads(initial.resources[0].resource) == {"v": 1}

    # Push an update and verify it arrives on the stream.
    xds.set_resource(TYPE_POLICY_BUNDLE, "policy", {"v": 2})
    update = await asyncio.wait_for(stream.read(), timeout=3.0)
    assert json.loads(update.resources[0].resource) == {"v": 2}

    stream.cancel()
