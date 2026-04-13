"""Tests for xDS resource distribution server and client."""

from __future__ import annotations

import json

import pytest
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
