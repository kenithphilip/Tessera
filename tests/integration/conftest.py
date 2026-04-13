from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip integration tests unless SPIFFE_ENDPOINT_SOCKET is set."""
    socket = os.environ.get("SPIFFE_ENDPOINT_SOCKET")
    if not socket:
        skip = pytest.mark.skip(reason="SPIFFE_ENDPOINT_SOCKET not set")
        for item in items:
            if "integration" in str(item.fspath):
                item.add_marker(skip)
