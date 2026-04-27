"""Shared fixtures + helpers for the adapter conformance suite."""

from __future__ import annotations

import sys
import types
from collections.abc import Iterator
from typing import Any

import pytest

from tessera.events import SecurityEvent, clear_sinks, register_sink
from tessera.policy import Policy
from tessera.labels import TrustLevel

KEY = b"conformance-suite-key"
PRINCIPAL = "conformance-test-user"


def make_policy(deny_tool: str | None = None) -> Policy:
    """Return a Policy that denies ``deny_tool`` from any USER context.

    Setting ``require=SYSTEM`` makes the requirement unsatisfiable from
    the USER-trusted context Tessera adapters create on session start,
    so any call to ``deny_tool`` is denied even on a clean context.
    """
    policy = Policy()
    if deny_tool:
        policy.require(deny_tool, TrustLevel.SYSTEM)
    return policy


@pytest.fixture
def captured_events() -> Iterator[list[SecurityEvent]]:
    """Drain Tessera SecurityEvents into a list. Auto-cleans on teardown."""
    clear_sinks()
    bucket: list[SecurityEvent] = []
    register_sink(bucket.append)
    yield bucket
    clear_sinks()


def stub_module(name: str, **attrs: Any) -> types.ModuleType:
    """Inject a stubbed module into sys.modules. Idempotent.

    Returns the existing module if one is already registered (so
    repeat calls in the same test don't shadow real installs).
    """
    if name in sys.modules:
        return sys.modules[name]
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    sys.modules[name] = mod
    return mod


def import_adapter(adapter_module_path: str, class_name: str):
    """Force re-import of an adapter module after stubs are in place.

    Adapter modules cache the success of their framework import at
    module load time, so once they've been imported with the real
    framework available, subsequent stubbing is a no-op. Pop the
    module from sys.modules first to force the import-time check
    to run again.
    """
    sys.modules.pop(adapter_module_path, None)
    module = __import__(adapter_module_path, fromlist=[class_name])
    return getattr(module, class_name)


def assert_method_signature(cls, method_name: str, *required_params: str) -> None:
    """Assert that ``cls.method_name`` has at least ``required_params``.

    Order does not matter; positional and keyword params both count.
    Used to detect a future framework version dropping a parameter
    that the adapter relies on receiving.
    """
    import inspect

    method = getattr(cls, method_name, None)
    assert method is not None, f"{cls.__name__} has no method {method_name!r}"
    sig = inspect.signature(method)
    actual = set(sig.parameters.keys())
    missing = set(required_params) - actual
    assert not missing, (
        f"{cls.__name__}.{method_name} is missing parameters: {missing!r}; "
        f"actual: {sorted(actual)!r}"
    )
