"""Audit-log surface (canonical JSON, hash-chained sink)."""

from __future__ import annotations

from tessera_rs._native import (
    JsonlHashchainSink,
    audit_canonical_json as canonical_json,
    make_replay_detail,
)

__all__ = ["JsonlHashchainSink", "canonical_json", "make_replay_detail"]
