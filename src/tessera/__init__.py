"""Tessera: signed provenance labels and taint-tracking policy for LLM context."""

from tessera.context import Context, LabeledSegment, make_segment
from tessera.events import (
    EventKind,
    EventSink,
    SecurityEvent,
    emit as emit_event,
    register_sink,
    stdout_sink,
    unregister_sink,
    webhook_sink,
)
from tessera.labels import Origin, TrustLabel, TrustLevel, sign_label, verify_label
from tessera.mcp import MCPInterceptor
from tessera.policy import Decision, Policy, PolicyViolation, ToolRequirement
from tessera.quarantine import (
    QuarantinedExecutor,
    WorkerReport,
    WorkerSchemaViolation,
    split_by_trust,
    strict_worker,
)
from tessera.registry import ToolRegistry
from tessera.signing import (
    HMACSigner,
    HMACVerifier,
    JWKSVerifier,
    JWTSigner,
    JWTVerifier,
    LabelSigner,
    LabelVerifier,
    SigningNotAvailable,
)

__all__ = [
    "Context",
    "Decision",
    "EventKind",
    "EventSink",
    "HMACSigner",
    "HMACVerifier",
    "JWKSVerifier",
    "JWTSigner",
    "JWTVerifier",
    "LabelSigner",
    "LabelVerifier",
    "LabeledSegment",
    "MCPInterceptor",
    "Origin",
    "Policy",
    "PolicyViolation",
    "QuarantinedExecutor",
    "SecurityEvent",
    "SigningNotAvailable",
    "ToolRegistry",
    "ToolRequirement",
    "TrustLabel",
    "TrustLevel",
    "WorkerReport",
    "WorkerSchemaViolation",
    "emit_event",
    "make_segment",
    "register_sink",
    "sign_label",
    "split_by_trust",
    "stdout_sink",
    "strict_worker",
    "unregister_sink",
    "verify_label",
    "webhook_sink",
]
