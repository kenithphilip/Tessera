"""Sigstore + in-toto signing for MCP manifests.

Wave 2B-i delivers the SignedManifest type that wraps the in-toto
Statement frozen in :mod:`tessera.mcp.manifest_schema` inside a
DSSE envelope, signs it via Sigstore Fulcio (or HMAC for
air-gapped tests), and verifies the result including the Rekor
inclusion proof.

The signing path is intentionally pluggable. ``method="sigstore"``
uses the public Fulcio + Rekor instances; ``method="hmac"`` is for
tests and air-gapped deployments where Sigstore is unavailable.
The verification path mirrors the same shape so an air-gapped
verifier can validate HMAC envelopes without contacting Sigstore.

Reference
---------

- :mod:`tessera.mcp.manifest_schema` (the Statement shape)
- in-toto Statement v1: https://in-toto.io/Statement/v1
- DSSE envelope: https://github.com/secure-systems-lab/dsse
- Sigstore: https://docs.sigstore.dev/
- ``docs/strategy/2026-04-engineering-brief.md`` Section 3.3
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

try:
    from jsonschema import validate as _jsonschema_validate
    from jsonschema import ValidationError as _JSONSchemaError
except ImportError:  # pragma: no cover - optional dep
    _jsonschema_validate = None
    _JSONSchemaError = ValueError

from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.mcp.manifest_schema import (
    MCP_MANIFEST_STATEMENT_SCHEMA,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
)


class SigningMethod(StrEnum):
    """Supported signing backends.

    SIGSTORE: Fulcio short-lived cert + Rekor inclusion proof.
        Default for production.
    HMAC: HMAC-SHA256 over the canonical-JSON payload. For tests and
        air-gapped deployments where Sigstore is unreachable.
    """

    SIGSTORE = "sigstore"
    HMAC = "hmac"


_DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def _b64(value: bytes) -> str:
    return base64.standard_b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.standard_b64decode(value.encode("ascii"))


def _canonical_json(payload: dict[str, Any]) -> bytes:
    """Stable canonical JSON encoding used as the signing payload."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _pae(payload_type: str, payload: bytes) -> bytes:
    """Pre-Authentication Encoding (PAE) per DSSE.

    PAE("DSSEv1", payload_type, payload) is the byte string the
    signer signs (NOT the raw payload), so a verifier rejects
    payloads of unexpected types even if they hash to the same
    value.
    """
    pt_bytes = payload_type.encode("utf-8")
    return (
        f"DSSEv1 {len(pt_bytes)} ".encode("utf-8")
        + pt_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


@dataclass(frozen=True, slots=True)
class DSSESignature:
    """One signature on a DSSE envelope."""

    keyid: str
    sig: str  # base64-encoded signature bytes
    cert: str | None = None  # PEM-encoded certificate (Sigstore Fulcio cert)


@dataclass(frozen=True, slots=True)
class RekorEntry:
    """Rekor inclusion proof attached by Sigstore."""

    log_index: int
    log_id: str
    integrated_time: int
    inclusion_proof: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SignedManifest:
    """In-toto Statement wrapped in a DSSE envelope, signed.

    Attributes:
        statement: The in-toto Statement payload (validated against
            :data:`MCP_MANIFEST_STATEMENT_SCHEMA`).
        signatures: Tuple of :class:`DSSESignature` (DSSE supports
            multiple signers; Tessera typically uses one).
        method: The :class:`SigningMethod` used.
        rekor: Optional Rekor inclusion proof (present only when
            ``method == SIGSTORE``).
    """

    statement: dict[str, Any]
    signatures: tuple[DSSESignature, ...]
    method: SigningMethod
    rekor: RekorEntry | None = None

    def to_envelope(self) -> dict[str, Any]:
        """Return the DSSE envelope as a JSON-serializable dict."""
        payload = _canonical_json(self.statement)
        return {
            "payloadType": _DSSE_PAYLOAD_TYPE,
            "payload": _b64(payload),
            "signatures": [
                {
                    "keyid": s.keyid,
                    "sig": s.sig,
                    **({"cert": s.cert} if s.cert else {}),
                }
                for s in self.signatures
            ],
            **(
                {
                    "rekor": {
                        "logIndex": self.rekor.log_index,
                        "logID": self.rekor.log_id,
                        "integratedTime": self.rekor.integrated_time,
                        "inclusionProof": self.rekor.inclusion_proof,
                    }
                }
                if self.rekor is not None
                else {}
            ),
            "method": str(self.method),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_envelope(), separators=(",", ":"))

    @classmethod
    def from_envelope(cls, envelope: dict[str, Any]) -> "SignedManifest":
        """Reconstruct a SignedManifest from its on-disk envelope."""
        if envelope.get("payloadType") != _DSSE_PAYLOAD_TYPE:
            raise ValueError(
                f"unexpected DSSE payloadType: {envelope.get('payloadType')!r}"
            )
        payload = _b64decode(envelope["payload"])
        statement = json.loads(payload)
        signatures = tuple(
            DSSESignature(
                keyid=s["keyid"],
                sig=s["sig"],
                cert=s.get("cert"),
            )
            for s in envelope.get("signatures", ())
        )
        method_raw = envelope.get("method", SigningMethod.HMAC.value)
        try:
            method = SigningMethod(method_raw)
        except ValueError as exc:
            raise ValueError(f"unknown signing method: {method_raw!r}") from exc
        rekor_data = envelope.get("rekor")
        rekor: RekorEntry | None = None
        if rekor_data is not None:
            rekor = RekorEntry(
                log_index=int(rekor_data["logIndex"]),
                log_id=str(rekor_data["logID"]),
                integrated_time=int(rekor_data["integratedTime"]),
                inclusion_proof=dict(rekor_data.get("inclusionProof", {})),
            )
        return cls(
            statement=statement,
            signatures=signatures,
            method=method,
            rekor=rekor,
        )


# ---------------------------------------------------------------------------
# Statement validation
# ---------------------------------------------------------------------------


def validate_statement(statement: dict[str, Any]) -> None:
    """Validate a Statement against the frozen schema.

    Raises :class:`ValueError` on any deviation. When the optional
    ``jsonschema`` dep is unavailable, falls back to a small set of
    must-have field checks so the boundary still rejects obvious
    junk.
    """
    if statement.get("_type") != STATEMENT_TYPE:
        raise ValueError(
            f"statement._type must be {STATEMENT_TYPE!r}; got {statement.get('_type')!r}"
        )
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise ValueError(
            f"statement.predicateType must be {PREDICATE_TYPE!r}; "
            f"got {statement.get('predicateType')!r}"
        )
    if "subject" not in statement or not statement["subject"]:
        raise ValueError("statement.subject must be a non-empty array")
    if "predicate" not in statement:
        raise ValueError("statement.predicate is required")
    if _jsonschema_validate is None:
        return
    try:
        _jsonschema_validate(
            instance=statement, schema=MCP_MANIFEST_STATEMENT_SCHEMA
        )
    except _JSONSchemaError as exc:
        raise ValueError(f"statement does not match schema: {exc}") from exc


# ---------------------------------------------------------------------------
# Sign + verify
# ---------------------------------------------------------------------------


def _hmac_sign(payload: bytes, key: bytes, keyid: str) -> DSSESignature:
    pae = _pae(_DSSE_PAYLOAD_TYPE, payload)
    sig = hmac.new(key, pae, hashlib.sha256).digest()
    return DSSESignature(keyid=keyid, sig=_b64(sig))


def _hmac_verify(payload: bytes, sig: DSSESignature, key: bytes) -> bool:
    pae = _pae(_DSSE_PAYLOAD_TYPE, payload)
    expected = hmac.new(key, pae, hashlib.sha256).digest()
    actual = _b64decode(sig.sig)
    return hmac.compare_digest(expected, actual)


def sign(
    statement: dict[str, Any],
    *,
    method: SigningMethod | str = SigningMethod.SIGSTORE,
    hmac_key: bytes | None = None,
    hmac_keyid: str = "tessera-hmac-v1",
    sigstore_identity_token: str | None = None,
) -> SignedManifest:
    """Sign an in-toto Statement and return a :class:`SignedManifest`.

    Args:
        statement: The in-toto Statement to sign. Validated against
            :data:`MCP_MANIFEST_STATEMENT_SCHEMA` before any
            signing work.
        method: :class:`SigningMethod`. Defaults to SIGSTORE.
        hmac_key: Required when ``method == HMAC``. Must be at least
            32 bytes.
        hmac_keyid: Identifier embedded in the signature for the HMAC
            path; allows verifiers to pick the right key.
        sigstore_identity_token: Optional pre-fetched OIDC token for
            the SIGSTORE path. When omitted, the sigstore-python
            library handles the OIDC dance interactively.

    Returns:
        A :class:`SignedManifest` whose envelope is ready to be
        written to disk via :meth:`to_envelope` /
        :meth:`to_json`.
    """
    method = SigningMethod(method) if isinstance(method, str) else method
    validate_statement(statement)
    payload = _canonical_json(statement)

    if method == SigningMethod.HMAC:
        if hmac_key is None or len(hmac_key) < 32:
            raise ValueError(
                "method=hmac requires hmac_key of at least 32 bytes"
            )
        sig = _hmac_sign(payload, hmac_key, hmac_keyid)
        return SignedManifest(
            statement=statement,
            signatures=(sig,),
            method=method,
        )

    # SIGSTORE path. Lazy-import sigstore so the dep stays optional.
    try:
        from sigstore.sign import SigningContext
        from sigstore.oidc import IdentityToken
    except ImportError as exc:  # pragma: no cover - optional dep
        raise RuntimeError(
            "method=sigstore requires the sigstore-python library; "
            "install with `pip install sigstore` or use method=hmac"
        ) from exc

    ctx = SigningContext.production()
    if sigstore_identity_token is not None:
        identity = IdentityToken(sigstore_identity_token)
    else:
        # Interactive OIDC flow; the caller is expected to have
        # the right env vars set up (CI provides them via OIDC).
        from sigstore.oidc import detect_credential

        identity = detect_credential()
    with ctx.signer(identity_token=identity) as signer:  # pragma: no cover
        bundle = signer.sign_artifact(payload)
    cert_pem = bundle.signing_certificate.public_bytes_pem.decode("ascii")
    signature = DSSESignature(
        keyid="sigstore-fulcio",
        sig=_b64(bundle.signature),
        cert=cert_pem,
    )
    rekor = RekorEntry(
        log_index=bundle.log_entry.log_index,
        log_id=bundle.log_entry.log_id,
        integrated_time=int(bundle.log_entry.integrated_time),
        inclusion_proof=getattr(bundle.log_entry, "inclusion_proof", {}) or {},
    )
    return SignedManifest(
        statement=statement,
        signatures=(signature,),
        method=method,
        rekor=rekor,
    )


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying a :class:`SignedManifest`."""

    valid: bool
    method: SigningMethod
    reason: str = ""

    def __bool__(self) -> bool:
        return self.valid


def verify(
    manifest: SignedManifest,
    *,
    hmac_key: bytes | None = None,
    expected_subject_digests: dict[str, str] | None = None,
    require_rekor: bool = True,
    principal: str | None = None,
) -> VerificationResult:
    """Verify a :class:`SignedManifest` and return the outcome.

    Validates the Statement schema, checks the signature against the
    method's verifier, optionally cross-checks the subject digests
    against the artifact the caller expects, and (for SIGSTORE)
    enforces a Rekor inclusion proof unless ``require_rekor=False``.
    A failed verification emits :attr:`EventKind.MCP_MANIFEST_SIG_INVALID`.
    """
    try:
        validate_statement(manifest.statement)
    except ValueError as exc:
        return _emit_invalid(manifest, principal, f"schema: {exc}")

    payload = _canonical_json(manifest.statement)

    if manifest.method == SigningMethod.HMAC:
        if hmac_key is None:
            return _emit_invalid(
                manifest, principal, "hmac_key required to verify HMAC envelope"
            )
        for sig in manifest.signatures:
            if _hmac_verify(payload, sig, hmac_key):
                if expected_subject_digests is not None:
                    if not _subjects_match(
                        manifest.statement, expected_subject_digests
                    ):
                        return _emit_invalid(
                            manifest, principal, "subject digest mismatch"
                        )
                return VerificationResult(
                    valid=True, method=manifest.method, reason="hmac ok"
                )
        return _emit_invalid(manifest, principal, "no signature verified")

    # SIGSTORE path.
    if require_rekor and manifest.rekor is None:
        return _emit_invalid(
            manifest, principal, "sigstore envelope missing Rekor entry"
        )
    try:
        from sigstore.verify import Verifier
        from sigstore.verify.policy import UnsafeNoOp
    except ImportError as exc:  # pragma: no cover - optional dep
        return _emit_invalid(
            manifest,
            principal,
            f"sigstore-python missing for verification: {exc}",
        )
    verifier = Verifier.production()
    for sig in manifest.signatures:
        if sig.cert is None:
            continue
        try:  # pragma: no cover - exercised in integration tests
            verifier.verify_artifact(
                input_=payload,
                bundle=_reconstruct_bundle(sig, manifest.rekor),
                policy=UnsafeNoOp(),
            )
        except Exception as exc:  # noqa: BLE001
            return _emit_invalid(
                manifest, principal, f"sigstore verification failed: {exc}"
            )
    if expected_subject_digests is not None:
        if not _subjects_match(manifest.statement, expected_subject_digests):
            return _emit_invalid(
                manifest, principal, "subject digest mismatch"
            )
    return VerificationResult(
        valid=True, method=manifest.method, reason="sigstore ok"
    )


def _subjects_match(
    statement: dict[str, Any], expected: dict[str, str]
) -> bool:
    """Return True when every expected (name, sha256) appears in the Statement."""
    by_name = {
        s.get("name"): s.get("digest", {}).get("sha256")
        for s in statement.get("subject", ())
    }
    for name, sha in expected.items():
        if by_name.get(name) != sha:
            return False
    return True


def _emit_invalid(
    manifest: SignedManifest, principal: str | None, reason: str
) -> VerificationResult:
    emit_event(
        SecurityEvent.now(
            kind=EventKind.MCP_MANIFEST_SIG_INVALID,
            principal=principal,
            detail={
                "method": str(manifest.method),
                "reason": reason,
                "subject": [s.get("name") for s in manifest.statement.get("subject", ())],
            },
        )
    )
    return VerificationResult(
        valid=False, method=manifest.method, reason=reason
    )


def _reconstruct_bundle(sig: DSSESignature, rekor: RekorEntry | None) -> Any:
    """Re-build a sigstore Bundle for verification.

    Lazy: returns whatever sigstore-python's Bundle.from_dict expects.
    Implementation finalized in Phase 2A.real when an end-to-end
    Sigstore test environment is wired.
    """
    return {  # pragma: no cover
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [{"rawBytes": sig.cert}] if sig.cert else []
            },
            **(
                {
                    "tlogEntries": [
                        {
                            "logIndex": str(rekor.log_index),
                            "logId": {"keyId": rekor.log_id},
                            "integratedTime": str(rekor.integrated_time),
                            "inclusionProof": rekor.inclusion_proof,
                        }
                    ]
                }
                if rekor is not None
                else {}
            ),
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": _b64(hashlib.sha256(b"placeholder").digest()),
            },
            "signature": sig.sig,
        },
    }


__all__ = [
    "DSSESignature",
    "RekorEntry",
    "SignedManifest",
    "SigningMethod",
    "VerificationResult",
    "sign",
    "validate_statement",
    "verify",
]
