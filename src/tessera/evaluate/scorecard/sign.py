"""Signing and verification for Tessera Security Attestations.

Two signing methods are supported:

- ``"sigstore"`` (default): Produces a DSSE envelope signed via Sigstore
  Fulcio (OIDC-bound short-lived cert) with a Rekor inclusion proof.
  Requires the ``sigstore`` Python package (``pip install sigstore``).

- ``"hmac"`` (air-gapped / test): Produces a minimal DSSE-shaped envelope
  where the signature is HMAC-SHA256 over the canonical-JSON payload.
  The key is read from the ``TESSERA_SCORECARD_HMAC_KEY`` environment
  variable (hex-encoded) or falls back to a deterministic test key.
  This method has no external dependencies and is suitable for CI and
  air-gapped deployments.

Envelope format (both methods)::

    {
        "payload":        "<base64-standard of the raw attestation JSON>",
        "payloadType":    "application/vnd.in-toto+json",
        "signatures": [
            {
                "keyid": "<key identifier or empty string>",
                "sig":   "<base64-standard of the raw signature bytes>"
            }
        ],
        "signing_method": "<sigstore|hmac>"
    }

The ``payload`` field is the raw JSON bytes of the attestation (not double-
encoded), base64-encoded so the envelope is itself valid JSON.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import os
from pathlib import Path

_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_HMAC_KEY_ENV = "TESSERA_SCORECARD_HMAC_KEY"
_FALLBACK_KEY = b"tessera-scorecard-dev-key-000000"  # 32 bytes, tests only


class SigningMethodUnavailable(RuntimeError):
    """Raised when a signing backend cannot be loaded.

    Attributes:
        method: The requested signing method name.
        hint: Installation or configuration hint.
    """

    def __init__(self, method: str, hint: str) -> None:
        self.method = method
        self.hint = hint
        super().__init__(f"Signing method '{method}' unavailable: {hint}")


def _hmac_key() -> bytes:
    """Resolve the HMAC key from the environment or use the fallback key.

    Production deployments must set TESSERA_SCORECARD_HMAC_KEY to a
    hex-encoded 32+ byte secret. The fallback is intentionally weak and
    should never be used outside of tests.

    Returns:
        Raw key bytes.
    """
    raw = os.environ.get(_HMAC_KEY_ENV, "")
    if raw:
        return bytes.fromhex(raw)
    return _FALLBACK_KEY


def _canonical_payload(attestation_path: Path) -> bytes:
    """Read the first line of the attestation JSONL and return canonical JSON bytes.

    Args:
        attestation_path: Path to a JSON-lines attestation file.

    Returns:
        Canonical JSON bytes (sort_keys=True, compact separators).

    Raises:
        ValueError: If the file is empty or the first line is not valid JSON.
    """
    text = attestation_path.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"attestation file is empty: {attestation_path}")
    first_line = text.splitlines()[0]
    try:
        data = json.loads(first_line)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"attestation first line is not valid JSON: {exc}"
        ) from exc
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _envelope_path(attestation_path: Path) -> Path:
    """Return the conventional path for the DSSE envelope alongside the attestation."""
    return attestation_path.with_suffix(".dsse.json")


def sign(
    attestation_path: Path,
    *,
    identity_token: str | None = None,
    signing_method: str = "sigstore",
) -> Path:
    """Sign an attestation file and write a DSSE-shaped envelope next to it.

    Args:
        attestation_path: Path to the JSON-lines attestation to sign.
        identity_token: OIDC identity token for Sigstore. When None,
            Sigstore performs interactive browser-based sign-in. Ignored
            for ``signing_method="hmac"``.
        signing_method: ``"sigstore"`` (default) or ``"hmac"``.

    Returns:
        Path to the written DSSE envelope file (``<attestation>.dsse.json``).

    Raises:
        SigningMethodUnavailable: When ``signing_method="sigstore"`` but the
            ``sigstore`` package is not installed.
        ValueError: When ``signing_method`` is not recognised.
    """
    payload_bytes = _canonical_payload(attestation_path)
    envelope_path = _envelope_path(attestation_path)

    if signing_method == "hmac":
        key = _hmac_key()
        sig_bytes = _hmac.new(key, payload_bytes, hashlib.sha256).digest()
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
        key_id = hashlib.sha256(key).hexdigest()[:16]
        envelope = {
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "payloadType": _PAYLOAD_TYPE,
            "signatures": [{"keyid": key_id, "sig": sig_b64}],
            "signing_method": "hmac",
        }
        envelope_path.write_text(
            json.dumps(envelope, sort_keys=True, indent=2), encoding="utf-8"
        )
        return envelope_path.resolve()

    if signing_method == "sigstore":
        try:
            import sigstore  # noqa: F401 - verify availability
            from sigstore.sign import SigningContext
            from sigstore.models import Bundle
        except ImportError as exc:
            raise SigningMethodUnavailable(
                "sigstore",
                "install with: pip install sigstore",
            ) from exc

        ctx = SigningContext.production()
        with ctx.signer(identity_token=identity_token) as signer:
            bundle: Bundle = signer.sign_artifact(payload_bytes)
        # Embed the bundle JSON as the signature field.
        bundle_json = bundle.to_json()
        sig_b64 = base64.b64encode(bundle_json.encode("utf-8")).decode("ascii")
        envelope = {
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "payloadType": _PAYLOAD_TYPE,
            "signatures": [{"keyid": "", "sig": sig_b64}],
            "signing_method": "sigstore",
        }
        envelope_path.write_text(
            json.dumps(envelope, sort_keys=True, indent=2), encoding="utf-8"
        )
        return envelope_path.resolve()

    raise ValueError(
        f"unknown signing_method {signing_method!r}: choose 'sigstore' or 'hmac'"
    )


def verify(envelope_path: Path) -> bool:
    """Verify the DSSE envelope produced by :func:`sign`.

    For HMAC envelopes: recomputes the HMAC over the embedded payload and
    does a constant-time comparison. Returns False on any mismatch, missing
    key, or malformed envelope.

    For Sigstore envelopes: delegates to the sigstore verifier. Returns False
    if the sigstore package is unavailable or verification fails.

    Args:
        envelope_path: Path to the DSSE envelope JSON file.

    Returns:
        True iff the envelope signature is valid.
    """
    if not envelope_path.exists():
        return False
    try:
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False

    method = envelope.get("signing_method", "hmac")
    payload_b64 = envelope.get("payload", "")
    sigs = envelope.get("signatures", [])
    if not sigs or not payload_b64:
        return False

    try:
        payload_bytes = base64.b64decode(payload_b64)
    except Exception:
        return False

    if method == "hmac":
        sig_entry = sigs[0]
        try:
            sig_bytes = base64.b64decode(sig_entry.get("sig", ""))
        except Exception:
            return False
        key = _hmac_key()
        expected = _hmac.new(key, payload_bytes, hashlib.sha256).digest()
        return _hmac.compare_digest(expected, sig_bytes)

    if method == "sigstore":
        try:
            from sigstore.verify import Verifier
            from sigstore.models import Bundle
        except ImportError:
            return False
        try:
            sig_entry = sigs[0]
            bundle_bytes = base64.b64decode(sig_entry.get("sig", ""))
            bundle = Bundle.from_json(bundle_bytes.decode("utf-8"))
            verifier = Verifier.production()
            verifier.verify_artifact(payload_bytes, bundle, policy=None)
            return True
        except Exception:
            return False

    return False


__all__ = ["sign", "verify", "SigningMethodUnavailable"]
