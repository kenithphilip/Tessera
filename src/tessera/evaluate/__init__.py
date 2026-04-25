"""Tessera evaluation package.

Re-exports the public surface of the evaluate sub-packages so callers can
import from ``tessera.evaluate`` directly.

Example::

    from tessera.evaluate import emit_scorecard, sign_scorecard
    from tessera.evaluate import SecurityAttestation, ScorecardEmitter
"""

from __future__ import annotations

from tessera.evaluate.scorecard.emitter import ScorecardEmitter
from tessera.evaluate.scorecard.sign import SigningMethodUnavailable, sign, verify


def emit_scorecard(
    version: str,
    out_path: str,
    *,
    signing_method: str = "none",
    **kwargs,
) -> str:
    """Convenience function: build, emit, and optionally sign an attestation.

    This is a thin wrapper around :class:`ScorecardEmitter` and :func:`sign`
    intended for use from scripts and notebooks. For full control, instantiate
    :class:`ScorecardEmitter` directly.

    Args:
        version: SemVer string for the Tessera release.
        out_path: Destination path for the JSON-lines attestation file.
        signing_method: ``"none"`` (default), ``"hmac"``, or ``"sigstore"``.
        **kwargs: Additional keyword arguments forwarded to
            :class:`ScorecardEmitter` (e.g. ``audit_log_path``,
            ``scanner_report_path``, ``benchmark_runs``).

    Returns:
        Path string of the written attestation file, or the DSSE envelope
        path when signing is requested.
    """
    from pathlib import Path

    emitter = ScorecardEmitter(version=version, **kwargs)
    written = emitter.emit(Path(out_path))
    if signing_method != "none":
        envelope = sign(written, signing_method=signing_method)
        return str(envelope)
    return str(written)


def sign_scorecard(
    attestation_path: str,
    *,
    signing_method: str = "hmac",
    identity_token: str | None = None,
) -> str:
    """Sign an existing attestation file.

    Args:
        attestation_path: Path to a JSON-lines attestation file.
        signing_method: ``"hmac"`` (default) or ``"sigstore"``.
        identity_token: OIDC token for Sigstore (ignored for HMAC).

    Returns:
        Path string of the written DSSE envelope file.
    """
    from pathlib import Path

    envelope = sign(
        Path(attestation_path),
        signing_method=signing_method,
        identity_token=identity_token,
    )
    return str(envelope)


# Alias for users who want to type-annotate return values.
SecurityAttestation = dict

__all__ = [
    "ScorecardEmitter",
    "SigningMethodUnavailable",
    "SecurityAttestation",
    "emit_scorecard",
    "sign_scorecard",
    "sign",
    "verify",
]
