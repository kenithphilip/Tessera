"""Tessera Security Attestation scorecard package.

Re-exports the public surface of the scorecard sub-package so callers can
import from ``tessera.evaluate.scorecard`` directly.

Example::

    from tessera.evaluate.scorecard import ScorecardEmitter, sign, verify
"""

from __future__ import annotations

from tessera.evaluate.scorecard.emitter import ScorecardEmitter
from tessera.evaluate.scorecard.sign import SigningMethodUnavailable, sign, verify

__all__ = [
    "ScorecardEmitter",
    "SigningMethodUnavailable",
    "sign",
    "verify",
]
