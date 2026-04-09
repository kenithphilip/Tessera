"""Label signing and verification."""

import pytest

from tessera.labels import (
    Origin,
    TrustLabel,
    TrustLevel,
    sign_label,
    verify_label,
)

KEY = b"test-hmac-key-do-not-use-in-prod"


def _label(origin: Origin, level: TrustLevel) -> TrustLabel:
    return TrustLabel(origin=origin, principal="alice", trust_level=level)


def test_signed_label_round_trips():
    content = "hello world"
    signed = sign_label(_label(Origin.USER, TrustLevel.USER), content, KEY)
    assert verify_label(signed, content, KEY) is True


def test_tampered_content_fails_verification():
    signed = sign_label(_label(Origin.USER, TrustLevel.USER), "original", KEY)
    assert verify_label(signed, "tampered", KEY) is False


def test_wrong_key_fails_verification():
    signed = sign_label(_label(Origin.USER, TrustLevel.USER), "x", KEY)
    assert verify_label(signed, "x", b"other-key") is False


def test_unsigned_label_fails_verification():
    unsigned = _label(Origin.USER, TrustLevel.USER)
    assert verify_label(unsigned, "x", KEY) is False


@pytest.mark.parametrize(
    "origin,level",
    [
        (Origin.WEB, TrustLevel.UNTRUSTED),
        (Origin.TOOL, TrustLevel.TOOL),
        (Origin.USER, TrustLevel.USER),
        (Origin.SYSTEM, TrustLevel.SYSTEM),
    ],
)
def test_each_origin_signs_and_verifies(origin: Origin, level: TrustLevel):
    content = f"sample for {origin}"
    signed = sign_label(_label(origin, level), content, KEY)
    assert verify_label(signed, content, KEY)
