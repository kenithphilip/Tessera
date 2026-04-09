"""Unit tests for the SecretRegistry redaction primitive."""

from __future__ import annotations

import pytest

from tessera.redaction import SecretRegistry, redact_nested


def test_registry_add_and_redact_single_value():
    reg = SecretRegistry()
    reg.add("GITHUB_TOKEN", "ghp_abcdefghij1234567890")

    redacted, hits = reg.redact(
        "Here is my token ghp_abcdefghij1234567890 to use for cloning."
    )

    assert redacted == "Here is my token <REDACTED:GITHUB_TOKEN> to use for cloning."
    assert hits == ["GITHUB_TOKEN"]


def test_redact_returns_original_text_and_empty_hits_on_miss():
    reg = SecretRegistry()
    reg.add("GITHUB_TOKEN", "ghp_abcdefghij1234567890")

    redacted, hits = reg.redact("nothing sensitive here")

    assert redacted == "nothing sensitive here"
    assert hits == []


def test_registry_is_noop_when_empty():
    reg = SecretRegistry()
    redacted, hits = reg.redact("arbitrary text ghp_fake")
    assert redacted == "arbitrary text ghp_fake"
    assert hits == []


def test_duplicate_name_rejected():
    reg = SecretRegistry()
    reg.add("TOKEN", "value-one-long-enough")
    with pytest.raises(ValueError, match="already registered"):
        reg.add("TOKEN", "value-two-different-but-same-name")


def test_duplicate_value_rejected_even_under_different_name():
    reg = SecretRegistry()
    reg.add("TOKEN_A", "shared-value-long-enough")
    with pytest.raises(ValueError, match="already registered under"):
        reg.add("TOKEN_B", "shared-value-long-enough")


def test_short_secret_rejected_to_avoid_false_positives():
    reg = SecretRegistry()
    with pytest.raises(ValueError, match="too likely to match"):
        reg.add("PIN", "1234")


def test_empty_name_rejected():
    reg = SecretRegistry()
    with pytest.raises(ValueError, match="name must be non-empty"):
        reg.add("", "value-long-enough")


def test_empty_value_rejected():
    reg = SecretRegistry()
    with pytest.raises(ValueError, match="must be non-empty"):
        reg.add("TOKEN", "")


def test_longer_secret_replaced_before_its_prefix():
    """A longer secret that contains a shorter secret must be replaced first.

    Otherwise the shorter secret would chop the longer one into pieces
    and the longer marker would never fire. The registry sorts by
    descending length at redaction time to prevent this.
    """
    reg = SecretRegistry()
    reg.add("SHORT_TOKEN", "abcdefgh")  # 8 chars, minimum
    reg.add("LONG_TOKEN", "abcdefghij1234567890")  # contains SHORT_TOKEN as prefix

    redacted, hits = reg.redact("see abcdefghij1234567890 for details")

    assert redacted == "see <REDACTED:LONG_TOKEN> for details"
    assert hits == ["LONG_TOKEN"]


def test_multiple_secrets_in_one_string_all_redacted():
    reg = SecretRegistry()
    reg.add("A", "aaaa1111bbbb")
    reg.add("B", "cccc2222dddd")

    redacted, hits = reg.redact("A=aaaa1111bbbb B=cccc2222dddd end")

    assert "aaaa1111bbbb" not in redacted
    assert "cccc2222dddd" not in redacted
    assert "<REDACTED:A>" in redacted
    assert "<REDACTED:B>" in redacted
    assert set(hits) == {"A", "B"}


def test_names_property_preserves_registration_order():
    reg = SecretRegistry()
    reg.add("FIRST", "aaaaaaaa1")
    reg.add("SECOND", "bbbbbbbb2")
    reg.add("THIRD", "cccccccc3")
    assert reg.names == ["FIRST", "SECOND", "THIRD"]


def test_len_reflects_registered_count():
    reg = SecretRegistry()
    assert len(reg) == 0
    reg.add("A", "aaaaaaaa1")
    assert len(reg) == 1
    reg.add("B", "bbbbbbbb2")
    assert len(reg) == 2


def test_clear_drops_all_secrets():
    reg = SecretRegistry()
    reg.add("A", "aaaaaaaa1")
    reg.add("B", "bbbbbbbb2")
    reg.clear()
    assert len(reg) == 0
    redacted, hits = reg.redact("aaaaaaaa1 and bbbbbbbb2")
    assert redacted == "aaaaaaaa1 and bbbbbbbb2"
    assert hits == []


def test_from_env_skips_missing_and_short_values(monkeypatch):
    monkeypatch.setenv("TESSERA_REAL", "real-token-long-enough")
    monkeypatch.setenv("TESSERA_SHORT", "dev")
    monkeypatch.delenv("TESSERA_MISSING", raising=False)

    reg = SecretRegistry.from_env("TESSERA_REAL", "TESSERA_SHORT", "TESSERA_MISSING")

    assert reg.names == ["TESSERA_REAL"]


def test_redact_nested_walks_dicts_and_lists():
    reg = SecretRegistry()
    reg.add("TOKEN", "ghp_aaaaaaaa11111111")

    payload = {
        "choices": [
            {
                "message": {
                    "content": "leaked: ghp_aaaaaaaa11111111",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "send",
                                "arguments": '{"key": "ghp_aaaaaaaa11111111"}',
                            }
                        }
                    ],
                }
            }
        ]
    }

    _, hits = redact_nested(payload, reg)

    assert hits.count("TOKEN") == 2
    assert "ghp_aaaaaaaa11111111" not in payload["choices"][0]["message"]["content"]
    assert "<REDACTED:TOKEN>" in payload["choices"][0]["message"]["content"]
    tool_args = payload["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert "ghp_aaaaaaaa11111111" not in tool_args
    assert "<REDACTED:TOKEN>" in tool_args


def test_redact_nested_leaves_non_string_leaves_alone():
    reg = SecretRegistry()
    reg.add("TOKEN", "ghp_aaaaaaaa11111111")

    payload = {
        "count": 42,
        "ratio": 3.14,
        "enabled": True,
        "nothing": None,
        "text": "ghp_aaaaaaaa11111111 leaked",
    }

    _, hits = redact_nested(payload, reg)

    assert payload["count"] == 42
    assert payload["ratio"] == 3.14
    assert payload["enabled"] is True
    assert payload["nothing"] is None
    assert hits == ["TOKEN"]
