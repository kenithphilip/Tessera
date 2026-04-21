"""Tests for tessera.scanners.yara."""

from __future__ import annotations

import pytest

from tessera.scanners.yara import YaraScanner, _YARA_AVAILABLE


def test_unavailable_returns_silent_allow():
    """Scanner with no rules (or without yara-x) returns a silent allow."""
    scanner = YaraScanner()
    assert not scanner.available
    r = scanner.scan(tool_name="bash.run", args={"command": "whatever"})
    assert r.allowed
    assert r.findings == ()


@pytest.mark.skipif(not _YARA_AVAILABLE, reason="yara-x not installed")
class TestYaraWithBindings:
    def test_compiles_and_matches(self):
        rule = r"""
rule hardcoded_password_literal {
    meta:
        severity = "high"
        rule_id  = "yara.demo.hardcoded_password"
        message  = "string 'sekret-pw' present"
    strings:
        $s = "sekret-pw" ascii
    condition:
        $s
}
"""
        scanner = YaraScanner(rules=[rule])
        assert scanner.available
        assert scanner.rule_count == 1

        r = scanner.scan(
            tool_name="http.post",
            args={"body": "login with sekret-pw please"},
        )
        assert not r.allowed
        assert any(f.rule_id == "yara.demo.hardcoded_password" for f in r.findings)

    def test_no_match_is_allowed(self):
        rule = r"""
rule impossible {
    strings: $s = "ZZZ-NEVER-MATCH-ZZZ"
    condition: $s
}
"""
        scanner = YaraScanner(rules=[rule])
        r = scanner.scan(tool_name="x", args={"foo": "bar"})
        assert r.allowed
        assert r.findings == ()

    def test_bad_rule_is_captured_not_raised(self):
        bad_rule = "this is not valid yara"
        scanner = YaraScanner(rules=[bad_rule])
        assert scanner.load_errors or not scanner.available
