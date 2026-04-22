"""Tests for tessera.ssrf_guard."""

from __future__ import annotations

import pytest

from tessera.ssrf_guard import SSRFGuard


def _fake_resolver(mapping: dict[str, list[str]]):
    def resolver(host: str) -> list[str]:
        if host in mapping:
            return mapping[host]
        raise OSError(f"unknown host: {host}")
    return resolver


def _guard(
    *,
    resolver=None,
    allowed_schemes=None,
    blocked_hostnames=None,
    allowlist_hostnames=None,
) -> SSRFGuard:
    kwargs = {}
    if resolver is not None:
        kwargs["resolver"] = resolver
    if allowed_schemes is not None:
        kwargs["allowed_schemes"] = allowed_schemes
    if blocked_hostnames is not None:
        kwargs["blocked_hostnames"] = blocked_hostnames
    if allowlist_hostnames is not None:
        kwargs["allowlist_hostnames"] = allowlist_hostnames
    return SSRFGuard(**kwargs)


class TestSchemes:
    def test_https_allowed(self) -> None:
        g = _guard(resolver=_fake_resolver({"example.com": ["93.184.216.34"]}))
        assert g.check_url("https://example.com/").allowed

    def test_http_allowed(self) -> None:
        g = _guard(resolver=_fake_resolver({"example.com": ["93.184.216.34"]}))
        assert g.check_url("http://example.com/").allowed

    def test_file_scheme_blocked(self) -> None:
        g = _guard()
        r = g.check_url("file:///etc/passwd")
        assert not r.allowed
        assert r.findings[0].category == "scheme"
        assert "file" in r.findings[0].rule_id

    def test_gopher_blocked(self) -> None:
        g = _guard()
        r = g.check_url("gopher://example.com/")
        assert not r.allowed
        assert r.findings[0].category == "scheme"

    def test_custom_allowed_schemes(self) -> None:
        g = _guard(
            allowed_schemes={"https"},
            resolver=_fake_resolver({"example.com": ["93.184.216.34"]}),
        )
        assert not g.check_url("http://example.com/").allowed
        assert g.check_url("https://example.com/").allowed


class TestPrivateRanges:
    def test_loopback_ipv4_blocked_directly(self) -> None:
        g = _guard()
        r = g.check_url("http://127.0.0.1/")
        assert not r.allowed
        assert r.findings[0].category == "loopback"

    def test_loopback_ipv6_blocked_directly(self) -> None:
        g = _guard()
        r = g.check_url("http://[::1]/")
        assert not r.allowed
        assert r.findings[0].category == "loopback"

    def test_rfc1918_10_blocked(self) -> None:
        g = _guard()
        assert not g.check_url("http://10.0.0.5/").allowed

    def test_rfc1918_172_blocked(self) -> None:
        g = _guard()
        assert not g.check_url("http://172.16.0.1/").allowed

    def test_rfc1918_192_blocked(self) -> None:
        g = _guard()
        assert not g.check_url("http://192.168.1.1/").allowed

    def test_link_local_blocked(self) -> None:
        g = _guard()
        r = g.check_url("http://169.254.0.5/")
        assert not r.allowed

    def test_unique_local_v6_blocked(self) -> None:
        g = _guard()
        r = g.check_url("http://[fc00::1]/")
        assert not r.allowed
        assert r.findings[0].category == "unique_local"

    def test_resolved_to_private_blocked(self) -> None:
        # DNS rebinding pinning: even though the hostname is "public",
        # if it resolves to RFC1918, deny.
        g = _guard(resolver=_fake_resolver({
            "internal.example.com": ["10.20.30.40"],
        }))
        r = g.check_url("http://internal.example.com/")
        assert not r.allowed
        assert r.findings[0].resolved_ip == "10.20.30.40"


class TestEncodedIPs:
    def test_decimal_encoded_loopback(self) -> None:
        # 2130706433 == 127.0.0.1
        g = _guard()
        r = g.check_url("http://2130706433/")
        assert not r.allowed
        assert r.findings[0].category == "loopback"

    def test_hex_encoded_loopback(self) -> None:
        g = _guard()
        r = g.check_url("http://0x7f000001/")
        assert not r.allowed
        assert r.findings[0].category == "loopback"

    def test_octal_dotted_loopback(self) -> None:
        g = _guard()
        r = g.check_url("http://0177.0.0.1/")
        assert not r.allowed
        assert r.findings[0].category == "loopback"

    def test_hex_dotted_loopback(self) -> None:
        g = _guard()
        r = g.check_url("http://0x7f.0.0.1/")
        assert not r.allowed
        assert r.findings[0].category == "loopback"

    def test_ipv4_mapped_ipv6_loopback(self) -> None:
        g = _guard()
        r = g.check_url("http://[::ffff:127.0.0.1]/")
        assert not r.allowed
        assert r.findings[0].category == "loopback"


class TestCloudMetadata:
    def test_aws_ip_specific_rule_id(self) -> None:
        g = _guard()
        r = g.check_url("http://169.254.169.254/latest/meta-data/")
        assert not r.allowed
        # Specific cloud_metadata category beats the generic link_local.
        assert r.findings[0].category == "cloud_metadata"
        assert r.findings[0].rule_id == "ssrf.cloud_metadata.aws_gcp_azure_oci"

    def test_alibaba_metadata(self) -> None:
        g = _guard()
        r = g.check_url("http://100.100.100.200/")
        assert not r.allowed
        assert r.findings[0].rule_id == "ssrf.cloud_metadata.alibaba"

    def test_metadata_resolved_via_dns(self) -> None:
        g = _guard(resolver=_fake_resolver({
            "metadata.google.internal": ["169.254.169.254"],
        }))
        r = g.check_url("http://metadata.google.internal/")
        assert not r.allowed
        assert r.findings[0].rule_id == "ssrf.cloud_metadata.aws_gcp_azure_oci"


class TestHostnameLists:
    def test_blocked_hostname_skips_resolution(self) -> None:
        called = []

        def tracking_resolver(host: str) -> list[str]:
            called.append(host)
            return ["1.2.3.4"]

        g = _guard(
            resolver=tracking_resolver,
            blocked_hostnames={"forbidden.example.com"},
        )
        r = g.check_url("http://forbidden.example.com/")
        assert not r.allowed
        assert r.findings[0].category == "hostname_denylist"
        # Resolver must not have been consulted.
        assert called == []

    def test_allowlist_denies_other_hostnames(self) -> None:
        g = _guard(
            resolver=_fake_resolver({
                "allowed.example.com": ["1.2.3.4"],
                "other.example.com": ["1.2.3.5"],
            }),
            allowlist_hostnames={"allowed.example.com"},
        )
        assert g.check_url("http://allowed.example.com/").allowed
        denied = g.check_url("http://other.example.com/")
        assert not denied.allowed
        assert denied.findings[0].category == "hostname_allowlist"

    def test_allowlist_blocks_raw_ip_even_if_public(self) -> None:
        # Allowlist mode should not let raw IPs slip through.
        g = _guard(
            allowlist_hostnames={"only.example.com"},
            resolver=_fake_resolver({"only.example.com": ["8.8.8.8"]}),
        )
        r = g.check_url("http://8.8.8.8/")
        assert not r.allowed
        assert r.findings[0].category == "hostname_allowlist"


class TestResolutionFailures:
    def test_resolver_raises_fails_closed(self) -> None:
        g = _guard(resolver=_fake_resolver({}))
        r = g.check_url("http://does-not-exist.example/")
        assert not r.allowed
        assert r.findings[0].category == "resolution"

    def test_empty_resolution_fails_closed(self) -> None:
        g = _guard(resolver=lambda host: [])
        r = g.check_url("http://something.example/")
        assert not r.allowed
        assert r.findings[0].rule_id == "ssrf.resolution_empty"

    def test_partial_bad_resolution_blocked(self) -> None:
        # Returns one public and one private IP -> deny.
        g = _guard(resolver=lambda host: ["8.8.8.8", "10.0.0.1"])
        r = g.check_url("http://multi.example/")
        assert not r.allowed
        # The bad entry shows up.
        assert any(f.resolved_ip == "10.0.0.1" for f in r.findings)


class TestMalformedURLs:
    def test_empty_url(self) -> None:
        g = _guard()
        r = g.check_url("")
        assert not r.allowed
        assert r.findings[0].category == "malformed"

    def test_no_host(self) -> None:
        g = _guard()
        r = g.check_url("http:///path")
        assert not r.allowed
        assert r.findings[0].rule_id == "ssrf.no_host"


class TestPublicURLAllowed:
    def test_public_dns_resolution_allowed(self) -> None:
        g = _guard(resolver=_fake_resolver({"example.com": ["93.184.216.34"]}))
        assert g.check_url("https://example.com/").allowed

    def test_public_ipv6_allowed(self) -> None:
        g = _guard()
        # 2606:4700:4700::1111 is Cloudflare DNS, public.
        assert g.check_url("https://[2606:4700:4700::1111]/").allowed


class TestScannerProtocol:
    def test_scan_finds_ssrf_in_dict_args(self) -> None:
        g = _guard()
        result = g.scan(
            tool_name="http.fetch",
            args={"url": "http://169.254.169.254/latest/meta-data/"},
        )
        assert not result.allowed
        assert result.findings[0].arg_path == "url"
        assert result.findings[0].metadata["category"] == "cloud_metadata"

    def test_scan_walks_nested_args(self) -> None:
        g = _guard(resolver=_fake_resolver({"good.example": ["8.8.8.8"]}))
        result = g.scan(
            tool_name="http.fetch",
            args={
                "good": "https://good.example/",
                "config": {"redirect": "http://10.0.0.1/admin"},
            },
        )
        assert not result.allowed
        assert any(
            f.arg_path == "config.redirect" for f in result.findings
        )

    def test_scan_allowed_when_no_urls(self) -> None:
        g = _guard()
        result = g.scan(tool_name="echo", args={"text": "hello"})
        assert result.allowed

    def test_scan_skips_ambient_text(self) -> None:
        # URLs in prose should still be checked, but pure prose should
        # not produce findings.
        g = _guard()
        result = g.scan(
            tool_name="echo",
            args={"text": "no urls in this string"},
        )
        assert result.allowed
