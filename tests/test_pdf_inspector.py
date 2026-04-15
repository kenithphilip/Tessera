"""Tests for sandboxed PDF inspection pipeline."""

from __future__ import annotations

import pytest

from tessera.scanners.pdf_inspector import (
    PDFInspectionResult,
    inspect_pdf,
    _classify_urls,
    _count_embedded_files,
    _detect_obfuscated_js,
    _extract_urls,
    _sanitize_pdf,
    _scan_raw_keys,
)


class TestRawKeyScan:
    def test_clean_pdf_no_threats(self) -> None:
        data = b"%PDF-1.4 clean content without dangerous keys"
        threats = _scan_raw_keys(data)
        assert threats == []

    def test_javascript_detected(self) -> None:
        data = b"%PDF-1.4\n/JS (payload)\nendobj"
        threats = _scan_raw_keys(data)
        assert "javascript_action" in threats

    def test_auto_action_detected(self) -> None:
        data = b"%PDF-1.4\n/AA << action >>"
        threats = _scan_raw_keys(data)
        assert "auto_action" in threats

    def test_launch_detected(self) -> None:
        data = b"%PDF-1.4\n/Launch << /F (cmd.exe) >>"
        threats = _scan_raw_keys(data)
        assert "launch_action" in threats

    def test_xfa_detected(self) -> None:
        data = b"%PDF-1.4\n/XFA [form data]"
        threats = _scan_raw_keys(data)
        assert "xfa_form" in threats

    def test_multiple_threats(self) -> None:
        data = b"%PDF-1.4\n/JS (x)\n/Launch << >>\n/XFA [y]"
        threats = _scan_raw_keys(data)
        assert len(threats) >= 3


class TestObfuscatedJSDetection:
    def test_plaintext_js_api_detected(self) -> None:
        data = b"%PDF-1.4\napp.launchURL('http://evil.com')"
        found = _detect_obfuscated_js(data)
        assert any("app.launchURL" in f for f in found)

    def test_hex_encoded_js_detected(self) -> None:
        # Payload must be >= 30 bytes to produce >= 60 hex chars
        payload = b"padding_content_here_" + b"app.alert('you have been hacked')"
        hex_encoded = payload.hex().encode()
        data = b"%PDF-1.4\n<" + hex_encoded + b">"
        found = _detect_obfuscated_js(data)
        assert any("app.alert" in f for f in found)

    def test_clean_hex_no_detection(self) -> None:
        # Hex-encoded "Hello World" (no JS patterns)
        payload = b"Hello World, this is plain text content for testing"
        hex_encoded = payload.hex().encode()
        data = b"%PDF-1.4\n<" + hex_encoded + b">"
        found = _detect_obfuscated_js(data)
        assert found == []


class TestURLExtraction:
    def test_urls_extracted(self) -> None:
        data = b"%PDF-1.4\n/URI (https://example.com/page)\nendobj"
        urls = _extract_urls(data)
        assert "https://example.com/page" in urls

    def test_suspicious_url_flagged(self) -> None:
        urls = ["https://bit.ly/abcdef", "https://safe-company.com/docs"]
        suspicious = _classify_urls(urls)
        assert "https://bit.ly/abcdef" in suspicious
        assert "https://safe-company.com/docs" not in suspicious

    def test_raw_ip_flagged(self) -> None:
        urls = ["http://192.168.1.100/payload"]
        suspicious = _classify_urls(urls)
        assert len(suspicious) == 1


class TestCDRSanitization:
    def test_js_key_neutralized(self) -> None:
        data = b"%PDF-1.4\n/JS (payload)"
        sanitized = _sanitize_pdf(data)
        assert b"/JS " not in sanitized
        assert b"/JS(" not in sanitized

    def test_openaction_neutralized(self) -> None:
        data = b"%PDF-1.4\n/OpenAction << /S /JavaScript >>"
        sanitized = _sanitize_pdf(data)
        assert b"/OpenAction " not in sanitized

    def test_clean_pdf_unchanged(self) -> None:
        data = b"%PDF-1.4\n/Type /Page\n/MediaBox [0 0 612 792]"
        sanitized = _sanitize_pdf(data)
        assert b"/Type" in sanitized
        assert b"/MediaBox" in sanitized

    def test_sanitized_length_preserved(self) -> None:
        """CDR preserves byte length for cross-reference table compatibility."""
        data = b"%PDF-1.4\n/JS (x)\n/Launch << >>"
        sanitized = _sanitize_pdf(data)
        assert len(sanitized) == len(data)


class TestEmbeddedFiles:
    def test_count_embedded(self) -> None:
        data = b"%PDF-1.4\n/EmbeddedFile one\n/EmbeddedFile two"
        assert _count_embedded_files(data) == 2

    def test_no_embedded(self) -> None:
        data = b"%PDF-1.4\nclean content"
        assert _count_embedded_files(data) == 0


class TestInspectPDF:
    def test_clean_pdf(self) -> None:
        data = b"%PDF-1.4\n/Type /Page\n/MediaBox [0 0 612 792]"
        result = inspect_pdf(data)
        assert not result.blocked
        assert result.threats == ()

    def test_javascript_blocks(self) -> None:
        data = b"%PDF-1.4\n/JS (payload)\nendobj"
        result = inspect_pdf(data)
        assert result.blocked
        assert "javascript_action" in result.threats
        assert result.text_extraction_method == "skipped"

    def test_obfuscated_js_blocks(self) -> None:
        payload = b"app.launchURL('http://evil.com')"
        hex_encoded = payload.hex().encode()
        data = b"%PDF-1.4\n<" + hex_encoded + b">"
        result = inspect_pdf(data)
        assert result.blocked
        assert "obfuscated_javascript" in result.threats

    def test_not_a_pdf(self) -> None:
        result = inspect_pdf(b"not a pdf at all")
        assert result.blocked
        assert "not_a_pdf" in result.threats

    def test_dict_input_handled(self) -> None:
        import base64
        raw = b"%PDF-1.4\n/Type /Page"
        content = {"data": base64.b64encode(raw).decode()}
        result = inspect_pdf(content)
        assert not result.blocked

    def test_suspicious_url_in_clean_pdf(self) -> None:
        data = b"%PDF-1.4\n/URI (https://bit.ly/malware)"
        result = inspect_pdf(data)
        assert "https://bit.ly/malware" in result.suspicious_urls
