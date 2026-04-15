"""Sandboxed PDF analysis with obfuscation detection and CDR.

Scans the raw PDF object tree for dangerous keys BEFORE any parsing
library touches it, then extracts text from a sanitized copy. This
prevents attacks that execute during PDF parsing (JavaScript in font
handlers, auto-actions on open, XFA form scripts).

Five-phase pipeline:
1. Raw byte-level threat scan (no parsing library invoked)
2. Obfuscated JavaScript detection (hex-encoded streams)
3. Content Disarm and Reconstruction (strip dangerous objects)
4. Sandboxed text extraction (resource-limited subprocess)
5. URL and embedded file analysis

References:
- Adobe Reader zero-day (April 2026): JS execution via obfuscated streams
- IBM X-Force 2025: 42% malicious PDFs use obfuscated URLs
- CVE-2024-4367: JS execution via font parsing in PDF.js
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PDFInspectionResult:
    """Result of deep PDF analysis."""

    threats: tuple[str, ...]
    obfuscated_js: tuple[str, ...]    # decoded JS patterns found in hex streams
    suspicious_urls: tuple[str, ...]
    embedded_files: int
    extracted_text: str
    text_extraction_method: str       # "sanitized", "direct", "skipped", "failed"
    blocked: bool


# Dangerous PDF keys that indicate potential threats.
_DANGEROUS_KEYS: dict[bytes, str] = {
    b"/JS": "javascript_action",
    b"/JavaScript": "javascript_action",
    b"/AA": "auto_action",
    b"/OpenAction": "open_action",
    b"/Launch": "launch_action",
    b"/EmbeddedFile": "embedded_file",
    b"/XFA": "xfa_form",
    b"/AcroForm": "acro_form",
    b"/RichMedia": "rich_media",
    b"/SubmitForm": "submit_form",
    b"/ImportData": "import_data",
    b"/GoToR": "remote_goto",
    b"/GoToE": "embedded_goto",
}

# Critical threats that block immediately
_CRITICAL_THREATS = frozenset({
    "javascript_action",
    "auto_action",
    "open_action",
    "launch_action",
    "xfa_form",
})

# JavaScript API patterns common in malicious PDFs.
# These are byte-literal patterns scanned in raw PDF content to detect
# malicious JS payloads that execute during parsing.
_JS_API_CALLS: tuple[bytes, ...] = (
    b"unescape(",
    b"String.fromCharCode",
    b"app.alert",
    b"this.exportDataObject",
    b"getAnnots",
    b"getField",
    b"submitForm",
    b"app.launchURL",
    b"this.getURL",
    b"util.printf",
    b"spell.customDictionaryOpen",
    b"media.newPlayer",
    b"Collab.getIcon",
)

# URL pattern in PDF streams
_URL_PATTERN = re.compile(rb"https?://[\w./-]+(?:\?\S+)?")

# Suspicious URL indicators
_SUSPICIOUS_URL_PATTERNS = re.compile(
    rb"(?:"
    rb"bit\.ly|tinyurl|t\.co|goo\.gl|"
    rb"pastebin\.com|hastebin|"
    rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    rb"\.tk/|\.ml/|\.ga/|\.cf/|"
    rb"ngrok\.io|cloudflare-ipfs"
    rb")",
    re.IGNORECASE,
)


def _scan_raw_keys(data: bytes) -> list[str]:
    """Byte-level scan for dangerous PDF keys. No parsing library."""
    threats: list[str] = []
    seen: set[str] = set()
    for key, threat_name in _DANGEROUS_KEYS.items():
        if key in data and threat_name not in seen:
            threats.append(threat_name)
            seen.add(threat_name)
    return threats


def _detect_obfuscated_js(data: bytes) -> list[str]:
    """Detect JavaScript hidden in hex-encoded PDF streams.

    Malicious PDFs encode JS payloads as hex strings inside angle brackets:
    <4576616C28...> which decodes to payload content.
    """
    found: list[str] = []

    # Find hex-encoded stream content (at least 60 hex chars)
    hex_streams = re.findall(rb"<([0-9A-Fa-f\s]{60,})>", data)
    for stream in hex_streams:
        try:
            cleaned = stream.decode("ascii", errors="replace").replace(" ", "")
            if len(cleaned) % 2 != 0:
                continue
            decoded = bytes.fromhex(cleaned)
            for pattern in _JS_API_CALLS:
                if pattern in decoded:
                    found.append(
                        f"hex_obfuscated: {pattern.decode('ascii', errors='replace')}"
                    )
        except (ValueError, UnicodeDecodeError):
            continue

    # Also check for raw JS patterns in plaintext
    for pattern in _JS_API_CALLS:
        if pattern in data:
            label = pattern.decode("ascii", errors="replace")
            entry = f"plaintext: {label}"
            if entry not in found:
                found.append(entry)

    return found


def _extract_urls(data: bytes) -> list[str]:
    """Extract all URLs from PDF content."""
    urls: list[str] = []
    for m in _URL_PATTERN.finditer(data):
        url = m.group(0).decode("ascii", errors="replace")
        if url not in urls:
            urls.append(url)
    return urls


def _classify_urls(urls: list[str]) -> list[str]:
    """Flag suspicious URLs (shorteners, raw IPs, free TLDs)."""
    suspicious: list[str] = []
    for url in urls:
        if _SUSPICIOUS_URL_PATTERNS.search(url.encode()):
            suspicious.append(url)
    return suspicious


def _count_embedded_files(data: bytes) -> int:
    """Count embedded file references in the PDF."""
    return len(re.findall(rb"/EmbeddedFile", data))


def _sanitize_pdf(data: bytes) -> bytes:
    """Content Disarm and Reconstruction: strip dangerous objects.

    Replaces dangerous PDF keys with neutralized versions of the same
    byte length to preserve cross-reference table offsets. This is a
    conservative byte-level CDR, not a full PDF object-tree rewrite.
    """
    result = data
    replacements: list[tuple[bytes, bytes]] = [
        (b"/JS ", b"/XX "),
        (b"/JS(", b"/XX("),
        (b"/JS<", b"/XX<"),
        (b"/JavaScript ", b"/Xxxxxxxxxxx "),
        (b"/JavaScript(", b"/Xxxxxxxxxxx("),
        (b"/AA ", b"/XX "),
        (b"/AA<", b"/XX<"),
        (b"/OpenAction ", b"/Xxxxxxxxxxx "),
        (b"/OpenAction<", b"/Xxxxxxxxxxx<"),
        (b"/OpenAction[", b"/Xxxxxxxxxxx["),
        (b"/Launch ", b"/Xxxxxx "),
        (b"/Launch<", b"/Xxxxxx<"),
        (b"/XFA ", b"/XXX "),
        (b"/XFA[", b"/XXX["),
        (b"/XFA<", b"/XXX<"),
    ]
    for old, new in replacements:
        result = result.replace(old, new)
    return result


def _extract_text_safe(data: bytes, timeout_seconds: int = 10) -> tuple[str, str]:
    """Extract text from PDF bytes with fallback chain.

    Tries sandboxed subprocess first, then direct pdfplumber, then PyPDF2.
    Returns (text, method_used).
    """
    # Method 1: sandboxed subprocess with timeout
    try:
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(data)
            pdf_path = f.name

        try:
            result = subprocess.run(
                [
                    "timeout", str(timeout_seconds),
                    "python3", "-c",
                    (
                        "import pdfplumber, sys; "
                        f"pdf=pdfplumber.open('{pdf_path}'); "
                        "[sys.stdout.write((p.extract_text() or '')[:10000]) "
                        "for p in pdf.pages[:20]]"
                    ),
                ],
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 2,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout[:100000], "sandboxed"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        finally:
            os.unlink(pdf_path)
    except Exception:
        pass

    # Method 2: direct pdfplumber
    try:
        import pdfplumber
        import io

        with pdfplumber.open(io.BytesIO(data)) as pdf:
            pages = []
            for page in pdf.pages[:20]:
                text = page.extract_text()
                if text:
                    pages.append(text)
            if pages:
                return "\n".join(pages)[:100000], "direct_pdfplumber"
    except ImportError:
        pass
    except Exception:
        pass

    # Method 3: PyPDF2
    try:
        from PyPDF2 import PdfReader
        import io

        reader = PdfReader(io.BytesIO(data))
        pages = []
        for page in reader.pages[:20]:
            text = page.extract_text()
            if text:
                pages.append(text)
        if pages:
            return "\n".join(pages)[:100000], "direct_pypdf2"
    except ImportError:
        pass
    except Exception:
        pass

    return "", "failed"


def inspect_pdf(content: Any) -> PDFInspectionResult:
    """Full PDF inspection pipeline.

    Args:
        content: PDF content (bytes or dict with data field).

    Returns:
        PDFInspectionResult with threats, extracted text, and block status.
    """
    import base64

    # Extract raw bytes
    raw: bytes = b""
    if isinstance(content, bytes):
        raw = content
    elif isinstance(content, dict):
        data = content.get("data", "")
        if isinstance(data, str):
            try:
                raw = base64.b64decode(data)
            except Exception:
                raw = data.encode("utf-8", errors="replace")
        elif isinstance(data, bytes):
            raw = data

    if not raw or not raw.startswith(b"%PDF"):
        return PDFInspectionResult(
            threats=("not_a_pdf",),
            obfuscated_js=(),
            suspicious_urls=(),
            embedded_files=0,
            extracted_text="",
            text_extraction_method="skipped",
            blocked=True,
        )

    # Phase 1: raw key scan
    key_threats = _scan_raw_keys(raw)

    # Phase 2: obfuscated JS detection
    obfuscated = _detect_obfuscated_js(raw)

    all_threats = list(key_threats)
    if obfuscated:
        all_threats.append("obfuscated_javascript")

    is_critical = bool(set(key_threats) & _CRITICAL_THREATS) or bool(obfuscated)

    # Phase 5: URL analysis (always runs)
    urls = _extract_urls(raw)
    suspicious = _classify_urls(urls)

    if is_critical:
        return PDFInspectionResult(
            threats=tuple(all_threats),
            obfuscated_js=tuple(obfuscated),
            suspicious_urls=tuple(suspicious),
            embedded_files=_count_embedded_files(raw),
            extracted_text="",
            text_extraction_method="skipped",
            blocked=True,
        )

    # Phase 3+4: sanitize and extract text
    sanitized = _sanitize_pdf(raw)
    text, method = _extract_text_safe(sanitized)

    if suspicious:
        all_threats.append("suspicious_urls")

    return PDFInspectionResult(
        threats=tuple(all_threats),
        obfuscated_js=tuple(obfuscated),
        suspicious_urls=tuple(suspicious),
        embedded_files=_count_embedded_files(raw),
        extracted_text=text,
        text_extraction_method=method,
        blocked=bool(all_threats),
    )
