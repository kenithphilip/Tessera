"""Binary content scanning for multimodal injection vectors.

Tool outputs can contain images, PDFs, audio, and other binary formats.
Standard adapters call str(output) on these, converting them to Python
repr strings that flow through text scanners without meaningful analysis.
A malicious document can contain hidden instructions that survive this
conversion: PDF JavaScript, image EXIF metadata with injection payloads,
QR codes encoding attacker commands, or steganographic text.

This scanner operates on raw binary content BEFORE text extraction. It
checks for known injection vectors in the binary structure itself:

1. PDF threats: embedded JavaScript (/JS, /AA auto-action), XFA forms,
   launch actions, URI actions, embedded files
2. Image metadata: EXIF comments, XMP descriptions, IPTC captions that
   contain injection text
3. Base64 payloads: detects and decodes base64-encoded content that may
   contain hidden instructions
4. Content type validation: rejects content whose declared MIME type
   does not match its actual structure

The scanner does NOT perform OCR or visual analysis. It catches threats
in the binary structure that text scanners miss. Post-OCR text still
flows through the directive and intent scanners as before.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from enum import StrEnum


class BinaryThreatCategory(StrEnum):
    PDF_JAVASCRIPT = "pdf_javascript"
    PDF_AUTO_ACTION = "pdf_auto_action"
    PDF_LAUNCH_ACTION = "pdf_launch_action"
    PDF_URI_ACTION = "pdf_uri_action"
    PDF_EMBEDDED_FILE = "pdf_embedded_file"
    PDF_XFA_FORM = "pdf_xfa_form"
    IMAGE_METADATA_INJECTION = "image_metadata_injection"
    BASE64_HIDDEN_PAYLOAD = "base64_hidden_payload"
    MIME_MISMATCH = "mime_mismatch"


@dataclass(frozen=True)
class BinaryThreatMatch:
    category: BinaryThreatCategory
    detail: str
    offset: int | None = None  # byte offset in the content


@dataclass(frozen=True)
class BinaryScanResult:
    """Result of scanning binary content for injection vectors."""

    threats: tuple[BinaryThreatMatch, ...]
    safe: bool
    score: float  # 0.0-1.0


# PDF threat patterns (byte-level, work on raw PDF bytes)
_PDF_JAVASCRIPT = re.compile(rb"/JS\s*[\(<]|/JavaScript\s*[\(<]", re.IGNORECASE)
_PDF_AUTO_ACTION = re.compile(rb"/AA\s*<<|/OpenAction\s*<<|/OpenAction\s*\[")
_PDF_LAUNCH = re.compile(rb"/Launch\s*<<|/S\s*/Launch")
_PDF_URI = re.compile(rb"/URI\s*\(|/S\s*/URI")
_PDF_EMBEDDED = re.compile(rb"/EmbeddedFile|/Filespec|/F\s*\(")
_PDF_XFA = re.compile(rb"/XFA\s*[\[<]")

# Image metadata fields that can carry text injection
_EXIF_COMMENT = re.compile(rb"(?:UserComment|ImageDescription|XPComment)\x00", re.IGNORECASE)
_XMP_DESCRIPTION = re.compile(rb"<dc:description>|<xmp:Description|<photoshop:Instructions", re.IGNORECASE)
_IPTC_CAPTION = re.compile(rb"\x1c\x02[\x78\x7a]", re.IGNORECASE)  # IPTC caption/abstract

# Injection indicators in metadata text
_METADATA_INJECTION = re.compile(
    rb"(?:ignore|disregard|forget|override).{0,20}(?:previous|prior|above|earlier)|"
    rb"(?:TODO|TASK|IMPORTANT)[:\-!]|"
    rb"(?:send|transfer|forward|email).{0,30}(?:to|@)",
    re.IGNORECASE,
)


def _scan_pdf(data: bytes) -> list[BinaryThreatMatch]:
    """Scan PDF bytes for active content threats."""
    threats: list[BinaryThreatMatch] = []

    for m in _PDF_JAVASCRIPT.finditer(data):
        threats.append(BinaryThreatMatch(
            category=BinaryThreatCategory.PDF_JAVASCRIPT,
            detail="PDF contains JavaScript action",
            offset=m.start(),
        ))

    for m in _PDF_AUTO_ACTION.finditer(data):
        threats.append(BinaryThreatMatch(
            category=BinaryThreatCategory.PDF_AUTO_ACTION,
            detail="PDF contains auto-action (runs on open)",
            offset=m.start(),
        ))

    for m in _PDF_LAUNCH.finditer(data):
        threats.append(BinaryThreatMatch(
            category=BinaryThreatCategory.PDF_LAUNCH_ACTION,
            detail="PDF contains launch action (can execute programs)",
            offset=m.start(),
        ))

    for m in _PDF_URI.finditer(data):
        threats.append(BinaryThreatMatch(
            category=BinaryThreatCategory.PDF_URI_ACTION,
            detail="PDF contains URI action",
            offset=m.start(),
        ))

    for m in _PDF_EMBEDDED.finditer(data):
        threats.append(BinaryThreatMatch(
            category=BinaryThreatCategory.PDF_EMBEDDED_FILE,
            detail="PDF contains embedded file",
            offset=m.start(),
        ))

    for m in _PDF_XFA.finditer(data):
        threats.append(BinaryThreatMatch(
            category=BinaryThreatCategory.PDF_XFA_FORM,
            detail="PDF contains XFA form (can contain scripts)",
            offset=m.start(),
        ))

    return threats


def _scan_image_metadata(data: bytes) -> list[BinaryThreatMatch]:
    """Scan image bytes for injection in metadata fields."""
    threats: list[BinaryThreatMatch] = []

    # Check for injection patterns in metadata regions
    for pattern in (_EXIF_COMMENT, _XMP_DESCRIPTION, _IPTC_CAPTION):
        for m in pattern.finditer(data):
            # Extract the surrounding bytes to check for injection content
            region = data[m.start():min(m.end() + 500, len(data))]
            if _METADATA_INJECTION.search(region):
                threats.append(BinaryThreatMatch(
                    category=BinaryThreatCategory.IMAGE_METADATA_INJECTION,
                    detail="Image metadata contains injection-like text",
                    offset=m.start(),
                ))
                break  # one match is enough

    return threats


def _scan_base64_payload(text: str) -> list[BinaryThreatMatch]:
    """Check if a base64 string decodes to content with injection markers."""
    threats: list[BinaryThreatMatch] = []

    # Find base64-encoded segments (at least 40 chars to avoid false matches)
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    for m in b64_pattern.finditer(text):
        try:
            decoded = base64.b64decode(m.group(0))
            if _METADATA_INJECTION.search(decoded):
                threats.append(BinaryThreatMatch(
                    category=BinaryThreatCategory.BASE64_HIDDEN_PAYLOAD,
                    detail="Base64-encoded content contains injection text",
                    offset=m.start(),
                ))
        except Exception:
            continue

    return threats


def _detect_content_type(data: bytes) -> str | None:
    """Detect actual content type from magic bytes."""
    if data[:4] == b"%PDF":
        return "application/pdf"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:4] == b"GIF8":
        return "image/gif"
    if data[:4] in (b"RIFF", b"WEBP"):
        return "image/webp"
    if data[:4] == b"\x00\x00\x01\x00":
        return "image/x-icon"
    if data[:2] == b"PK":
        return "application/zip"  # also DOCX, XLSX, PPTX
    return None


def scan_binary(
    data: bytes,
    declared_mime: str | None = None,
) -> BinaryScanResult:
    """Scan binary content for injection vectors.

    Checks for PDF active content, image metadata injection, and
    MIME type mismatches. Does not perform OCR or visual analysis.

    Args:
        data: Raw binary content.
        declared_mime: The MIME type claimed by the source. If provided,
            checked against actual content type for mismatches.

    Returns:
        BinaryScanResult with threat details and safety flag.
    """
    if not data:
        return BinaryScanResult(threats=(), safe=True, score=0.0)

    threats: list[BinaryThreatMatch] = []

    # MIME type validation
    actual_mime = _detect_content_type(data)
    if declared_mime and actual_mime and declared_mime != actual_mime:
        threats.append(BinaryThreatMatch(
            category=BinaryThreatCategory.MIME_MISMATCH,
            detail=f"declared={declared_mime}, actual={actual_mime}",
        ))

    # Content-type-specific scanning
    if actual_mime == "application/pdf" or data[:4] == b"%PDF":
        threats.extend(_scan_pdf(data))

    if actual_mime and actual_mime.startswith("image/"):
        threats.extend(_scan_image_metadata(data))

    # Always check for image metadata even if MIME is unknown
    if not actual_mime:
        threats.extend(_scan_image_metadata(data))

    # Score: PDF JS and launch actions are critical (0.9+),
    # metadata injection is high (0.7), MIME mismatch is medium (0.4)
    if not threats:
        return BinaryScanResult(threats=(), safe=True, score=0.0)

    _CATEGORY_SCORES = {
        BinaryThreatCategory.PDF_JAVASCRIPT: 0.95,
        BinaryThreatCategory.PDF_LAUNCH_ACTION: 0.95,
        BinaryThreatCategory.PDF_AUTO_ACTION: 0.85,
        BinaryThreatCategory.PDF_XFA_FORM: 0.8,
        BinaryThreatCategory.PDF_EMBEDDED_FILE: 0.6,
        BinaryThreatCategory.PDF_URI_ACTION: 0.5,
        BinaryThreatCategory.IMAGE_METADATA_INJECTION: 0.7,
        BinaryThreatCategory.BASE64_HIDDEN_PAYLOAD: 0.8,
        BinaryThreatCategory.MIME_MISMATCH: 0.4,
    }
    score = max(_CATEGORY_SCORES.get(t.category, 0.5) for t in threats)

    return BinaryScanResult(
        threats=tuple(threats),
        safe=False,
        score=score,
    )


def scan_text_for_hidden_binary(text: str) -> BinaryScanResult:
    """Scan text content for hidden base64-encoded payloads.

    Tool outputs sometimes contain base64-encoded content inline.
    This function finds and decodes those payloads, checking the
    decoded content for injection markers.

    Args:
        text: Text that may contain embedded base64 content.

    Returns:
        BinaryScanResult for any hidden payloads found.
    """
    threats = _scan_base64_payload(text)
    if not threats:
        return BinaryScanResult(threats=(), safe=True, score=0.0)

    score = max(0.8 if t.category == BinaryThreatCategory.BASE64_HIDDEN_PAYLOAD else 0.5
                for t in threats)
    return BinaryScanResult(threats=tuple(threats), safe=False, score=score)
