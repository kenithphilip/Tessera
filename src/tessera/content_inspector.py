"""Content-type-aware inspection pipeline for multimodal tool outputs.

Tool outputs can contain images, PDFs, audio, HTML, and other non-text
formats. Standard adapters call str(output) on these, flattening them
into Python repr strings that bypass all content scanners. This module
sits BEFORE the adapter's str() conversion and inspects content based
on its actual type.

The pipeline:
    Tool Output -> ContentTypeDetector -> ContentInspector -> Scanners -> Adapter
                                              |
                        +---------------------+---------------------+
                        v                     v                     v
                 ImageInspector        PDFInspector          AudioInspector
                 (metadata +           (sandbox parse +     (transcript +
                  OCR if available)     structure check)     keyword check)

Each inspector extracts text, checks for structural threats, and returns
an InspectionResult with extracted text, detected threats, and a trust
recommendation. The extracted text then flows through Tessera's standard
text scanners (heuristic, directive, intent, schema enforcement).

External dependencies are optional:
- OCR: tesseract (via pytesseract) for image text extraction
- Audio: whisper for transcription
- PDF text: pdfplumber or PyPDF2 for text extraction
All inspectors degrade gracefully when dependencies are absent,
falling back to metadata-only inspection.

References:
- OWASP LLM01:2025 multimodal injection risk
- GPT-4o image injection (Arxiv 2509.05883)
- Adobe Reader zero-day (April 2026) via malicious PDF JavaScript
- IBM X-Force 2025: 42% malicious PDFs use obfuscated URLs
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ContentType(StrEnum):
    TEXT = "text"
    IMAGE = "image"
    PDF = "pdf"
    AUDIO = "audio"
    HTML = "html"
    BINARY = "binary"
    UNKNOWN = "unknown"


class TrustRecommendation(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class InspectionResult:
    """Result of inspecting one piece of tool output content."""

    content_type: ContentType
    extracted_text: str        # text extracted from the content
    threats: tuple[str, ...]   # detected threat descriptions
    trust: TrustRecommendation
    metadata: dict[str, Any]   # content-specific metadata
    content_hash: str          # SHA-256 of the raw content


# MIME type to ContentType mapping
_MIME_MAP: dict[str, ContentType] = {
    "image/png": ContentType.IMAGE,
    "image/jpeg": ContentType.IMAGE,
    "image/webp": ContentType.IMAGE,
    "image/gif": ContentType.IMAGE,
    "image/svg+xml": ContentType.IMAGE,
    "application/pdf": ContentType.PDF,
    "audio/wav": ContentType.AUDIO,
    "audio/mp3": ContentType.AUDIO,
    "audio/mpeg": ContentType.AUDIO,
    "audio/ogg": ContentType.AUDIO,
    "text/html": ContentType.HTML,
    "application/xhtml+xml": ContentType.HTML,
}

# Magic bytes for content type detection
_MAGIC_BYTES: list[tuple[bytes, ContentType]] = [
    (b"%PDF", ContentType.PDF),
    (b"\xff\xd8\xff", ContentType.IMAGE),        # JPEG
    (b"\x89PNG\r\n\x1a\n", ContentType.IMAGE),   # PNG
    (b"GIF8", ContentType.IMAGE),                  # GIF
    (b"RIFF", ContentType.IMAGE),                  # WEBP (RIFF container)
    (b"<!DOCTYPE html", ContentType.HTML),
    (b"<html", ContentType.HTML),
]


def detect_content_type(output: Any) -> ContentType:
    """Detect the content type of a tool output.

    Checks explicit type markers, MIME types, magic bytes, and
    structural heuristics.
    """
    if isinstance(output, dict):
        # Explicit type or MIME markers
        ct = str(output.get("type", "")).lower()
        mime = str(output.get("mime_type", output.get("mimeType", ""))).lower()

        if ct in ("image", "img") or mime.startswith("image/"):
            return ContentType.IMAGE
        if ct == "pdf" or mime == "application/pdf":
            return ContentType.PDF
        if ct in ("audio", "speech") or mime.startswith("audio/"):
            return ContentType.AUDIO
        if mime in _MIME_MAP:
            return _MIME_MAP[mime]

        # Check for base64-encoded data field
        data = output.get("data", "")
        if isinstance(data, str) and len(data) > 100:
            stripped = data.replace("\n", "").replace("\r", "")
            if re.match(r"^[A-Za-z0-9+/=]{100,}$", stripped[:200]):
                return ContentType.BINARY

    if isinstance(output, bytes):
        for magic, ct in _MAGIC_BYTES:
            if output[:len(magic)] == magic:
                return ct
        return ContentType.BINARY

    if isinstance(output, str):
        stripped = output.strip()
        if stripped.startswith("<!DOCTYPE html") or stripped.startswith("<html"):
            return ContentType.HTML
        # Check for base64
        if len(stripped) > 200 and re.match(r"^[A-Za-z0-9+/=\n]{200,}$", stripped[:300]):
            return ContentType.BINARY

    return ContentType.TEXT


def _inspect_image(output: Any) -> InspectionResult:
    """Inspect image content for metadata injection and hidden text."""
    from tessera.scanners.binary_content import scan_binary, scan_text_for_hidden_binary

    threats: list[str] = []
    extracted_text = ""
    metadata: dict[str, Any] = {"inspector": "image"}

    # Get raw bytes
    raw: bytes = b""
    if isinstance(output, bytes):
        raw = output
    elif isinstance(output, dict):
        data = output.get("data", "")
        if isinstance(data, str):
            try:
                raw = base64.b64decode(data)
            except Exception:
                raw = data.encode("utf-8", errors="replace")
        elif isinstance(data, bytes):
            raw = data

    if raw:
        # Deep image analysis: steganography, invisible text, adversarial,
        # metadata injection (all in one pass)
        from tessera.scanners.image_inspector import analyze_image

        analysis = analyze_image(output)
        metadata["steganography_score"] = analysis.steganography_score
        metadata["adversarial_score"] = analysis.adversarial_score

        if analysis.metadata_threats:
            threats.extend(analysis.metadata_threats)
        if analysis.steganography_score > 0.85:
            threats.append(
                f"LSB steganography suspected (score={analysis.steganography_score:.2f})"
            )
        if analysis.invisible_text:
            threats.append("invisible/low-contrast text detected in image")
            extracted_text = analysis.invisible_text
            metadata["invisible_text_found"] = True
        if analysis.adversarial_score > 0.7:
            threats.append(
                f"adversarial perturbation suspected (score={analysis.adversarial_score:.2f})"
            )

        # Also try standard OCR if invisible text detection didn't produce text
        if not extracted_text:
            try:
                import pytesseract
                from PIL import Image
                import io

                img = Image.open(io.BytesIO(raw))
                ocr_text = pytesseract.image_to_string(img)
                if ocr_text.strip():
                    extracted_text = ocr_text
                    metadata["ocr_extracted"] = True
                    metadata["ocr_length"] = len(ocr_text)
            except ImportError:
                metadata["ocr_available"] = False
            except Exception as e:
                metadata["ocr_error"] = str(e)[:100]

    content_hash = hashlib.sha256(raw or str(output).encode()).hexdigest()
    trust = TrustRecommendation.BLOCKED if threats else TrustRecommendation.UNTRUSTED

    return InspectionResult(
        content_type=ContentType.IMAGE,
        extracted_text=extracted_text,
        threats=tuple(threats),
        trust=trust,
        metadata=metadata,
        content_hash=content_hash,
    )


def _inspect_pdf(output: Any) -> InspectionResult:
    """Inspect PDF content for active threats and extract text."""
    from tessera.scanners.binary_content import scan_binary

    threats: list[str] = []
    extracted_text = ""
    metadata: dict[str, Any] = {"inspector": "pdf"}

    # Get raw bytes
    raw: bytes = b""
    if isinstance(output, bytes):
        raw = output
    elif isinstance(output, dict):
        data = output.get("data", "")
        if isinstance(data, str):
            try:
                raw = base64.b64decode(data)
            except Exception:
                raw = data.encode("utf-8", errors="replace")
        elif isinstance(data, bytes):
            raw = data

    if raw:
        # Binary-level scan for PDF threats (JS, auto-action, XFA, etc.)
        result = scan_binary(raw, declared_mime="application/pdf")
        if not result.safe:
            threats.extend(t.detail for t in result.threats)

        # If structural threats found, do NOT attempt text extraction
        # (parsing a malicious PDF could execute embedded JS)
        if threats:
            metadata["text_extraction_skipped"] = True
            metadata["reason"] = "structural threats detected, parsing unsafe"
        else:
            # Try safe text extraction
            try:
                import pdfplumber
                import io

                with pdfplumber.open(io.BytesIO(raw)) as pdf:
                    pages = []
                    for page in pdf.pages[:20]:  # cap at 20 pages
                        text = page.extract_text()
                        if text:
                            pages.append(text)
                    extracted_text = "\n".join(pages)
                    metadata["pages_extracted"] = len(pages)
            except ImportError:
                try:
                    from PyPDF2 import PdfReader
                    import io

                    reader = PdfReader(io.BytesIO(raw))
                    pages = []
                    for page in reader.pages[:20]:
                        text = page.extract_text()
                        if text:
                            pages.append(text)
                    extracted_text = "\n".join(pages)
                    metadata["pages_extracted"] = len(pages)
                except ImportError:
                    metadata["pdf_parser_available"] = False
                except Exception as e:
                    metadata["pdf_parse_error"] = str(e)[:100]
            except Exception as e:
                metadata["pdf_parse_error"] = str(e)[:100]

    content_hash = hashlib.sha256(raw or str(output).encode()).hexdigest()

    # Block if structural threats, untrusted otherwise
    if threats:
        trust = TrustRecommendation.BLOCKED
    else:
        trust = TrustRecommendation.UNTRUSTED

    return InspectionResult(
        content_type=ContentType.PDF,
        extracted_text=extracted_text,
        threats=tuple(threats),
        trust=trust,
        metadata=metadata,
        content_hash=content_hash,
    )


def _inspect_audio(output: Any) -> InspectionResult:
    """Inspect audio content by transcription if available."""
    metadata: dict[str, Any] = {"inspector": "audio"}
    extracted_text = ""
    threats: list[str] = []

    # Try whisper transcription
    try:
        import whisper  # type: ignore[import-untyped]

        raw: bytes = b""
        if isinstance(output, bytes):
            raw = output
        elif isinstance(output, dict):
            data = output.get("data", "")
            if isinstance(data, str):
                try:
                    raw = base64.b64decode(data)
                except Exception:
                    pass

        if raw:
            import tempfile
            import os

            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
                f.write(raw)
                tmp_path = f.name
            try:
                model = whisper.load_model("tiny")
                result = model.transcribe(tmp_path)
                extracted_text = result.get("text", "")
                metadata["transcription_model"] = "whisper-tiny"
            finally:
                os.unlink(tmp_path)
    except ImportError:
        metadata["whisper_available"] = False
    except Exception as e:
        metadata["transcription_error"] = str(e)[:100]

    content_hash = hashlib.sha256(str(output)[:10000].encode()).hexdigest()

    return InspectionResult(
        content_type=ContentType.AUDIO,
        extracted_text=extracted_text,
        threats=tuple(threats),
        trust=TrustRecommendation.UNTRUSTED,
        metadata=metadata,
        content_hash=content_hash,
    )


def _inspect_html(output: Any) -> InspectionResult:
    """Inspect HTML content, stripping tags and checking for script injection."""
    text = str(output)
    threats: list[str] = []
    metadata: dict[str, Any] = {"inspector": "html"}

    # Check for script tags
    if re.search(r"<script\b", text, re.IGNORECASE):
        threats.append("HTML contains <script> tag")

    # Check for event handlers (onclick, onerror, onload, etc.)
    if re.search(r"\bon\w+\s*=", text, re.IGNORECASE):
        threats.append("HTML contains inline event handler")

    # Check for iframe injection
    if re.search(r"<iframe\b", text, re.IGNORECASE):
        threats.append("HTML contains <iframe> tag")

    # Check for form action to external URL
    if re.search(r"<form\b[^>]*action\s*=\s*['\"]https?://", text, re.IGNORECASE):
        threats.append("HTML form submits to external URL")

    # Strip tags for text extraction
    stripped = re.sub(r"<[^>]+>", " ", text)
    stripped = re.sub(r"\s+", " ", stripped).strip()

    content_hash = hashlib.sha256(text.encode()).hexdigest()
    trust = TrustRecommendation.BLOCKED if threats else TrustRecommendation.UNTRUSTED

    return InspectionResult(
        content_type=ContentType.HTML,
        extracted_text=stripped,
        threats=tuple(threats),
        trust=trust,
        metadata=metadata,
        content_hash=content_hash,
    )


def inspect_content(
    tool_output: Any,
    tool_name: str = "unknown",
) -> InspectionResult:
    """Inspect tool output content based on its detected type.

    This is the main entry point. Detects the content type, runs the
    appropriate inspector, and returns extracted text with threat
    assessment. The extracted text should then flow through Tessera's
    standard text scanners (heuristic, directive, intent).

    Args:
        tool_output: Raw tool output (dict, bytes, or string).
        tool_name: Name of the tool that produced the output.

    Returns:
        InspectionResult with extracted text, threats, and trust
        recommendation.
    """
    content_type = detect_content_type(tool_output)

    if content_type == ContentType.IMAGE:
        result = _inspect_image(tool_output)
    elif content_type == ContentType.PDF:
        result = _inspect_pdf(tool_output)
    elif content_type == ContentType.AUDIO:
        result = _inspect_audio(tool_output)
    elif content_type == ContentType.HTML:
        result = _inspect_html(tool_output)
    elif content_type == ContentType.BINARY:
        # Unknown binary: scan with binary scanner, extract nothing
        from tessera.scanners.binary_content import scan_text_for_hidden_binary

        text = str(tool_output)
        b64_result = scan_text_for_hidden_binary(text)
        threats = tuple(t.detail for t in b64_result.threats) if not b64_result.safe else ()
        result = InspectionResult(
            content_type=ContentType.BINARY,
            extracted_text="",
            threats=threats,
            trust=TrustRecommendation.BLOCKED if threats else TrustRecommendation.UNTRUSTED,
            metadata={"inspector": "binary_fallback"},
            content_hash=hashlib.sha256(text[:10000].encode()).hexdigest(),
        )
    else:
        # Plain text: no special inspection, pass through
        text = str(tool_output)
        result = InspectionResult(
            content_type=ContentType.TEXT,
            extracted_text=text,
            threats=(),
            trust=TrustRecommendation.UNTRUSTED,
            metadata={"inspector": "text_passthrough"},
            content_hash=hashlib.sha256(text[:10000].encode()).hexdigest(),
        )

    return result
