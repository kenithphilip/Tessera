"""Hidden Unicode tag detection.

Unicode tag block (U+E0000..U+E007F) characters are invisible in most
renderers but some LLM tokenizers decode them. Attackers can use them to
embed hidden instructions in documents, web pages, or tool outputs that
look clean to human reviewers.

Technique: scan for any code point in the tag block, decode the hidden
payload by subtracting 0xE0000 from each tag character, and include the
decoded string in the SecurityEvent for forensic inspection.

Source attribution: PurpleLlama HiddenASCIIScanner
(promptguard/src/hidden_ascii_scanner.py).
"""

from __future__ import annotations

from dataclasses import dataclass

# Unicode tag block: U+E0000..U+E007F
# U+E0001 is the deprecated "language tag" control. U+E0020..U+E007E are
# tag space through tag tilde -- printable ASCII clones used for encoding.
_TAG_START = 0xE0000
_TAG_END = 0xE007F
_TAG_PRINTABLE_START = 0xE0020  # corresponds to ASCII space
_TAG_PRINTABLE_END = 0xE007E    # corresponds to ASCII tilde


@dataclass(frozen=True)
class UnicodeScanResult:
    """Result of scanning a string for hidden Unicode tag characters."""

    detected: bool
    hidden_payload: str
    tag_count: int
    positions: tuple[int, ...]


def scan_unicode_tags(text: str) -> UnicodeScanResult:
    """Scan text for hidden Unicode tag block characters (U+E0000..U+E007F).

    When tag characters are found, decodes the hidden payload by mapping
    each tag code point back to its ASCII equivalent (cp - 0xE0000).

    Args:
        text: The text to scan.

    Returns:
        UnicodeScanResult with detection flag, decoded payload, count, and
        positions of tag characters.
    """
    tag_chars: list[tuple[int, str]] = []  # (position, decoded char)

    for i, ch in enumerate(text):
        cp = ord(ch)
        if _TAG_START <= cp <= _TAG_END:
            # Decode: subtract base to get ASCII code point.
            # Non-printable tag chars (U+E0000, U+E0001) map to control
            # characters; include them for forensics but strip from display.
            ascii_cp = cp - _TAG_START
            decoded = chr(ascii_cp) if 0x20 <= ascii_cp <= 0x7E else ""
            tag_chars.append((i, decoded))

    if not tag_chars:
        return UnicodeScanResult(
            detected=False,
            hidden_payload="",
            tag_count=0,
            positions=(),
        )

    positions = tuple(pos for pos, _ in tag_chars)
    hidden_payload = "".join(ch for _, ch in tag_chars if ch)

    return UnicodeScanResult(
        detected=True,
        hidden_payload=hidden_payload,
        tag_count=len(tag_chars),
        positions=positions,
    )


def scan_and_emit(text: str, principal: str, source: str = "unknown") -> UnicodeScanResult:
    """Scan text and emit a SecurityEvent if hidden tag characters are found.

    Args:
        text: The text to scan.
        principal: The principal associated with this content (for the event).
        source: Human-readable source label (e.g., tool name, URL).

    Returns:
        UnicodeScanResult, same as scan_unicode_tags.
    """
    result = scan_unicode_tags(text)
    if result.detected:
        from tessera.events import EventKind, SecurityEvent, emit

        emit(
            SecurityEvent.now(
                kind=EventKind.CONTENT_INJECTION_DETECTED,
                principal=principal,
                detail={
                    "scanner": "unicode_tag",
                    "source": source,
                    "tag_count": result.tag_count,
                    "hidden_payload": result.hidden_payload,
                    "first_position": result.positions[0] if result.positions else None,
                    "owasp": "LLM01",
                    "rule": "AGENT-unicode-tag-steganography",
                },
            )
        )
    return result
