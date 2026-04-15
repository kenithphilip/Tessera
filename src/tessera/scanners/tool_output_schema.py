"""Tool output schema enforcement.

Tool outputs should contain data, not instructions. A hotel search tool
should return structured records (name, rating, price, address). If it
returns prose with imperative verbs or promotional superlatives, that is
anomalous regardless of whether any directive pattern matches.

This scanner validates that tool outputs conform to their expected output
shape based on tool name patterns. It catches output manipulation attacks
that evade directive detection: injected fake reviews, promotional copy
embedded in search results, persuasive prose where facts are expected.

Detection axes:
1. Schema kind mismatch: a STRUCTURED or LIST_STRUCTURED tool returns
   significant prose paragraphs.
2. Imperative presence: any imperative verb in output that should be
   factual (structured or numeric) is anomalous.
3. Sentence length anomaly: factual tool outputs have short "sentences"
   (key:value pairs, single values). Attack payloads use longer clauses.

Tools that legitimately return free text (emails, messages, file content)
are excluded from schema enforcement. The directive scanner and output
monitor handle injection in those.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatch


class ToolOutputKind(StrEnum):
    STRUCTURED = "structured"           # key:value records, JSON objects
    LIST_STRUCTURED = "list_structured" # list of structured records
    FREE_TEXT = "free_text"             # prose: emails, messages, documents
    NUMERIC = "numeric"                 # a single number or number + units


# Tool name glob patterns -> expected output kind.
# Matched in order; first match wins. Patterns are case-insensitive.
# Tools that legitimately return free text appear first so they are
# excluded from structural checks before the broader structured patterns.
_REGISTRY: list[tuple[str, ToolOutputKind]] = [
    # Free text: injection lives here too, but schema enforcement cannot help.
    # The directive scanner and output_monitor handle these.
    # File-related tools return document content (prose), even when
    # their names match search_* or list_* patterns.
    ("*email*",            ToolOutputKind.FREE_TEXT),
    ("*message*",          ToolOutputKind.FREE_TEXT),
    ("*read_file*",        ToolOutputKind.FREE_TEXT),
    ("*file_content*",     ToolOutputKind.FREE_TEXT),
    ("*_file*",            ToolOutputKind.FREE_TEXT),  # search_files, list_files, get_file
    ("*_files*",           ToolOutputKind.FREE_TEXT),
    ("*document*",         ToolOutputKind.FREE_TEXT),
    ("*webpage*",          ToolOutputKind.FREE_TEXT),
    ("*page_content*",     ToolOutputKind.FREE_TEXT),
    ("*post*",             ToolOutputKind.FREE_TEXT),
    ("*inbox*",            ToolOutputKind.FREE_TEXT),
    ("*calendar*",         ToolOutputKind.FREE_TEXT),  # calendar events have descriptions
    ("*review*",           ToolOutputKind.FREE_TEXT),  # reviews are prose

    # Numeric: single values. Excludes plural forms (get_prices returns
    # a dict of records, not a single number).
    ("*balance*",          ToolOutputKind.NUMERIC),
    ("*count*",            ToolOutputKind.NUMERIC),
    ("*total*",            ToolOutputKind.NUMERIC),
    ("*amount*",           ToolOutputKind.NUMERIC),

    # Price/rating tools return structured dicts, not single numbers.
    ("*price*",            ToolOutputKind.STRUCTURED),
    ("*rating*",           ToolOutputKind.STRUCTURED),

    # List of structured records
    ("search_*",           ToolOutputKind.LIST_STRUCTURED),
    ("list_*",             ToolOutputKind.LIST_STRUCTURED),
    ("find_*",             ToolOutputKind.LIST_STRUCTURED),
    ("get_*s",             ToolOutputKind.LIST_STRUCTURED),

    # Single structured record
    ("get_*",              ToolOutputKind.STRUCTURED),
    ("lookup_*",           ToolOutputKind.STRUCTURED),
    ("fetch_*",            ToolOutputKind.STRUCTURED),
    ("describe_*",         ToolOutputKind.STRUCTURED),
    ("check_*",            ToolOutputKind.STRUCTURED),
    ("verify_*",           ToolOutputKind.STRUCTURED),
]

# Imperative verbs that have no place in factual structured data.
_IMPERATIVE = re.compile(
    r"(?<!\bI\s)\b(send|forward|transfer|pay|email|delete|create|update|"
    r"say|tell|recommend|suggest|visit|choose|pick|use|install|run|grant|"
    r"invite|publish|write|overwrite|include|make\s+sure|don'?t\s+forget)\b",
    re.IGNORECASE,
)

# Sentence splitter: splits on . ! ? followed by whitespace or end-of-string.
_SENTENCE_SPLIT = re.compile(r"[.!?]+(?:\s+|$)")

# Key:value marker: "Word: value" or "word = value"
_KV_MARKER = re.compile(r"\b\w[\w\s]{0,20}[:=]\s*\S")


@dataclass(frozen=True)
class ProseMetrics:
    """Structural metrics of a tool output text."""

    word_count: int
    sentence_count: int        # sentences of >= 5 words
    avg_sentence_length: float # words per prose sentence
    imperative_count: int      # imperative verb occurrences
    kv_marker_count: int       # key:value or key=value patterns


@dataclass(frozen=True)
class SchemaViolationResult:
    """Result of checking one tool output against its expected schema."""

    tool_name: str
    expected_kind: ToolOutputKind
    violation: bool
    score: float               # 0.0-1.0: severity of the violation
    reason: str                # human-readable explanation
    metrics: ProseMetrics


def _resolve_kind(tool_name: str) -> ToolOutputKind:
    """Resolve expected output kind for a tool name using the registry."""
    lower = tool_name.lower()
    for pattern, kind in _REGISTRY:
        if fnmatch(lower, pattern):
            return kind
    # Unknown tool: assume structured (conservative -- most tools return data)
    return ToolOutputKind.STRUCTURED


def _compute_metrics(text: str) -> ProseMetrics:
    words = text.split()
    word_count = len(words)

    # Count full prose sentences (>= 5 words between delimiters)
    fragments = _SENTENCE_SPLIT.split(text)
    prose = [f.strip() for f in fragments if len(f.split()) >= 5]
    avg_len = (
        sum(len(f.split()) for f in prose) / len(prose) if prose else 0.0
    )

    imperatives = len(_IMPERATIVE.findall(text))
    kv_markers = len(_KV_MARKER.findall(text))

    return ProseMetrics(
        word_count=word_count,
        sentence_count=len(prose),
        avg_sentence_length=avg_len,
        imperative_count=imperatives,
        kv_marker_count=kv_markers,
    )


def scan_tool_output(tool_name: str, output_text: str) -> SchemaViolationResult:
    """Check whether tool output conforms to the expected output schema.

    Free-text tools (emails, messages, files) are excluded from structural
    checks. Structured and numeric tools are checked for prose invasion
    and imperative language.

    Args:
        tool_name: Registered name of the tool that produced the output.
        output_text: The tool's response text.

    Returns:
        SchemaViolationResult with violation flag, score, and metrics.
    """
    kind = _resolve_kind(tool_name)
    metrics = _compute_metrics(output_text)

    # Free text tools: no structural enforcement. Directive/output monitor apply.
    if kind == ToolOutputKind.FREE_TEXT:
        return SchemaViolationResult(
            tool_name=tool_name,
            expected_kind=kind,
            violation=False,
            score=0.0,
            reason="free-text tool: schema enforcement not applicable",
            metrics=metrics,
        )

    score = 0.0
    reasons: list[str] = []

    # Key:value markers indicate structured data, even if the sentence
    # detector counts the text as "prose." "Price range: 100.0 - 180.0"
    # has a key:value marker and is not prose.
    has_kv_structure = metrics.kv_marker_count > 0

    # Numeric tools: prose without key:value markers is a violation.
    if kind == ToolOutputKind.NUMERIC:
        if metrics.sentence_count >= 1 and not has_kv_structure:
            score += 0.6
            reasons.append(
                f"numeric tool returned {metrics.sentence_count} prose sentence(s)"
            )
        if metrics.imperative_count > 0:
            score += 0.4
            reasons.append(
                f"{metrics.imperative_count} imperative verb(s) in numeric output"
            )

    # Structured and list-structured: flag prose density above threshold.
    else:
        # Two or more prose sentences WITHOUT key:value markers is anomalous.
        # Outputs with key:value structure are data, not injection prose.
        if metrics.sentence_count >= 2 and not has_kv_structure:
            score += 0.4
            reasons.append(
                f"{metrics.sentence_count} prose sentences in structured output "
                f"(avg {metrics.avg_sentence_length:.1f} words/sentence)"
            )
        elif (metrics.sentence_count == 1
              and metrics.avg_sentence_length >= 15
              and not has_kv_structure):
            score += 0.3
            reasons.append(
                f"long prose sentence ({metrics.avg_sentence_length:.1f} words) "
                f"in structured output"
            )

        # Any imperative in a structured output is suspicious.
        if metrics.imperative_count > 0:
            score += 0.4
            reasons.append(
                f"{metrics.imperative_count} imperative verb(s) in structured output"
            )

        # Heavy prose relative to structured markers: if there are many prose
        # sentences but few key:value markers, the output looks like an essay.
        if (metrics.sentence_count >= 2 and metrics.kv_marker_count == 0
                and metrics.word_count > 30):
            score += 0.2
            reasons.append("no key:value markers in multi-sentence structured output")

    score = min(score, 1.0)
    violation = score >= 0.5

    return SchemaViolationResult(
        tool_name=tool_name,
        expected_kind=kind,
        violation=violation,
        score=score,
        reason="; ".join(reasons) if reasons else "output conforms to expected schema",
        metrics=metrics,
    )
