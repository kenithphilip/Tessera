"""Security-aware error redaction for untrusted-origin errors.

When an error or SecurityEvent originates from processing untrusted data,
the error message may contain attacker-controlled content. Exposing that
content verbatim to the LLM or to detailed logs enables oracle attacks:
the attacker crafts inputs specifically to learn about the security policy
from the error messages.

This module provides redaction functions that strip attacker-controlled
content from error details before they reach the model or sinks.

Source attribution: CaMeL format_camel_exception with is_trusted() check.
"""

from __future__ import annotations

import re
from typing import Any

from tessera.context import Context
from tessera.events import SecurityEvent
from tessera.labels import TrustLevel

# Patterns that may leak security policy details.
_POLICY_DETAIL_PATTERNS = (
    re.compile(r"trust_level=\d+"),
    re.compile(r"required \d+ for tool"),
    re.compile(r"readers lattice"),
    re.compile(r"delegation constraint"),
    re.compile(r"min_trust\(\d+\)"),
)

_REDACTED = "[redacted: untrusted-origin error detail]"


def redact_event_detail(
    event: SecurityEvent,
    context: Context | None = None,
    threshold: TrustLevel = TrustLevel.TOOL,
) -> SecurityEvent:
    """Return a copy of the event with detail redacted if context is untrusted.

    If the context's min_trust is below the threshold, the event's detail
    dict is replaced with a sanitized version that contains only safe
    metadata (kind, principal, timestamp) and a generic message. The
    original detail is not preserved.

    If context is None or trusted, the event is returned unchanged.

    Args:
        event: The SecurityEvent to potentially redact.
        context: The context that triggered the event. If None, no
            redaction is applied.
        threshold: Trust level below which redaction kicks in.

    Returns:
        SecurityEvent (possibly with redacted detail).
    """
    if context is None:
        return event
    if context.min_trust >= threshold:
        return event

    safe_detail: dict[str, Any] = {
        "redacted": True,
        "reason": "event originated from untrusted context",
    }
    # Preserve non-sensitive metadata keys.
    for key in ("tool", "scanner", "owasp", "rule", "rules"):
        if key in event.detail:
            safe_detail[key] = event.detail[key]

    return SecurityEvent(
        kind=event.kind,
        principal=event.principal,
        detail=safe_detail,
        timestamp=event.timestamp,
        correlation_id=event.correlation_id,
        trace_id=event.trace_id,
    )


def redact_error_message(
    message: str,
    context: Context | None = None,
    threshold: TrustLevel = TrustLevel.TOOL,
) -> str:
    """Redact policy-revealing details from an error message.

    When the context is untrusted, strips patterns that reveal trust
    levels, required thresholds, and policy rule names. This prevents
    an attacker from probing the policy by observing error messages.

    If context is None or trusted, the message is returned unchanged.
    """
    if context is None:
        return message
    if context.min_trust >= threshold:
        return message

    result = message
    for pattern in _POLICY_DETAIL_PATTERNS:
        result = pattern.sub(_REDACTED, result)
    return result


def safe_error_for_model(
    error: Exception,
    context: Context | None = None,
    threshold: TrustLevel = TrustLevel.TOOL,
) -> str:
    """Produce a model-safe error string.

    When context is untrusted, returns a generic message. When trusted,
    returns the full error string. This is the function to use when
    constructing error messages that will be injected back into the
    LLM's context window.
    """
    if context is not None and context.min_trust < threshold:
        return "Action was denied by security policy."
    return str(error)
