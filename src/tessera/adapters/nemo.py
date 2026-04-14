"""NeMo Guardrails adapter: expose Tessera policy as a NeMo @action.

NeMo Guardrails uses @action decorators to expose functions that
rails can call from Colang flows. This adapter exposes Tessera's
policy evaluation as a NeMo action and injects trust labels as
NeMo context variables.

Install requirements:
    pip install tessera[nemo]   # adds nemoguardrails

Source attribution: action interface from NeMo Guardrails (actions.py).
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from tessera.context import Context, make_segment
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy
from tessera.scanners.heuristic import injection_score

try:
    from nemoguardrails import LLMRails  # noqa: F401

    _NEMO_AVAILABLE = True
except ImportError:
    _NEMO_AVAILABLE = False

log = logging.getLogger(__name__)

_DEFAULT_READ_ONLY_PATTERNS: tuple[str, ...] = (
    "get_*",
    "read_*",
    "search_*",
    "list_*",
    "find_*",
)


class TesseraRailAction:
    """Exposes Tessera policy evaluation as a NeMo Guardrails @action.

    Usage in NeMo config::

        from tessera.adapters.nemo import TesseraRailAction
        action = TesseraRailAction(key=b"...", principal="agent")
        rails.register_action(action.check_tool_call, name="tessera_check")

    The action can be called from Colang flows::

        define flow check tool call
            $result = execute tessera_check(tool=$tool, args=$args, content=$content)
            if $result.blocked
                bot refuse to execute tool

    Args:
        key: HMAC key used to sign context segment labels.
        principal: Principal name for context segments.
        injection_threshold: Injection score above which content is
            labeled UNTRUSTED. Default 0.75.
        read_only_patterns: Glob patterns for tools exempt from
            taint-floor denial.
    """

    def __init__(
        self,
        key: bytes,
        principal: str = "nemo-agent",
        injection_threshold: float = 0.75,
        read_only_patterns: tuple[str, ...] = _DEFAULT_READ_ONLY_PATTERNS,
    ) -> None:
        self._key = key
        self._principal = principal
        self._injection_threshold = injection_threshold
        self._read_only_patterns = read_only_patterns
        self._context = Context()
        self._policy = Policy()
        for pattern in self._read_only_patterns:
            self._policy.require(pattern, TrustLevel.USER, side_effects=False)

    async def check_tool_call(
        self,
        tool: str,
        args: dict | None = None,
        content: str | None = None,
    ) -> dict:
        """NeMo action interface.

        Scores content for injection, adds it to the context, and
        evaluates the tool call against the Tessera policy.

        Args:
            tool: Name of the tool being called.
            args: Tool call arguments.
            content: Optional content to score and add to context.

        Returns:
            Dict with 'blocked', 'reason', 'trust_level', 'injection_score'.
        """
        score = 0.0
        if content:
            score = injection_score(content)
            if score >= self._injection_threshold:
                origin = Origin.WEB
                trust = TrustLevel.UNTRUSTED
            else:
                origin = Origin.TOOL
                trust = TrustLevel.USER

            seg = make_segment(
                content,
                origin=origin,
                principal=self._principal,
                key=self._key,
                trust_level=trust,
            )
            self._context.add(seg)

            if score >= self._injection_threshold:
                emit_event(
                    SecurityEvent.now(
                        kind=EventKind.CONTENT_INJECTION_DETECTED,
                        principal=self._principal,
                        detail={
                            "tool": tool,
                            "injection_score": round(score, 2),
                            "threshold": self._injection_threshold,
                        },
                    )
                )

        decision = self._policy.evaluate(
            self._context,
            tool,
            args=args,
        )

        return {
            "blocked": not decision.allowed,
            "reason": decision.reason,
            "trust_level": int(decision.observed_trust),
            "injection_score": round(score, 2),
        }

    def get_context_variables(self) -> dict:
        """Return current trust state as NeMo context variables.

        Returns:
            Dict with 'trust_level', 'segment_count', 'min_trust',
            'is_tainted'.
        """
        min_trust = self._context.min_trust
        return {
            "trust_level": int(min_trust),
            "segment_count": len(self._context.segments),
            "min_trust": int(min_trust),
            "is_tainted": min_trust <= TrustLevel.UNTRUSTED,
        }

    def as_event_sink(self) -> Callable:
        """Return a sink that forwards Tessera SecurityEvents to NeMo logging.

        Returns:
            Callable suitable for register_sink().
        """

        def sink(event: SecurityEvent) -> None:
            log.info(
                "tessera.security.%s principal=%s detail=%s",
                event.kind,
                event.principal,
                event.detail,
            )

        return sink


def register_with_rails(
    rails: Any,
    key: bytes,
    principal: str = "nemo-agent",
) -> TesseraRailAction:
    """Create a TesseraRailAction and register it with an LLMRails instance.

    Args:
        rails: NeMo LLMRails instance.
        key: HMAC key for label signing.
        principal: Principal name for context segments.

    Returns:
        The created TesseraRailAction.
    """
    action = TesseraRailAction(key=key, principal=principal)
    rails.register_action(action.check_tool_call, name="tessera_check")
    return action
