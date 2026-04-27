"""Native AlignmentCheck-style intent-drift scanner.

Compares the user's *declared* intent (a natural-language goal
captured at session start) to the agent's *actual* trajectory
(the sequence of tool calls the planner has issued). Flags
goal-hijack attacks where the agent is steered, by an injected
prompt or a poisoned context segment, into a tool call the user
did not authorise.

Mesh-review priority 1 (``docs/strategy/2026-04-mesh-review.md``).
Engineering brief Section 2 names this as the AlignmentCheck
gap; today only ``tessera.adapters.llamafirewall`` exists, and
that module is a wrapper around Meta's external SDK, not a
Tessera-native implementation.

Design properties:

- **Raw bytes never leave the call site.** The scanner builds a
  metadata-only ``ActionReview`` from the proposed tool call and
  passes ONLY argument shapes (type, length, char-class
  footprint) to the LLM judge. The user-intent text and tool
  description ARE included in the prompt because they originate
  from trusted segments (USER trust label and signed MCP
  manifest respectively); the untrusted argument values are
  not.
- **Fast pre-filter.** When ``user_intent`` itself looks benign
  (heuristic injection_score below ``injection_threshold``) and
  no tool history has been recorded, the scanner short-circuits
  to ALLOW without an LLM call. This keeps the latency budget
  small on the median benign request.
- **Fail-open by default.** Backend timeouts, network errors,
  unparseable LLM responses: every failure path returns
  ``allowed=True`` with an ``INTENT_DRIFT_BACKEND_FAILURE``
  event so the deterministic policy stays the source of truth
  and an LLM outage cannot lock the system out.
- **Backend swap.** The scanner uses its own
  :class:`IntentDriftBackend` protocol so the prompt template
  stays specialised for intent-drift audit; it does not inherit
  the action-critic system prompt. The bundled
  :class:`LocalSmallBackend` and :class:`ProviderAgnosticBackend`
  read the same env vars as the action_critic backends to
  simplify deployment (``TOGETHER_API_KEY`` /
  ``GROQ_API_KEY`` for local-small;
  ``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY`` for provider-agnostic).

Integration seam: ``tessera.plan_verifier.verify_sequence`` gains
an optional ``scanner`` parameter that callers can pass to layer
this scanner on top of the existing fnmatch-based heuristic. See
the ``examples/intent_drift_demo.py`` runbook (when added).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from tessera.action_critic import (
    ActionImpact,
    ActionReview,
    ArgShape,
    LabelSummary,
    RiskSignals,
)
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.scanners import ScanFinding, ScanResult, Severity
from tessera.scanners.heuristic import injection_score
from tessera.taint.label import (
    InformationCapacity,
    IntegrityLevel,
    SecrecyLevel,
)


# ---------------------------------------------------------------------------
# Public scanner identity
# ---------------------------------------------------------------------------

SCANNER_NAME = "tessera.scanners.intent_drift"

# Default fast-path thresholds.
_DEFAULT_INJECTION_THRESHOLD = 0.3
_DEFAULT_BACKEND_TIMEOUT = 5.0
_DEFAULT_MAX_HISTORY = 16

_PROMPT_PATH = Path(__file__).parent / "intent_drift_prompts" / "v1.txt"


def _load_system_prompt() -> str:
    """Read the v1 system prompt template, cached on first read."""
    try:
        return _PROMPT_PATH.read_text(encoding="utf-8").strip()
    except FileNotFoundError:  # pragma: no cover - shipped with package
        return (
            "You are an Intent-Drift Auditor. Decide allow|deny|require_approval "
            "for the following tool call relative to the declared intent."
        )


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class IntentDriftBackend(Protocol):
    """Backend that issues one LLM-judge call per scan invocation.

    The backend receives the FULL prompt the scanner has already
    assembled; it must NOT splice extra material into the prompt.
    """

    name: str

    def review(self, *, system_prompt: str, user_prompt: str) -> str:
        """Return the LLM's raw text response."""
        ...


@dataclass
class StubBackend:
    """Test-only backend. Returns a canned response.

    Used by tests and by the ``off`` operating mode (matches the
    ``TESSERA_INTENT_DRIFT_BACKEND=off`` env var) so callers always
    get a deterministic non-LLM result without a network round-trip.
    """

    name: str = "stub"
    canned_decision: str = "allow"
    canned_reason: str = "stub backend"

    def review(self, *, system_prompt: str, user_prompt: str) -> str:
        return json.dumps(
            {
                "decision": self.canned_decision,
                "reason": self.canned_reason,
                "triggered_principles": [],
            }
        )


@dataclass
class LocalSmallBackend:
    """Together / Groq HTTP-API backend mirroring action_critic.LocalSmallCritic.

    Reads ``TESSERA_INTENT_DRIFT_LOCAL_MODEL`` (overrides the default
    ``meta-llama/Llama-4-Scout-17B-16E-Instruct``) and either
    ``TOGETHER_API_KEY`` or ``GROQ_API_KEY``. When neither is set the
    backend raises ``BackendUnconfigured`` so the scanner falls
    through to ALLOW with an INTENT_DRIFT_BACKEND_FAILURE event.
    """

    name: str = "local_small"
    timeout: float = _DEFAULT_BACKEND_TIMEOUT
    http_client: Any = None
    model_override: str | None = None

    def _resolve_provider(self) -> tuple[str, str, str] | None:
        model = (
            self.model_override
            or os.environ.get("TESSERA_INTENT_DRIFT_LOCAL_MODEL", "").strip()
            or "meta-llama/Llama-4-Scout-17B-16E-Instruct"
        )
        if os.environ.get("TOGETHER_API_KEY", "").strip():
            return (
                "https://api.together.xyz/v1/chat/completions",
                os.environ["TOGETHER_API_KEY"].strip(),
                model,
            )
        if os.environ.get("GROQ_API_KEY", "").strip():
            return (
                "https://api.groq.com/openai/v1/chat/completions",
                os.environ["GROQ_API_KEY"].strip(),
                model,
            )
        return None

    def review(self, *, system_prompt: str, user_prompt: str) -> str:
        provider = self._resolve_provider()
        if provider is None:
            raise BackendUnconfigured(
                "no provider key (TOGETHER_API_KEY or GROQ_API_KEY)"
            )
        url, api_key, model = provider
        client = self.http_client
        if client is None:
            try:
                import httpx  # type: ignore[import-untyped]
            except ImportError as exc:  # pragma: no cover
                raise BackendUnconfigured("httpx not installed") from exc
            client = httpx.Client(timeout=self.timeout)
        resp = client.post(
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": model,
                "temperature": 0.0,
                "max_tokens": 256,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


@dataclass
class ProviderAgnosticBackend:
    """Anthropic / OpenAI client passthrough.

    Pass either an Anthropic ``Anthropic`` client (we call
    ``messages.create``) or an OpenAI ``OpenAI`` client (we call
    ``chat.completions.create``). The backend duck-types on the
    presence of those attributes so we don't import either SDK at
    module load time.
    """

    name: str = "provider_agnostic"
    client: Any = None
    model: str = "claude-3-5-sonnet-20241022"

    def review(self, *, system_prompt: str, user_prompt: str) -> str:
        if self.client is None:
            raise BackendUnconfigured("no client passed to ProviderAgnosticBackend")

        if hasattr(self.client, "messages") and hasattr(self.client.messages, "create"):
            # Anthropic shape.
            resp = self.client.messages.create(
                model=self.model,
                max_tokens=256,
                temperature=0.0,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            # Anthropic returns content as a list of blocks; first
            # text block is the JSON.
            blocks = getattr(resp, "content", []) or []
            for block in blocks:
                text = getattr(block, "text", None)
                if text:
                    return text
            return ""

        if hasattr(self.client, "chat") and hasattr(
            self.client.chat, "completions"
        ):
            resp = self.client.chat.completions.create(
                model=self.model,
                temperature=0.0,
                max_tokens=256,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return resp.choices[0].message.content or ""

        raise BackendUnconfigured(
            f"client {type(self.client).__name__} has neither .messages.create "
            f"nor .chat.completions.create"
        )


class BackendUnconfigured(RuntimeError):
    """Raised when a backend cannot dispatch (missing client, missing key)."""


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


@dataclass
class IntentDriftScanner:
    """Compare declared user intent to a proposed tool call.

    Args:
        backend: An :class:`IntentDriftBackend` instance. When None,
            the scanner reads ``TESSERA_INTENT_DRIFT_BACKEND`` to
            select a default (``off`` -> StubBackend allow,
            ``stub`` -> StubBackend require_approval, ``local-small``
            -> LocalSmallBackend, ``provider-agnostic`` ->
            ProviderAgnosticBackend with no client which fails open).
        injection_threshold: heuristic.injection_score below this
            value short-circuits to allow when there's no history.
            Default 0.3.
        max_history: Truncate ``tool_call_history`` to the last N
            entries before sending to the LLM. Default 16.
        timeout: Per-call timeout passed to backends that respect it.
        system_prompt_override: Replace the bundled v1 system prompt
            (test escape hatch).
    """

    backend: IntentDriftBackend | None = None
    injection_threshold: float = _DEFAULT_INJECTION_THRESHOLD
    max_history: int = _DEFAULT_MAX_HISTORY
    timeout: float = _DEFAULT_BACKEND_TIMEOUT
    system_prompt_override: str | None = None

    name: str = field(default=SCANNER_NAME, init=False)

    def __post_init__(self) -> None:
        if self.backend is None:
            self.backend = self._default_backend()

    # ------------------------------------------------------------------
    # Default-backend selection
    # ------------------------------------------------------------------

    @staticmethod
    def _default_backend() -> IntentDriftBackend:
        mode = os.environ.get("TESSERA_INTENT_DRIFT_BACKEND", "off").strip().lower()
        if mode == "stub":
            return StubBackend(
                canned_decision="require_approval",
                canned_reason="stub backend; intent-drift configured but no LLM",
            )
        if mode == "local-small":
            return LocalSmallBackend()
        if mode == "provider-agnostic":
            return ProviderAgnosticBackend()
        # Default and "off": pure-allow stub.
        return StubBackend(canned_decision="allow", canned_reason="off")

    # ------------------------------------------------------------------
    # Scanner protocol
    # ------------------------------------------------------------------

    def scan(
        self,
        *,
        tool_name: str,
        args: Any,
        trajectory_id: str = "",
        user_intent: str | None = None,
        tool_call_history: tuple[str, ...] = (),
        tool_description: str | None = None,
        principal: str = "intent-drift-scanner",
    ) -> ScanResult:
        # Without a declared intent we have nothing to compare against.
        if not user_intent or not user_intent.strip():
            return ScanResult(scanner=self.name, allowed=True)

        # Fast-path: low injection score and short history -> allow
        # without an LLM call.
        score = injection_score(user_intent)
        if (
            score < self.injection_threshold
            and not tool_call_history
            and self._call_looks_benign(tool_name, args)
        ):
            return ScanResult(scanner=self.name, allowed=True)

        # Build a metadata-only ActionReview. The shapes derive from
        # `args` but never carry the raw values; the user_intent and
        # tool_description ARE included verbatim in the prompt
        # because they originate from trusted segments (USER trust
        # label and signed MCP manifest respectively).
        try:
            arg_shapes = self._args_to_shapes(args)
        except Exception:  # noqa: BLE001 - defensive
            return ScanResult(scanner=self.name, allowed=True)

        action = ActionReview(
            tool=tool_name,
            principal=principal,
            args=arg_shapes,
            risk=RiskSignals(action_impact=self._guess_impact(tool_name)),
            correlation_id=trajectory_id or None,
        )

        history = tuple(tool_call_history)[-self.max_history :]
        system_prompt = self.system_prompt_override or _load_system_prompt()
        user_prompt = self._build_user_prompt(
            user_intent=user_intent.strip(),
            action=action,
            tool_description=(tool_description or "").strip()[:600],
            history=history,
        )

        # Dispatch.
        try:
            assert self.backend is not None  # post_init guaranteed
            raw = self.backend.review(
                system_prompt=system_prompt, user_prompt=user_prompt
            )
        except BackendUnconfigured as exc:
            self._emit_failure(trajectory_id, tool_name, str(exc))
            return ScanResult(scanner=self.name, allowed=True)
        except Exception as exc:  # noqa: BLE001 - swallow per fail-open
            self._emit_failure(
                trajectory_id, tool_name, f"{type(exc).__name__}: {exc}"
            )
            return ScanResult(scanner=self.name, allowed=True)

        # Parse + map.
        decision, reason, triggered = self._parse_response(raw)
        if decision == "allow":
            return ScanResult(scanner=self.name, allowed=True)

        severity: Severity = "high" if decision == "deny" else "medium"
        finding = ScanFinding(
            rule_id=f"intent_drift.{decision}",
            severity=severity,
            message=reason or "intent drift detected",
            arg_path=tool_name,
            evidence="",
            metadata={
                "triggered_principles": list(triggered),
                "decision": decision,
                "trajectory_id": trajectory_id,
                "history_length": len(history),
            },
        )
        self._emit_decision(decision, trajectory_id, tool_name, reason, triggered)
        return ScanResult(
            scanner=self.name, allowed=False, findings=(finding,)
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _call_looks_benign(self, tool_name: str, args: Any) -> bool:
        """Return True when no destination-shaped argument is present.

        Skipping the LLM for low-injection-score + benign-tool calls
        is safe because the intent is unlikely to have been hijacked
        AND the call has no exfil channel.
        """
        if any(prefix in tool_name for prefix in ("send_", "transfer_", "delete_", "exfil_")):
            return False
        if isinstance(args, dict):
            for key in args:
                if any(needle in key.lower() for needle in ("recipient", "url", "to", "address", "destination")):
                    return False
        return True

    def _guess_impact(self, tool_name: str) -> ActionImpact:
        if any(p in tool_name for p in ("delete_", "transfer_", "send_money")):
            return ActionImpact.DESTRUCTIVE
        if any(p in tool_name for p in ("send_", "create_", "update_", "post_")):
            return ActionImpact.SIDE_EFFECT
        return ActionImpact.BENIGN

    def _args_to_shapes(self, args: Any) -> tuple[ArgShape, ...]:
        """Flatten a dict of arg_name -> value into ArgShape entries.

        Non-dict ``args`` (positional list, raw string, None) is
        normalised to a single anonymous ``arg0`` shape so the
        scanner stays usable without forcing every adapter to use
        the dict convention.
        """
        if args is None:
            return ()

        items: list[tuple[str, Any]]
        if isinstance(args, dict):
            items = [(str(k), v) for k, v in args.items()]
        elif isinstance(args, (list, tuple)):
            items = [(f"arg{i}", v) for i, v in enumerate(args)]
        else:
            items = [("arg0", args)]

        shapes: list[ArgShape] = []
        for name, value in items:
            shapes.append(
                ArgShape(
                    name=name,
                    type_hint=type(value).__name__,
                    length=len(value) if hasattr(value, "__len__") else 0,
                    char_classes=self._char_classes(value),
                    label=_PUBLIC_LABEL_SUMMARY,
                )
            )
        return tuple(shapes)

    @staticmethod
    def _char_classes(value: Any) -> tuple[str, ...]:
        if not isinstance(value, str):
            return ()
        classes: list[str] = []
        if any(c.isdigit() for c in value):
            classes.append("digit")
        if any(c.isalpha() for c in value):
            classes.append("alpha")
        if any(c in "@" for c in value):
            classes.append("at")
        if any(c in ":/" for c in value):
            classes.append("url-ish")
        if any(c in '"\'`' for c in value):
            classes.append("quote")
        if any(c == "<" or c == ">" for c in value):
            classes.append("angle")
        return tuple(classes)

    def _build_user_prompt(
        self,
        *,
        user_intent: str,
        action: ActionReview,
        tool_description: str,
        history: tuple[str, ...],
    ) -> str:
        # Truncate user-intent at a reasonable bound so a malicious
        # USER segment can't blow the prompt context.
        intent_clipped = user_intent[:600]
        return (
            "Declared user intent (verbatim, trusted USER segment):\n"
            f"  {intent_clipped}\n\n"
            "Tool call metadata to audit (no raw argument values):\n"
            + json.dumps(action.model_dump(mode="json"), indent=2, sort_keys=True)
            + "\n\nProposed tool description (from signed MCP manifest):\n"
            f"  {tool_description or '(none)'}\n\n"
            "Tool calls already made this session (most recent last):\n"
            + (
                "\n".join(f"  {i + 1}. {tool}" for i, tool in enumerate(history))
                if history
                else "  (none)"
            )
            + "\n\nRespond with the single-line JSON object specified above."
        )

    @staticmethod
    def _parse_response(raw: str) -> tuple[str, str, tuple[str, ...]]:
        """Extract decision / reason / triggered_principles from the LLM
        response. Tolerant of code fences and leading prose."""
        text = raw.strip()
        if text.startswith("```"):
            try:
                text = text.split("```", 2)[1]
                if text.lower().startswith("json"):
                    text = text[4:]
            except IndexError:
                pass
        text = text.strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Fall back to require_approval rather than allow on
            # parse failure: a malformed LLM response is suspicious
            # behaviour, not benign noise.
            return ("require_approval", "backend response unparseable", ())
        decision = str(data.get("decision", "require_approval")).lower()
        if decision not in ("allow", "deny", "require_approval"):
            decision = "require_approval"
        reason = str(data.get("reason", "no reason provided"))[:240]
        principles_raw = data.get("triggered_principles") or []
        if not isinstance(principles_raw, list):
            principles_raw = []
        triggered = tuple(str(p) for p in principles_raw)
        return decision, reason, triggered

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    def _emit_failure(self, trajectory_id: str, tool_name: str, reason: str) -> None:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.GUARDRAIL_DECISION,
                principal="intent-drift-scanner",
                detail={
                    "scanner": SCANNER_NAME,
                    "outcome": "backend_failure",
                    "tool": tool_name,
                    "trajectory_id": trajectory_id,
                    "reason": reason,
                },
            )
        )

    def _emit_decision(
        self,
        decision: str,
        trajectory_id: str,
        tool_name: str,
        reason: str,
        triggered: tuple[str, ...],
    ) -> None:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.GUARDRAIL_DECISION,
                principal="intent-drift-scanner",
                detail={
                    "scanner": SCANNER_NAME,
                    "outcome": decision,
                    "tool": tool_name,
                    "trajectory_id": trajectory_id,
                    "reason": reason,
                    "triggered_principles": list(triggered),
                },
            )
        )


# ---------------------------------------------------------------------------
# Module-level constants used by ArgShape construction
# ---------------------------------------------------------------------------

# Conservative label summary applied to every ArgShape the scanner
# constructs. Real provenance labels (when callers wire them) should
# be passed via a richer adapter; for now we err on the side of
# treating arguments as untrusted (highest integrity number; the
# join is max so this is the safe floor) and not narrowing reader
# principals.
_PUBLIC_LABEL_SUMMARY = LabelSummary(
    integrity=IntegrityLevel.UNTRUSTED,
    secrecy=SecrecyLevel.PUBLIC,
    capacity=InformationCapacity.STRING,
    source_count=0,
    reader_principals=None,
)


__all__ = [
    "BackendUnconfigured",
    "IntentDriftBackend",
    "IntentDriftScanner",
    "LocalSmallBackend",
    "ProviderAgnosticBackend",
    "SCANNER_NAME",
    "StubBackend",
]
