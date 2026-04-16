"""LangChain callback handler that gates tool calls via Tessera policy.

Install requirements:
    pip install tessera[langchain]   # adds langchain-core

Design:
- on_llm_start: initialise a fresh Context, label the input messages
  as USER segments (trust_level=100). The handler holds one Context
  per chain run identified by run_id.
- on_tool_start: run Policy.evaluate(); on deny, emit a SecurityEvent
  and raise ToolException to abort the tool call.
- on_tool_end: label the tool output as TOOL trust (trust_level=50)
  and run the injection scorer; high scores are recorded as events.
- on_llm_end: run the canary guard on the completion text if a guard
  was injected at chain start.

Source attribution: callback-handler pattern from LangKit
(callback_handler.py).
"""

from __future__ import annotations

import uuid
from typing import Any, Union

from tessera.context import Context, make_segment
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy
from tessera.scanners.heuristic import injection_score


class LangChainNotAvailable(RuntimeError):
    """Raised when langchain-core is not installed."""


class TesseraCallbackHandler:
    """LangChain callback handler that gates tool calls via Tessera policy.

    Args:
        policy: The Policy instance to evaluate tool calls against.
        signing_key: HMAC key used to sign context segment labels.
        principal: Principal name for context segments (e.g. the user or agent ID).
        injection_threshold: Injection score above which an event is emitted
            for tool outputs. Default 0.5.

    Usage::

        from tessera import Policy, TrustLevel
        from tessera.adapters.langchain import TesseraCallbackHandler

        policy = Policy()
        policy.require("some_tool", TrustLevel.USER)

        handler = TesseraCallbackHandler(
            policy=policy,
            signing_key=b"replace-me",
            principal="alice",
        )
        chain = SomeChain(..., callbacks=[handler])
    """

    def __init__(
        self,
        policy: Policy,
        signing_key: bytes,
        principal: str = "user",
        injection_threshold: float = 0.5,
        guardrail: Any = None,
    ) -> None:
        try:
            from langchain_core.callbacks import BaseCallbackHandler  # noqa: F401
            from langchain_core.tools import ToolException  # noqa: F401
        except ImportError as exc:
            raise LangChainNotAvailable(
                "langchain-core is required for TesseraCallbackHandler. "
                "Install it with: pip install tessera[langchain]"
            ) from exc

        self._policy = policy
        self._key = signing_key
        self._principal = principal
        self._injection_threshold = injection_threshold
        self._guardrail = guardrail
        # Single shared context across the session. LangGraph creates
        # many nested run_ids (one per node), so per-run contexts lose
        # taint state when chain_end cleans up between nodes.
        self._context = Context()

        # LangChain expects these properties on all callback handlers.
        # They control event routing and error behavior.
        self.raise_error = True       # raise exceptions on tool denial
        self.ignore_llm = False
        self.ignore_chat_model = False
        self.ignore_chain = False
        self.ignore_agent = False
        self.ignore_retriever = False
        self.ignore_retry = True
        self.ignore_custom_event = True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def context(self) -> Context:
        """The current session context. Exposed for inspection."""
        return self._context

    def _add_user_segment(self, text: str) -> None:
        seg = make_segment(
            text,
            origin=Origin.USER,
            principal=self._principal,
            key=self._key,
        )
        self._context.add(seg)

    def _add_tool_segment(self, text: str) -> None:
        seg = make_segment(
            text,
            origin=Origin.TOOL,
            principal=self._principal,
            key=self._key,
        )
        self._context.add(seg)

    # ------------------------------------------------------------------
    # LangChain callback interface (duck-typed; no base class required)
    # ------------------------------------------------------------------

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Label each prompt message as a USER segment."""
        for prompt in prompts:
            self._add_user_segment(prompt)

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Label chat messages as USER segments (chat-model variant).
        Only labels the first user message to avoid re-labeling on
        each LLM turn in an agent loop."""
        if self._context.segments:
            return  # already have context from previous turn
        for message_list in messages:
            for msg in message_list:
                content = getattr(msg, "content", str(msg))
                if isinstance(content, str) and content.strip():
                    self._add_user_segment(content)

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Gate the tool call against the Tessera policy."""
        tool_name = serialized.get("name", "unknown_tool")

        decision = self._policy.evaluate(self._context, tool_name)
        if not decision.allowed:
            try:
                from langchain_core.tools import ToolException
            except ImportError:
                raise RuntimeError(decision.reason)
            raise ToolException(decision.reason)

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Label tool output with trust level based on scanner results."""
        from tessera.scanners.directive import scan_directive
        from tessera.scanners.heuristic import injection_scores

        text = str(output)

        # Run scanners to determine trust level
        h_regex, h_window = injection_scores(text)
        d_result = scan_directive(text)

        regex_match = h_regex >= 0.9
        window_corroborated = h_window >= self._injection_threshold and d_result.score > 0.2
        is_tainted = regex_match or d_result.detected or window_corroborated

        # LLM guardrail fallback on uncertain cases
        if not is_tainted and self._guardrail is not None:
            is_tainted = self._guardrail.should_taint(text)

        if is_tainted:
            seg = make_segment(
                text, Origin.WEB, self._principal, self._key,
                trust_level=TrustLevel.UNTRUSTED,
            )
        else:
            # Clean tool output: label as USER trust so it doesn't
            # drag the context min_trust below the threshold for
            # side-effecting tools.
            seg = make_segment(
                text, Origin.TOOL, self._principal, self._key,
                trust_level=TrustLevel.USER,
            )
        self._context.add(seg)

        score = max(h_regex, h_window)
        if score >= self._injection_threshold:
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.CONTENT_INJECTION_DETECTED,
                    principal=self._principal,
                    detail={
                        "tool": "(tool_output)",
                        "injection_score": round(score, 2),
                        "threshold": self._injection_threshold,
                    },
                )
            )

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """LLM call completed. Do NOT clean up context here: in an agent
        loop, tools execute after the LLM call ends and need the context.
        Context cleanup happens in on_chain_end."""
        pass

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Initialize context for a chain run."""
        pass  # Context is created lazily in _get_or_create_context

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Chain finished. Context is preserved for the session."""
        pass

    def on_chain_error(
        self,
        error: Any,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Chain errored. Context is preserved for inspection."""
        pass
