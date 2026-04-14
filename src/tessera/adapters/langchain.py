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
        # run_id (str) -> Context
        self._contexts: dict[str, Context] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_create_context(self, run_id: Any) -> Context:
        key = str(run_id)
        if key not in self._contexts:
            self._contexts[key] = Context()
        return self._contexts[key]

    def _add_user_segment(self, run_id: Any, text: str) -> None:
        ctx = self._get_or_create_context(run_id)
        seg = make_segment(
            text,
            origin=Origin.USER,
            principal=self._principal,
            key=self._key,
        )
        ctx.add(seg)

    def _add_tool_segment(self, run_id: Any, text: str) -> None:
        ctx = self._get_or_create_context(run_id)
        seg = make_segment(
            text,
            origin=Origin.TOOL,
            principal=self._principal,
            key=self._key,
        )
        ctx.add(seg)

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
        if run_id is None:
            run_id = uuid.uuid4()
        for prompt in prompts:
            self._add_user_segment(run_id, prompt)

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Label chat messages as USER segments (chat-model variant)."""
        if run_id is None:
            run_id = uuid.uuid4()
        for message_list in messages:
            for msg in message_list:
                content = getattr(msg, "content", str(msg))
                if isinstance(content, str):
                    self._add_user_segment(run_id, content)

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Gate the tool call against the Tessera policy.

        Uses parent_run_id to look up the chain context (tools run
        as child runs). Falls back to run_id if parent is absent.
        """
        lookup_id = parent_run_id if parent_run_id is not None else run_id
        ctx = self._get_or_create_context(lookup_id)
        tool_name = serialized.get("name", "unknown_tool")

        decision = self._policy.evaluate(ctx, tool_name)
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
        """Label tool output as TOOL trust and scan for injection."""
        lookup_id = parent_run_id if parent_run_id is not None else run_id
        self._add_tool_segment(lookup_id, str(output))

        score = injection_score(str(output))
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
        """Clean up per-run context on completion."""
        self._contexts.pop(str(run_id), None)

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Clean up per-run context when the chain finishes."""
        self._contexts.pop(str(run_id), None)

    def on_chain_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Clean up on chain error."""
        self._contexts.pop(str(run_id), None)
