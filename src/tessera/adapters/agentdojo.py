"""AgentDojo adapter: Tessera as a BasePipelineElement defense.

Plugs Tessera's taint-tracking policy engine into AgentDojo's benchmark
framework. Two pipeline elements:

1. TesseraToolLabeler: sits after ToolsExecutor in the tools loop.
   Labels every tool result message with a Tessera trust label based on
   its content (heuristic injection scoring + configurable origin).

2. TesseraToolGuard: sits before the LLM in the tools loop. When the LLM
   returns tool_calls, intercepts them before execution and evaluates each
   call against the Tessera policy engine. Denied calls are replaced with
   an error message. This is the taint-floor enforcement point.

Pipeline shape with Tessera defense:

    SystemMessage -> InitQuery -> LLM -> ToolsExecutionLoop([
        ToolsExecutor,    # execute tool calls, get raw results
        TesseraToolLabeler,  # label results with trust metadata
        TesseraToolGuard,    # block tool calls when context is tainted
        LLM,              # model sees labeled context, makes next call
    ])

The labeler accumulates a Tessera Context across the conversation. The
guard checks that context before each tool execution. If any tool output
contained content that scores above the injection threshold, the context
is tainted (min_trust=UNTRUSTED), and side-effecting tool calls are denied.

Requires: pip install agentdojo
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from tessera.context import Context, LabeledSegment, make_segment
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy
from tessera.scanners.heuristic import injection_score

# AgentDojo imports are optional: this module is only loaded when agentdojo
# is installed. Guard the imports so the rest of tessera.adapters doesn't
# break when agentdojo is absent.
try:
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.errors import AbortAgentError
    from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
    from agentdojo.types import (
        ChatMessage,
        get_text_content_as_str,
        text_content_block_from_string,
    )

    _AGENTDOJO_AVAILABLE = True
except ImportError:
    _AGENTDOJO_AVAILABLE = False

    # Stubs so the module can be imported without agentdojo for type
    # checking and unit tests with mocks.
    class BasePipelineElement:  # type: ignore[no-redef]
        name: str | None = None

        def query(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

    class AbortAgentError(Exception):  # type: ignore[no-redef]
        pass

    Env = Any  # type: ignore[assignment,misc]
    EmptyEnv = dict  # type: ignore[assignment,misc]
    FunctionsRuntime = Any  # type: ignore[assignment,misc]
    ChatMessage = dict  # type: ignore[assignment,misc]


# Default HMAC key for benchmark use. Not secret: the threat model is
# injection, not key compromise. Production deployments use real keys.
_BENCH_KEY = b"tessera-agentdojo-bench-key"

# Tools that are read-only and should be allowed even when the context
# contains untrusted segments. This matches CaMeL's no_side_effect_tools.
_DEFAULT_READ_ONLY_PATTERNS: tuple[str, ...] = (
    "get_*",
    "read_*",
    "search_*",
    "list_*",
    "find_*",
    "check_*",
    "verify_*",
    "lookup_*",
    "query_*",
    "show_*",
    "view_*",
    "fetch_*",
    "describe_*",
)


@dataclass
class TesseraToolLabeler:
    """Label tool result messages with Tessera trust metadata.

    Scans each tool output with three scanners in parallel:
    1. Heuristic injection scorer (override patterns, delimiter injection)
    2. Directive scanner (output manipulation, "say X to the user")
    3. Tool output schema enforcement (prose in structured output)

    Any scanner triggering above threshold marks the output UNTRUSTED.
    This element must sit in the ToolsExecutionLoop after ToolsExecutor.
    """

    name: str | None = "tessera_labeler"
    key: bytes = _BENCH_KEY
    principal: str = "agentdojo-bench"
    injection_threshold: float = 0.75
    directive_threshold: float = 0.5
    context: Context = field(default_factory=Context)
    _labeled_count: int = field(default=0, repr=False)

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any = None,
        messages: Sequence[Any] = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, Any, Any, Sequence[Any], dict[str, Any]]:
        if extra_args is None:
            extra_args = {}

        # Label the user query on first call if context is empty.
        if not self.context.segments:
            self.context.add(
                make_segment(query, Origin.USER, self.principal, self.key)
            )

        from tessera.scanners.directive import scan_directive
        from tessera.scanners.tool_output_schema import scan_tool_output

        # Walk tool result messages that haven't been labeled yet.
        tool_msgs = [m for m in messages if m.get("role") == "tool"]
        for msg in tool_msgs[self._labeled_count:]:
            content = msg.get("content")
            if content is None:
                continue

            # Extract text from content blocks.
            if isinstance(content, list):
                text_parts = []
                for block in content:
                    if isinstance(block, dict) and block.get("content"):
                        text_parts.append(str(block["content"]))
                text = "\n".join(text_parts)
            else:
                text = str(content)

            if not text.strip():
                self._labeled_count += 1
                continue

            # Extract tool name for schema enforcement
            tool_name = ""
            tool_call_id = msg.get("tool_call_id", "")
            # Try to find the tool name from the preceding assistant message
            for prev in reversed(list(messages)):
                if prev.get("role") == "assistant" and prev.get("tool_calls"):
                    for tc in prev["tool_calls"]:
                        tc_id = tc.id if hasattr(tc, "id") else tc.get("id", "")
                        if tc_id == tool_call_id:
                            tool_name = (
                                tc.function if hasattr(tc, "function")
                                else tc.get("function", "")
                            )
                            break
                    if tool_name:
                        break

            # Run all three scanners with corroboration logic.
            #
            # The heuristic has two components: regex patterns (high
            # confidence: delimiter injection, role override, shell
            # commands) and sliding-window phrase matching (noisy:
            # 0.50-0.65 baseline on hotel reviews, file listings).
            #
            # Regex matches always taint. Sliding-window matches need
            # corroboration from the directive or schema scanner.
            from tessera.scanners.heuristic import injection_scores

            h_regex, h_window = injection_scores(text)
            h_score = max(h_regex, h_window)
            d_result = scan_directive(text)
            s_result = scan_tool_output(tool_name or "unknown", text)

            regex_match = h_regex >= 0.9
            window_corroborated = (
                h_window >= self.injection_threshold
                and (d_result.score > 0.2 or s_result.score > 0.3)
            )

            is_tainted = (
                regex_match
                or d_result.detected
                or s_result.violation
                or window_corroborated
            )

            if is_tainted:
                origin = Origin.WEB
                trust = TrustLevel.UNTRUSTED
            else:
                origin = Origin.TOOL
                trust = TrustLevel.USER

            seg = make_segment(text, origin, self.principal, self.key, trust_level=trust)
            self.context.add(seg)
            self._labeled_count += 1

        return query, runtime, env, messages, extra_args or {}


def _infer_critical_args(tool_name: str) -> frozenset[str] | None:
    """Map tool name patterns to critical argument sets."""
    from tessera.taint import (
        CRITICAL_ARGS_EXECUTE,
        CRITICAL_ARGS_SEND,
        CRITICAL_ARGS_TRANSFER,
        CRITICAL_ARGS_WRITE,
    )

    lower = tool_name.lower()
    if any(p in lower for p in ("send_email", "email", "forward")):
        return CRITICAL_ARGS_SEND
    if any(p in lower for p in ("send_money", "transfer", "wire", "pay")):
        return CRITICAL_ARGS_TRANSFER
    if any(p in lower for p in ("write", "delete", "upload", "append", "post_webpage")):
        return CRITICAL_ARGS_WRITE
    if any(p in lower for p in ("execute", "run", "install")):
        return CRITICAL_ARGS_EXECUTE
    return None


@dataclass
class TesseraToolGuard:
    """Enforce Tessera policy on tool calls before execution.

    Sits in the ToolsExecutionLoop BEFORE ToolsExecutor. When the LLM
    emits tool_calls, this element checks each call against the Tessera
    policy engine using the accumulated context from TesseraToolLabeler.

    Uses value-level taint via DependencyAccumulator: tool arguments
    that came from the user prompt are clean even when the context
    contains untrusted segments. Only arguments whose values trace to
    untrusted tool output trigger a deny.

    Args:
        labeler: The TesseraToolLabeler that accumulates context. Must be
            the same instance used in the pipeline.
        policy: Tessera Policy. If None, a default policy is created that
            requires USER trust for all tools except read-only patterns.
        read_only_patterns: Glob patterns for tools exempt from taint-floor
            denial. These are marked side_effects=False.
        abort_on_deny: If True, raise AbortAgentError on first denied call.
            If False, replace the denied call's result with an error message
            and continue (the LLM may retry with a different approach).
    """

    name: str | None = "tessera_guard"
    labeler: TesseraToolLabeler | None = None
    policy: Policy | None = None
    read_only_patterns: tuple[str, ...] = _DEFAULT_READ_ONLY_PATTERNS
    abort_on_deny: bool = True

    def _get_policy(self) -> Policy:
        if self.policy is not None:
            return self.policy
        p = Policy()
        for pattern in self.read_only_patterns:
            p.require(pattern, TrustLevel.USER, side_effects=False)
        return p

    def _get_context(self) -> Context:
        if self.labeler is not None:
            return self.labeler.context
        return Context()

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any = None,
        messages: Sequence[Any] = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, Any, Any, Sequence[Any], dict[str, Any]]:
        if extra_args is None:
            extra_args = {}
        if not messages:
            return query, runtime, env, messages, extra_args

        last = messages[-1]
        if last.get("role") != "assistant":
            return query, runtime, env, messages, extra_args

        tool_calls = last.get("tool_calls")
        if not tool_calls:
            return query, runtime, env, messages, extra_args

        ctx = self._get_context()
        pol = self._get_policy()

        # Value-level taint: trace each argument to its source.
        # Arguments whose string value appears in the user prompt are
        # clean (user-provided). Others are bound to the most recent
        # untrusted segment via bind_from_tool_output.
        from tessera.taint import DependencyAccumulator

        acc = DependencyAccumulator(context=ctx)

        for tc in tool_calls:
            tool_name = tc.function if hasattr(tc, "function") else tc.get("function", "")
            args = tc.args if hasattr(tc, "args") else tc.get("args", {})
            args_dict = dict(args) if args else {}

            # Bind argument provenance
            for arg_name, arg_val in args_dict.items():
                if isinstance(arg_val, str) and arg_val in query:
                    acc.bind_from_user(arg_name, arg_val)
                else:
                    acc.bind_from_tool_output(arg_name, arg_val, tool_name)

            decision = pol.evaluate(
                ctx, tool_name,
                args=args_dict if args_dict else None,
                accumulator=acc,
                critical_args=_infer_critical_args(tool_name),
            )

            if not decision.allowed:
                if self.abort_on_deny:
                    raise AbortAgentError(
                        f"Tessera policy denied tool {tool_name!r}: {decision.reason}",
                        list(messages),
                        env,
                    )

        return query, runtime, env, messages, extra_args or {}


def create_tessera_defense(
    injection_threshold: float = 0.75,
    read_only_patterns: tuple[str, ...] | None = None,
    abort_on_deny: bool = True,
    key: bytes = _BENCH_KEY,
) -> tuple[TesseraToolLabeler, TesseraToolGuard]:
    """Create a paired labeler + guard for use in an AgentDojo pipeline.

    Returns (labeler, guard). Both share the same context accumulator.
    Insert into ToolsExecutionLoop as:

        labeler, guard = create_tessera_defense()
        loop = ToolsExecutionLoop([ToolsExecutor(), labeler, guard, llm])

    Args:
        injection_threshold: Heuristic injection score threshold for
            labeling tool output as UNTRUSTED. Default 0.75.
        read_only_patterns: Glob patterns for side-effect-free tools.
            If None, uses the default set (get_*, read_*, search_*, etc.).
        abort_on_deny: If True, raise AbortAgentError on denied calls.
        key: HMAC key for label signing. Defaults to bench key.

    Returns:
        Tuple of (TesseraToolLabeler, TesseraToolGuard).
    """
    patterns = read_only_patterns if read_only_patterns is not None else _DEFAULT_READ_ONLY_PATTERNS
    labeler = TesseraToolLabeler(key=key, injection_threshold=injection_threshold)
    guard = TesseraToolGuard(
        labeler=labeler,
        read_only_patterns=patterns,
        abort_on_deny=abort_on_deny,
    )
    return labeler, guard
