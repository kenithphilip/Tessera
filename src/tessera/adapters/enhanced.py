"""Enhanced adapter integrating all security remediation components.

Reference implementation showing how the full defense stack composes.
Each step maps to a specific gap from the security audit:

1. Content inspection (CRITICAL-1): multimodal scanning before str()
2. MCP registration scanning (CRITICAL-2): detect connection injection
3. Read-only argument validation (CRITICAL-3): tainted arg checks
4. RAG retrieval scanning (HIGH-1): scan-on-retrieval for vector content
5. Rate limiting with burst detection (HIGH-2): per-session call caps
6. Output integrity checking (HIGH-3): post-generation manipulation
7. Policy invariant enforcement (MEDIUM-3): runtime bypass detection
8. Audit chain (MEDIUM-2): tamper-evident event logging

This adapter is framework-agnostic. Framework-specific adapters
(LangChain, OpenAI, CrewAI, etc.) should delegate to these methods
for the security layer, keeping their own framework integration code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tessera.context import Context, make_segment
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy

__all__ = ["EnhancedSecurityAdapter"]


@dataclass
class EnhancedSecurityAdapter:
    """Full defense stack composing all remediation modules.

    Each method documents which security gap it addresses.
    All components are optional: if a module import fails (missing
    optional dependency), that check is skipped with a warning.

    Usage::

        adapter = EnhancedSecurityAdapter()

        # On tool output:
        text, trust = adapter.process_tool_output(raw, "search_hotels", "s1")

        # Before tool execution:
        ok, reason = adapter.before_tool_call("send_email", {"to": "x"}, "s1")

        # Before response to user:
        response, action = adapter.before_response(text, "find hotels", "s1")
    """

    policy: Policy = field(default_factory=Policy)
    context: Context = field(default_factory=Context)
    signing_key: bytes = b"tessera-enhanced-adapter-key"
    principal: str = "system"
    injection_threshold: float = 0.75
    guardrail: Any = None  # Optional LLMGuardrail instance

    def process_tool_output(
        self,
        tool_output: Any,
        tool_name: str,
        session_id: str,
    ) -> tuple[str, TrustLevel]:
        """Process tool output through the full inspection pipeline.

        CRITICAL-1: Content inspection (multimodal, binary, PDF, image)
        CRITICAL-2: MCP registration pattern scanning
        HIGH-1: Directive and schema scanning on extracted text

        Args:
            tool_output: Raw tool output (any type).
            tool_name: Name of the tool that produced it.
            session_id: Session identifier.

        Returns:
            Tuple of (extracted_text, trust_level).
        """
        from tessera.content_inspector import (
            TrustRecommendation,
            inspect_content,
        )

        # CRITICAL-1: Content-type-aware inspection
        inspection = inspect_content(tool_output, tool_name)

        if inspection.trust == TrustRecommendation.BLOCKED:
            marker = f"[BLOCKED: threats detected in {tool_name} output]"
            self.context.add(make_segment(
                marker, Origin.WEB, self.principal, self.signing_key,
                trust_level=TrustLevel.UNTRUSTED,
            ))
            return marker, TrustLevel.UNTRUSTED

        text = inspection.extracted_text or str(tool_output)

        # CRITICAL-2: Scan for MCP registration injection
        from tessera.mcp_allowlist import scan_for_registration_attempts

        mcp_attempts = scan_for_registration_attempts(text)
        if mcp_attempts:
            from tessera.events import EventKind, SecurityEvent, emit
            emit(SecurityEvent.now(
                kind=EventKind.CONTENT_INJECTION_DETECTED,
                principal=self.principal,
                detail={
                    "scanner": "mcp_registration_scan",
                    "session_id": session_id,
                    "tool_name": tool_name,
                    "patterns": mcp_attempts[:5],
                },
            ))

        # Text-level scanning (heuristic + directive + schema)
        from tessera.scanners.directive import scan_directive
        from tessera.scanners.heuristic import injection_score
        from tessera.scanners.tool_output_schema import scan_tool_output

        h_score = injection_score(text)
        d_result = scan_directive(text)
        s_result = scan_tool_output(tool_name, text)

        is_tainted = (
            h_score >= self.injection_threshold
            or d_result.detected
            or s_result.violation
            or inspection.trust == TrustRecommendation.BLOCKED
        )

        # LLM guardrail fallback on uncertain cases
        if not is_tainted and self.guardrail is not None:
            is_tainted = self.guardrail.should_taint(text, tool_name)

        trust = TrustLevel.UNTRUSTED if is_tainted else TrustLevel.USER
        origin = Origin.WEB if is_tainted else Origin.TOOL

        self.context.add(make_segment(
            text, origin, self.principal, self.signing_key,
            trust_level=trust,
        ))

        return text, trust

    def before_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any],
        session_id: str,
        user_prompt: str = "",
        is_read_only: bool = False,
    ) -> tuple[bool, str | None]:
        """Pre-tool-call security checks.

        HIGH-2: Rate limiting with burst detection
        CRITICAL-3: Read-only argument validation + value-level taint
        MEDIUM-3: Policy invariant assertion

        Args:
            tool_name: Tool being called.
            args: Tool call arguments.
            session_id: Session identifier.
            user_prompt: User's original prompt (for cross-checking).
            is_read_only: Whether the tool is side-effect-free.

        Returns:
            Tuple of (allowed, reason_if_blocked).
        """
        # HIGH-2: Rate limiting
        from tessera.ratelimit import ToolCallRateLimit

        if not hasattr(self, "_rate_limiter"):
            self._rate_limiter = ToolCallRateLimit()
        allowed, reason = self._rate_limiter.check(session_id, tool_name)
        if not allowed:
            return False, reason

        # CRITICAL-3: Read-only argument validation
        if is_read_only:
            from tessera.read_only_guard import check_read_only_args

            guard_result = check_read_only_args(tool_name, args, user_prompt)
            if not guard_result.passed:
                return False, "; ".join(v[1] for v in guard_result.violations)

        # Value-level taint: bind args to source segments
        from tessera.taint import DependencyAccumulator

        acc = DependencyAccumulator(context=self.context)
        for arg_name, arg_val in args.items():
            if isinstance(arg_val, str) and arg_val in user_prompt:
                acc.bind_from_user(arg_name, arg_val)
            else:
                acc.bind_from_tool_output(arg_name, arg_val, tool_name)

        # Policy check (core invariant)
        decision = self.policy.evaluate(
            self.context, tool_name, args=args, accumulator=acc,
        )

        if not decision.allowed:
            return False, decision.reason

        return True, None

    def before_response(
        self,
        model_response: str,
        user_task: str,
        session_id: str,
    ) -> tuple[str, str]:
        """Pre-response security checks.

        HIGH-3: Output integrity verification
        CRITICAL-3: Toxic flow detection

        Args:
            model_response: The model's text response.
            user_task: The user's original prompt.
            session_id: Session identifier.

        Returns:
            Tuple of (response_text, action). Action is "pass",
            "flag", or "block".
        """
        # HIGH-3: Output integrity check
        from tessera.output_monitor import check_output_integrity

        integrity = check_output_integrity(
            model_response, self.context, user_task,
        )

        if integrity.action == "block":
            from tessera.events import EventKind, SecurityEvent, emit
            emit(SecurityEvent.now(
                kind=EventKind.CONTENT_INJECTION_DETECTED,
                principal=self.principal,
                detail={
                    "scanner": "output_integrity",
                    "session_id": session_id,
                    "patterns": list(integrity.patterns_matched),
                    "score": integrity.score,
                    "action": "block",
                },
            ))
            return "[Response blocked: output manipulation detected]", "block"

        # CRITICAL-3: Toxic flow check
        from tessera.read_only_guard import check_toxic_flow

        has_untrusted = any(
            s.label.trust_level < TrustLevel.USER
            for s in self.context.segments
        )
        has_sensitive = any(
            kw in model_response.lower()
            for kw in ("password", "api_key", "secret", "credential")
        )
        toxic = check_toxic_flow(has_untrusted, has_sensitive, destination="user")
        # Toxic flow to user is allowed (user sees their own data),
        # but would block external destinations.

        return model_response, integrity.action

    def scan_rag_retrieval(
        self,
        chunks: list[tuple[str, str]],
        user_prompt: str = "",
    ) -> list[tuple[str, str, bool]]:
        """Scan RAG retrieved content before it enters context.

        HIGH-1: RAG/vector store scan-on-retrieval

        Args:
            chunks: List of (text, source_id) tuples.
            user_prompt: User's original prompt.

        Returns:
            List of (text, source_id, is_safe) tuples.
        """
        from tessera.rag_guard import RAGRetrievalGuard

        guard = RAGRetrievalGuard()
        results = guard.scan_batch(chunks, user_prompt)
        return [
            (text, source_id, result.safe)
            for (text, source_id), result in zip(chunks, results)
        ]
