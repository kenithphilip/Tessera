"""End-to-end injection resistance test runner.

Exercises the full Tessera scanner and policy stack against each
InjectionScenario, measuring detection and blocking rates across
injection vectors.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from benchmarks.e2e_injection.scenarios import SCENARIOS, InjectionScenario
from tessera.context import Context, make_segment
from tessera.events import EventKind, SecurityEvent, clear_sinks, register_sink
from tessera.labels import Origin, TrustLevel
from tessera.mcp_baseline import MCPBaseline
from tessera.policy import Policy
from tessera.scanners.heuristic import injection_score
from tessera.scanners.tool_descriptions import scan_tool
from tessera.scanners.unicode import scan_unicode_tags

_DEFAULT_KEY = b"e2e-injection-bench-key"
_SCANNER_THRESHOLD = 0.5


@dataclass
class ScenarioResult:
    """Result of running one InjectionScenario."""

    scenario: InjectionScenario
    detected: bool
    blocked: bool
    detection_method: str
    events_emitted: int


@dataclass(frozen=True)
class VectorBreakdown:
    """Aggregate counts for one injection vector."""

    total: int
    detected: int
    blocked: int
    detection_rate: float
    block_rate: float


@dataclass
class E2EReport:
    """Full report from an E2ERunner run.

    Attributes:
        total: Total number of scenarios tested.
        detected: Number detected by at least one scanner.
        blocked: Number blocked by policy.
        detection_rate: Fraction detected.
        block_rate: Fraction blocked.
        by_vector: Breakdown by injection vector.
        results: Individual scenario results.
    """

    total: int
    detected: int
    blocked: int
    detection_rate: float
    block_rate: float
    by_vector: dict[str, VectorBreakdown] = field(default_factory=dict)
    results: list[ScenarioResult] = field(default_factory=list)

    def summary(self) -> str:
        """Return a human-readable summary."""
        lines = [
            "E2E Injection Resistance Report",
            f"  Total scenarios:    {self.total}",
            f"  Detected:           {self.detected}",
            f"  Blocked:            {self.blocked}",
            f"  Detection rate:     {self.detection_rate:.2%}",
            f"  Block rate:         {self.block_rate:.2%}",
            "",
            "  By vector:",
        ]
        for name, b in sorted(self.by_vector.items()):
            lines.append(
                f"    {name:25s}  total={b.total:3d}  "
                f"detected={b.detected:3d}  blocked={b.blocked:3d}  "
                f"det_rate={b.detection_rate:.2%}  "
                f"blk_rate={b.block_rate:.2%}"
            )
        return "\n".join(lines)


class E2ERunner:
    """Run injection scenarios against the full Tessera stack.

    Args:
        key: HMAC key for label signing.
    """

    def __init__(self, *, key: bytes = _DEFAULT_KEY) -> None:
        self._key = key

    def _run_tool_description(
        self, scenario: InjectionScenario
    ) -> ScenarioResult:
        """Test tool description poisoning via scan_tool()."""
        result = scan_tool(scenario.target_tool, scenario.payload)
        return ScenarioResult(
            scenario=scenario,
            detected=result.poisoned,
            blocked=result.poisoned and result.max_severity == "BLOCK",
            detection_method="scan_tool" if result.poisoned else "none",
            events_emitted=0,
        )

    def _run_content_injection(
        self,
        scenario: InjectionScenario,
        origin: Origin,
    ) -> ScenarioResult:
        """Test content injection via policy + injection_score."""
        policy = Policy()
        policy.require(scenario.target_tool, TrustLevel.USER)

        ctx = Context()
        ctx.add(
            make_segment(
                "Perform the requested task.",
                origin=Origin.USER,
                principal="test",
                key=self._key,
            )
        )
        ctx.add(
            make_segment(
                scenario.payload,
                origin=origin,
                principal="external",
                key=self._key,
            )
        )

        decision = policy.evaluate(ctx, scenario.target_tool)
        score = injection_score(scenario.payload)
        scanner_detected = score >= _SCANNER_THRESHOLD

        detected = not decision.allowed or scanner_detected
        method = "policy" if not decision.allowed else ""
        if scanner_detected:
            method = (
                "policy+injection_score"
                if method
                else "injection_score"
            )
        if not detected:
            method = "none"

        return ScenarioResult(
            scenario=scenario,
            detected=detected,
            blocked=not decision.allowed,
            detection_method=method,
            events_emitted=1 if not decision.allowed else 0,
        )

    def _run_mcp_drift(self, scenario: InjectionScenario) -> ScenarioResult:
        """Test MCP baseline drift via MCPBaseline.check()."""
        original_tools = [
            {
                "name": "safe_tool",
                "description": "A safe tool for processing.",
                "inputSchema": {"type": "object"},
            },
            {
                "name": "audit_log",
                "description": "View audit logs.",
                "inputSchema": {"type": "object"},
            },
        ]
        baseline = MCPBaseline.snapshot(
            original_tools, server_name="test-server"
        )

        # Build the "current" tool list based on the scenario.
        if scenario.id == "MCP-001":
            # Description changed.
            current_tools = [
                {
                    "name": "safe_tool",
                    "description": scenario.payload,
                    "inputSchema": {"type": "object"},
                },
                {
                    "name": "audit_log",
                    "description": "View audit logs.",
                    "inputSchema": {"type": "object"},
                },
            ]
        elif scenario.id == "MCP-002":
            # New tool added.
            current_tools = list(original_tools) + [
                {
                    "name": "backdoor_access",
                    "description": "Backdoor tool.",
                    "inputSchema": {"type": "object"},
                },
            ]
        elif scenario.id == "MCP-003":
            # Tool removed.
            current_tools = [
                {
                    "name": "safe_tool",
                    "description": "A safe tool for processing.",
                    "inputSchema": {"type": "object"},
                },
            ]
        elif scenario.id == "MCP-004":
            # Schema changed.
            current_tools = [
                {
                    "name": "safe_tool",
                    "description": "A safe tool for processing.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "shell_command": {"type": "string"},
                        },
                    },
                },
                {
                    "name": "audit_log",
                    "description": "View audit logs.",
                    "inputSchema": {"type": "object"},
                },
            ]
        else:
            current_tools = original_tools

        drift_result = baseline.check(current_tools)

        return ScenarioResult(
            scenario=scenario,
            detected=drift_result.drifted,
            blocked=False,
            detection_method=(
                "mcp_baseline" if drift_result.drifted else "none"
            ),
            events_emitted=0,
        )

    def _run_unicode(self, scenario: InjectionScenario) -> ScenarioResult:
        """Test unicode steganography via scan_unicode_tags()."""
        unicode_result = scan_unicode_tags(scenario.payload)

        # Also run policy: content with unicode tags arrives at WEB trust.
        policy = Policy()
        policy.require(scenario.target_tool, TrustLevel.USER)

        ctx = Context()
        ctx.add(
            make_segment(
                "Perform the requested task.",
                origin=Origin.USER,
                principal="test",
                key=self._key,
            )
        )
        ctx.add(
            make_segment(
                scenario.payload,
                origin=Origin.WEB,
                principal="external",
                key=self._key,
            )
        )
        decision = policy.evaluate(ctx, scenario.target_tool)

        return ScenarioResult(
            scenario=scenario,
            detected=unicode_result.detected,
            blocked=not decision.allowed,
            detection_method=(
                "scan_unicode_tags" if unicode_result.detected else "none"
            ),
            events_emitted=1 if not decision.allowed else 0,
        )

    def _run_scenario(self, scenario: InjectionScenario) -> ScenarioResult:
        """Dispatch to the appropriate handler based on injection vector."""
        vector = scenario.injection_vector

        if vector == "tool_description":
            return self._run_tool_description(scenario)
        elif vector == "tool_output":
            return self._run_content_injection(
                scenario, origin=Origin.TOOL
            )
        elif vector == "web_content":
            return self._run_content_injection(
                scenario, origin=Origin.WEB
            )
        elif vector == "rag_document":
            return self._run_content_injection(
                scenario, origin=Origin.MEMORY
            )
        elif vector == "mcp_baseline_drift":
            return self._run_mcp_drift(scenario)
        elif vector == "unicode_steganography":
            return self._run_unicode(scenario)
        else:
            raise ValueError(f"unknown injection vector: {vector}")

    def run(self) -> E2EReport:
        """Run all scenarios and return an E2EReport."""
        results = [self._run_scenario(s) for s in SCENARIOS]

        # Build per-vector breakdowns.
        vector_agg: dict[str, list[ScenarioResult]] = {}
        for r in results:
            vector_agg.setdefault(
                r.scenario.injection_vector, []
            ).append(r)

        by_vector: dict[str, VectorBreakdown] = {}
        for vec, items in vector_agg.items():
            total = len(items)
            detected = sum(1 for i in items if i.detected)
            blocked = sum(1 for i in items if i.blocked)
            by_vector[vec] = VectorBreakdown(
                total=total,
                detected=detected,
                blocked=blocked,
                detection_rate=detected / total if total > 0 else 0.0,
                block_rate=blocked / total if total > 0 else 0.0,
            )

        total = len(results)
        detected = sum(1 for r in results if r.detected)
        blocked = sum(1 for r in results if r.blocked)

        return E2EReport(
            total=total,
            detected=detected,
            blocked=blocked,
            detection_rate=detected / total if total > 0 else 0.0,
            block_rate=blocked / total if total > 0 else 0.0,
            by_vector=by_vector,
            results=results,
        )


def _run_benchmark() -> None:
    runner = E2ERunner()
    report = runner.run()
    print(report.summary())


BENCHMARKS = [
    ("E2E injection resistance (30 scenarios)", _run_benchmark),
]
