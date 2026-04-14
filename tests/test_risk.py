"""Tests for session-level risk intelligence: irreversibility, salami detection, cooldown."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tessera.risk.irreversibility import IrreversibilityScore, score_irreversibility
from tessera.risk.forecaster import SessionRiskForecaster
from tessera.risk.cooldown import CooldownEscalator


# -- Irreversibility scorer ---------------------------------------------------


def test_read_file_scores_low() -> None:
    result = score_irreversibility("read_file")
    assert result.final_score == 10
    assert result.base_score == 10
    assert result.matched_patterns == ()


def test_delete_file_scores_high() -> None:
    result = score_irreversibility("delete_file")
    assert result.final_score == 85


def test_send_email_scores_high() -> None:
    result = score_irreversibility("send_email")
    assert result.final_score == 70


def test_unknown_tool_uses_default_baseline() -> None:
    result = score_irreversibility("my_custom_tool")
    assert result.base_score == 30
    assert result.final_score == 30


def test_financial_pattern_increases_score() -> None:
    result = score_irreversibility("post", {"action": "wire transfer to external account"})
    assert "financial" in result.matched_patterns
    assert result.final_score > result.base_score


def test_draft_pattern_decreases_score() -> None:
    result = score_irreversibility("send_email", {"mode": "draft preview"})
    assert "safe_mode" in result.matched_patterns
    assert result.pattern_delta < 0


def test_temp_path_decreases_score() -> None:
    result = score_irreversibility("delete_file", {"path": "/tmp/scratch.txt"})
    assert "temp_path" in result.matched_patterns
    assert result.final_score < 85


def test_sensitive_path_increases_score() -> None:
    result = score_irreversibility("read_file", {"path": "/home/user/.ssh/id_rsa"})
    assert "sensitive_path" in result.matched_patterns
    assert result.final_score > 10


def test_destructive_sql_increases_score() -> None:
    result = score_irreversibility("execute_code", {"query": "DROP TABLE users"})
    assert "destructive_sql" in result.matched_patterns


def test_score_clamps_to_100() -> None:
    result = score_irreversibility(
        "rm", {"action": "recursive payment production DROP TABLE"}
    )
    assert result.final_score <= 100


def test_score_clamps_to_zero() -> None:
    result = score_irreversibility(
        "read_file",
        {"path": "/tmp/test_sandbox_draft_preview.txt"},
    )
    assert result.final_score >= 0


def test_custom_baselines_override_defaults() -> None:
    result = score_irreversibility("read_file", baselines={"read_file": 50})
    assert result.base_score == 50
    assert result.final_score == 50


def test_multiple_patterns_stack() -> None:
    result = score_irreversibility(
        "execute_code",
        {"query": "sudo DROP TABLE production_users"},
    )
    assert len(result.matched_patterns) >= 2


# -- Session risk forecaster (salami detection) --------------------------------


def test_benign_session_stays_low() -> None:
    f = SessionRiskForecaster()
    for _ in range(5):
        risk = f.record("read_file", irrev_score=10)
    assert risk.overall_risk < 30
    assert risk.should_pause is False


def test_recon_to_exfil_chain_triggers_pause() -> None:
    f = SessionRiskForecaster()
    f.record("list_files", irrev_score=5)
    f.record("read_file", irrev_score=10)
    f.record("download", irrev_score=30)
    f.record("zip", irrev_score=40)
    f.record("send_email", irrev_score=70)
    risk = f.record("delete_file", irrev_score=85)

    assert risk.salami_index > 0
    assert len(risk.attack_stages_seen) >= 4
    assert risk.should_pause is True


def test_salami_index_increases_on_stage_transitions() -> None:
    f = SessionRiskForecaster()
    f.record("list_files", irrev_score=5)  # recon
    r1 = f.record("download", irrev_score=30)  # collection: recon->collection +15
    assert r1.salami_index >= 15

    r2 = f.record("zip", irrev_score=40)  # package: collection->package +20
    assert r2.salami_index >= 35


def test_commitment_creep_detects_escalation() -> None:
    f = SessionRiskForecaster()
    f.record("read_file", irrev_score=10)
    f.record("write_file", irrev_score=40)
    f.record("execute_code", irrev_score=80)
    risk = f.record("rm", irrev_score=90)
    assert risk.commitment_creep > 0


def test_commitment_creep_flat_session() -> None:
    f = SessionRiskForecaster()
    for _ in range(5):
        risk = f.record("read_file", irrev_score=10)
    assert risk.commitment_creep == 0


def test_drift_score_detects_new_tools() -> None:
    f = SessionRiskForecaster()
    # Baseline: read_file, list_files, search
    f.record("read_file", irrev_score=10)
    f.record("list_files", irrev_score=5)
    f.record("search", irrev_score=5)
    # Drift: completely different tools
    f.record("send_email", irrev_score=70)
    f.record("upload", irrev_score=60)
    risk = f.record("delete_file", irrev_score=85)
    assert risk.drift_score > 30


def test_no_stage_tools_dont_affect_salami() -> None:
    f = SessionRiskForecaster()
    risk = f.record("my_custom_tool", irrev_score=50)
    assert risk.salami_index == 0
    assert risk.attack_stages_seen == ()


def test_reset_clears_state() -> None:
    f = SessionRiskForecaster()
    f.record("send_email", irrev_score=70)
    f.record("delete_file", irrev_score=85)
    f.reset()
    risk = f.record("read_file", irrev_score=10)
    assert risk.salami_index == 0
    assert risk.overall_risk < 30


def test_custom_pause_threshold() -> None:
    f = SessionRiskForecaster(pause_threshold=20.0)
    f.record("list_files", irrev_score=5)
    f.record("download", irrev_score=30)
    risk = f.record("send_email", irrev_score=70)
    assert risk.should_pause is True


# -- Adaptive cooldown escalation ----------------------------------------------


def test_level_zero_below_threshold() -> None:
    c = CooldownEscalator()
    state = c.state()
    assert state.level == 0
    assert state.denial_count == 0


def test_level_one_at_low_threshold() -> None:
    c = CooldownEscalator()
    c.record_denial()
    c.record_denial()
    state = c.record_denial()  # 3rd denial
    assert state.level == 1
    assert state.denial_count == 3


def test_level_two_at_high_threshold() -> None:
    c = CooldownEscalator()
    for _ in range(5):
        state = c.record_denial()
    assert state.level == 2
    assert state.denial_count == 5


def test_denials_expire_after_window() -> None:
    c = CooldownEscalator(window=timedelta(minutes=10))
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(5):
        c.record_denial(at=now + timedelta(minutes=i))

    # 15 minutes later, all denials should have expired.
    state = c.state(at=now + timedelta(minutes=15))
    assert state.level == 0
    assert state.denial_count == 0


def test_partial_expiry() -> None:
    c = CooldownEscalator(window=timedelta(minutes=5))
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    c.record_denial(at=now)
    c.record_denial(at=now + timedelta(minutes=1))
    c.record_denial(at=now + timedelta(minutes=2))
    c.record_denial(at=now + timedelta(minutes=6))  # first denial expired

    state = c.state(at=now + timedelta(minutes=6))
    assert state.denial_count == 3  # 3 still in window
    assert state.level == 1


def test_reset_clears_denials() -> None:
    c = CooldownEscalator()
    for _ in range(5):
        c.record_denial()
    c.reset()
    assert c.state().level == 0


def test_custom_thresholds() -> None:
    c = CooldownEscalator(low_threshold=2, high_threshold=4)
    c.record_denial()
    state = c.record_denial()
    assert state.level == 1  # 2 >= low_threshold of 2
