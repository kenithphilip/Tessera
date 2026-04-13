"""Tests for the AgentMesh CLI (python -m agentmesh)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from agentmesh.__main__ import main


@pytest.fixture()
def clean_dir(tmp_path, monkeypatch):
    """Switch to a temp directory with no agentmesh.yaml."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_init_creates_yaml_file(clean_dir):
    """Verify 'init' creates agentmesh.yaml in the current directory."""
    code = main(["init"])
    assert code == 0

    target = clean_dir / "agentmesh.yaml"
    assert target.is_file()
    content = target.read_text(encoding="utf-8")
    assert "hmac_key" in content
    assert "default_required_trust" in content
    assert "tool_policies" in content


def test_init_refuses_overwrite(clean_dir):
    """Verify 'init' refuses to overwrite an existing file."""
    (clean_dir / "agentmesh.yaml").write_text("existing", encoding="utf-8")
    code = main(["init"])
    assert code == 1


def test_check_validates_config(clean_dir, capsys):
    """Verify 'check' loads and prints a summary of the config."""
    pytest.importorskip("yaml")
    main(["init"])
    code = main(["check"])
    assert code == 0

    captured = capsys.readouterr()
    assert "Config loaded" in captured.out
    assert "Default required trust" in captured.out


def test_check_with_tool_policies(clean_dir, capsys):
    """Verify 'check' lists per-tool policies."""
    pytest.importorskip("yaml")
    cfg = clean_dir / "agentmesh.yaml"
    cfg.write_text(
        'hmac_key: "test-key-long-enough"\n'
        "tool_policies:\n"
        "  - name: send_email\n"
        "    required_trust: user\n",
        encoding="utf-8",
    )
    code = main(["check"])
    assert code == 0

    captured = capsys.readouterr()
    assert "send_email" in captured.out
    assert "USER" in captured.out


def test_check_missing_file(clean_dir, capsys):
    """Verify 'check' reports error when no config file exists."""
    code = main(["check"])
    assert code == 1

    captured = capsys.readouterr()
    assert "No agentmesh.yaml" in captured.err


def test_version_prints_version(capsys):
    """Verify 'version' prints the version string."""
    code = main(["version"])
    assert code == 0

    captured = capsys.readouterr()
    assert "agentmesh" in captured.out
    assert "0.0.1" in captured.out


def test_no_command_shows_help(capsys):
    """Verify running with no command shows help and returns 1."""
    code = main([])
    assert code == 1


def test_cli_via_subprocess(clean_dir):
    """Verify the CLI runs as 'python -m agentmesh version' via subprocess."""
    result = subprocess.run(
        [sys.executable, "-m", "agentmesh", "version"],
        capture_output=True,
        text=True,
        cwd=str(clean_dir),
    )
    assert result.returncode == 0
    assert "0.0.1" in result.stdout
