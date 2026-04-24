"""Tests for the AST-rewriting label propagator and lint check.

Pinning the contract that ``@provenance_tracked`` rewrites
f-strings into label-preserving calls and the lint check finds
adapter handlers missing the decorator.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tessera.lint import (
    CoverageGap,
    check_provenance_coverage,
)
from tessera.taint.instrument import TRACKED_FUNCTIONS, provenance_tracked
from tessera.taint.label import IntegrityLevel, ProvenanceLabel
from tessera.taint.tstr import TaintedStr


# --- @provenance_tracked rewriting -----------------------------------------


@pytest.fixture
def web_str() -> TaintedStr:
    label = ProvenanceLabel.untrusted_tool_output(
        segment_id="seg-w", origin_uri="web://x"
    )
    return TaintedStr("payload", label)


def test_decorator_preserves_label_through_fstring(web_str: TaintedStr) -> None:
    @provenance_tracked
    def render(value: str) -> str:
        return f"prefix: {value} end"

    out = render(web_str)
    assert isinstance(out, TaintedStr)
    assert out == "prefix: payload end"
    assert out._label.integrity == IntegrityLevel.UNTRUSTED


def test_decorator_no_op_for_bare_str() -> None:
    @provenance_tracked
    def render(value: str) -> str:
        return f"hello {value}"

    out = render("world")
    # Bare-str input means no labels in play; result must remain bare str.
    assert isinstance(out, str)
    assert not isinstance(out, TaintedStr)
    assert out == "hello world"


def test_decorator_handles_multiple_interpolations(web_str: TaintedStr) -> None:
    user_label = ProvenanceLabel.trusted_user("alice")
    user_str = TaintedStr("alice", user_label)

    @provenance_tracked
    def render(user: str, msg: str) -> str:
        return f"{user} said: {msg}"

    out = render(user_str, web_str)
    assert isinstance(out, TaintedStr)
    # Join: USER + UNTRUSTED = UNTRUSTED.
    assert out._label.integrity == IntegrityLevel.UNTRUSTED


def test_decorator_handles_format_spec(web_str: TaintedStr) -> None:
    @provenance_tracked
    def render(value: str) -> str:
        return f"{value:>20}"

    out = render(web_str)
    assert isinstance(out, TaintedStr)
    assert out._label.integrity == IntegrityLevel.UNTRUSTED


def test_decorator_preserves_function_name() -> None:
    @provenance_tracked
    def my_handler(value: str) -> str:
        return f">{value}<"

    assert my_handler.__name__ == "my_handler"


def test_decorator_preserves_docstring() -> None:
    @provenance_tracked
    def my_handler(value: str) -> str:
        """My very important docstring."""
        return f">{value}<"

    assert my_handler.__doc__ == "My very important docstring."


def test_decorator_registers_qualname_in_tracked_set() -> None:
    @provenance_tracked
    def some_named_handler(v: str) -> str:
        return f"{v}"

    qual = some_named_handler.__module__ + "." + some_named_handler.__qualname__
    # Note: after rewriting, __qualname__ may contain __wrapped__ / different
    # qualname. Look for any entry containing the function name.
    assert any("some_named_handler" in q for q in TRACKED_FUNCTIONS)


# --- lint coverage check ----------------------------------------------------


def _write(tmp_path: Path, name: str, src: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    return p


def test_lint_flags_handler_prefix_without_decorator(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    _write(
        pkg,
        "__init__.py",
        "",
    )
    _write(
        pkg,
        "adapter.py",
        """
        def handle_message(value):
            return f"{value}"
        """,
    )

    gaps = check_provenance_coverage([pkg])
    assert any(g.qualname == "handle_message" for g in gaps)


def test_lint_does_not_flag_decorated_function(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    _write(pkg, "__init__.py", "")
    _write(
        pkg,
        "adapter.py",
        """
        from tessera.taint.instrument import provenance_tracked

        @provenance_tracked
        def handle_message(value):
            return f"{value}"
        """,
    )

    gaps = check_provenance_coverage([pkg])
    assert not any(g.qualname == "handle_message" for g in gaps)


def test_lint_flags_labeled_param_annotation(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    _write(pkg, "__init__.py", "")
    _write(
        pkg,
        "adapter.py",
        """
        from tessera.taint.tstr import TaintedStr

        def consume(value: TaintedStr) -> str:
            return f"{value}"
        """,
    )

    gaps = check_provenance_coverage([pkg])
    assert any(g.qualname == "consume" for g in gaps)


def test_lint_respects_allowlist(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    _write(pkg, "__init__.py", "")
    _write(
        pkg,
        "adapter.py",
        """
        def handle_message(value):
            return f"{value}"
        """,
    )

    gaps = check_provenance_coverage(
        [pkg], allowlist=["pkg.adapter.handle_message"]
    )
    assert not any(g.qualname == "handle_message" for g in gaps)


def test_lint_skips_nested_function(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    _write(pkg, "__init__.py", "")
    _write(
        pkg,
        "adapter.py",
        """
        def outer():
            def handle_inner(value):
                return value
            return handle_inner
        """,
    )

    gaps = check_provenance_coverage([pkg])
    # outer() doesn't match any pattern; handle_inner is nested so skipped.
    assert not any(g.qualname == "handle_inner" for g in gaps)


def test_lint_returns_stable_sorted_order(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    _write(pkg, "__init__.py", "")
    _write(
        pkg,
        "a.py",
        """
        def handle_a():
            pass
        """,
    )
    _write(
        pkg,
        "b.py",
        """
        def handle_b():
            pass
        """,
    )

    gaps = check_provenance_coverage([pkg])
    files = [g.file_path for g in gaps]
    assert files == sorted(files)


def test_lint_format_includes_actionable_message() -> None:
    gap = CoverageGap(
        module="pkg.adapter",
        qualname="handle_message",
        file_path="pkg/adapter.py",
        line=12,
        reason="name matches handler prefix",
    )
    msg = gap.format()
    assert "pkg/adapter.py:12" in msg
    assert "handle_message" in msg
    assert "@provenance_tracked" in msg
