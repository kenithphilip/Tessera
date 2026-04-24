"""TaintedStr label-preservation invariants.

For every string operation Tessera supports, the label must travel
to the result. Failure of any test here is a security regression:
labels evaporating mid-pipeline means downstream policy checks
trust unlabeled bytes.

The string-operation surface tested is the union of pytaint /
fuzzingbook / Conti & Russo (LNCS 2010) - approximately 28 dunder
methods + factory helpers. Operations that legitimately drop
labels at C boundaries (locale.strcoll, unicodedata.normalize)
are NOT tested here; the recovery step at the next provenance
boundary handles those.

References
----------

- ``docs/strategy/2026-04-engineering-brief.md`` Section 1.4.
"""

from __future__ import annotations

import copy

import pytest

from tessera.taint.label import (
    IntegrityLevel,
    ProvenanceLabel,
    SecrecyLevel,
)
from tessera.taint.tstr import TaintedStr, taint_fstring, tjoin


@pytest.fixture
def web_label() -> ProvenanceLabel:
    return ProvenanceLabel.untrusted_tool_output(
        segment_id="seg-7", origin_uri="web://evil.example"
    )


@pytest.fixture
def user_label() -> ProvenanceLabel:
    return ProvenanceLabel.trusted_user("alice")


@pytest.fixture
def web_str(web_label: ProvenanceLabel) -> TaintedStr:
    return TaintedStr("payload from web", web_label)


@pytest.fixture
def user_str(user_label: ProvenanceLabel) -> TaintedStr:
    return TaintedStr("user-typed text", user_label)


# ---------------------------------------------------------------------------
# Construction + str inheritance basics
# ---------------------------------------------------------------------------


def test_constructor_carries_label(web_str, web_label) -> None:
    assert web_str._label is web_label


def test_str_inheritance_equality_with_bare_str(web_str) -> None:
    assert web_str == "payload from web"
    assert hash(web_str) == hash("payload from web")


def test_deepcopy_preserves_label_via_reduce(web_str, web_label) -> None:
    """Exercises the __reduce__ protocol path that pickle / copy /
    multiprocessing all share, without triggering the pickle hook."""
    revived = copy.deepcopy(web_str)
    assert isinstance(revived, TaintedStr)
    assert revived._label.integrity == web_label.integrity
    assert revived == web_str


def test_repr_shows_label_integrity(web_str) -> None:
    rep = repr(web_str)
    assert "TaintedStr" in rep
    assert "UNTRUSTED" in rep


# ---------------------------------------------------------------------------
# Arithmetic-shaped operators
# ---------------------------------------------------------------------------


def test_add_joins_labels(web_str, user_str) -> None:
    combined = user_str + web_str
    assert isinstance(combined, TaintedStr)
    assert combined == "user-typed textpayload from web"
    assert combined._label.integrity == IntegrityLevel.UNTRUSTED


def test_radd_joins_labels(web_str) -> None:
    combined = "prefix " + web_str
    assert isinstance(combined, TaintedStr)
    assert combined._label.integrity == IntegrityLevel.UNTRUSTED


def test_add_with_bare_str_keeps_label(user_str) -> None:
    combined = user_str + " suffix"
    assert isinstance(combined, TaintedStr)
    assert combined._label.integrity == IntegrityLevel.TRUSTED


def test_mul_preserves_label(user_str) -> None:
    repeated = user_str * 3
    assert isinstance(repeated, TaintedStr)
    assert repeated == "user-typed textuser-typed textuser-typed text"
    assert repeated._label.integrity == IntegrityLevel.TRUSTED


def test_mod_with_tuple_args_joins_labels(web_str, user_label) -> None:
    template = TaintedStr("greeting: %s", user_label)
    result = template % (web_str,)
    assert isinstance(result, TaintedStr)
    assert result._label.integrity == IntegrityLevel.UNTRUSTED


def test_mod_with_dict_args_joins_labels(web_str, user_label) -> None:
    template = TaintedStr("greeting: %(who)s", user_label)
    result = template % {"who": web_str}
    assert isinstance(result, TaintedStr)
    assert result._label.integrity == IntegrityLevel.UNTRUSTED


# ---------------------------------------------------------------------------
# Indexing and slicing
# ---------------------------------------------------------------------------


def test_getitem_preserves_label(web_str) -> None:
    sliced = web_str[0:7]
    assert isinstance(sliced, TaintedStr)
    assert sliced == "payload"
    assert sliced._label.integrity == IntegrityLevel.UNTRUSTED


def test_iter_yields_tainted_chars(web_str) -> None:
    chars = list(web_str)
    assert all(isinstance(c, TaintedStr) for c in chars)
    assert all(c._label.integrity == IntegrityLevel.UNTRUSTED for c in chars)


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def test_format_with_tainted_value_joins_labels(web_str, user_label) -> None:
    template = TaintedStr("to: {}", user_label)
    result = template.format(web_str)
    assert isinstance(result, TaintedStr)
    assert result._label.integrity == IntegrityLevel.UNTRUSTED


def test_format_with_keyword_arg(web_str, user_label) -> None:
    template = TaintedStr("to: {who}", user_label)
    result = template.format(who=web_str)
    assert isinstance(result, TaintedStr)
    assert result._label.integrity == IntegrityLevel.UNTRUSTED


def test_format_dunder_keeps_label(web_str) -> None:
    formatted = format(web_str, ">20")
    assert isinstance(formatted, TaintedStr)
    assert formatted._label.integrity == IntegrityLevel.UNTRUSTED


def test_format_map_joins_labels(web_str, user_label) -> None:
    template = TaintedStr("to: {who}", user_label)
    result = template.format_map({"who": web_str})
    assert isinstance(result, TaintedStr)
    assert result._label.integrity == IntegrityLevel.UNTRUSTED


def test_taint_fstring_helper_simulates_ast_rewrite(web_str) -> None:
    # The Phase 1B-ii AST rewriter rewrites `f"prefix: {web_str} end"`
    # into a call of taint_fstring; this test simulates that.
    result = taint_fstring("prefix: ", web_str, " end")
    assert isinstance(result, TaintedStr)
    assert result == "prefix: payload from web end"
    assert result._label.integrity == IntegrityLevel.UNTRUSTED


# ---------------------------------------------------------------------------
# Joining and splitting
# ---------------------------------------------------------------------------


def test_join_method_joins_labels(web_str, user_label) -> None:
    sep = TaintedStr(", ", user_label)
    result = sep.join([web_str, "bare"])
    assert isinstance(result, TaintedStr)
    assert result._label.integrity == IntegrityLevel.UNTRUSTED


def test_tjoin_helper_joins_labels(web_str, user_str) -> None:
    result = tjoin(", ", [user_str, web_str])
    assert isinstance(result, TaintedStr)
    assert result._label.integrity == IntegrityLevel.UNTRUSTED


def test_split_preserves_label_on_pieces(web_str) -> None:
    pieces = web_str.split(" ")
    assert all(isinstance(p, TaintedStr) for p in pieces)
    assert all(p._label.integrity == IntegrityLevel.UNTRUSTED for p in pieces)


def test_rsplit_preserves_label_on_pieces(user_str) -> None:
    pieces = user_str.rsplit(" ", 1)
    assert all(isinstance(p, TaintedStr) for p in pieces)
    assert all(p._label.integrity == IntegrityLevel.TRUSTED for p in pieces)


def test_splitlines_preserves_label(user_label) -> None:
    s = TaintedStr("line one\nline two\n", user_label)
    pieces = s.splitlines()
    assert all(isinstance(p, TaintedStr) for p in pieces)


def test_partition_preserves_label(user_str) -> None:
    a, b, c = user_str.partition("typed")
    assert isinstance(a, TaintedStr) and isinstance(b, TaintedStr) and isinstance(c, TaintedStr)
    assert a._label.integrity == IntegrityLevel.TRUSTED


def test_rpartition_preserves_label(user_str) -> None:
    a, b, c = user_str.rpartition(" ")
    assert isinstance(c, TaintedStr)
    assert c._label.integrity == IntegrityLevel.TRUSTED


# ---------------------------------------------------------------------------
# Case transforms
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method_name",
    ["upper", "lower", "title", "capitalize", "casefold", "swapcase"],
)
def test_case_transforms_preserve_label(
    user_str: TaintedStr, method_name: str
) -> None:
    method = getattr(user_str, method_name)
    result = method()
    assert isinstance(result, TaintedStr)
    assert result._label.integrity == IntegrityLevel.TRUSTED


# ---------------------------------------------------------------------------
# Trimming and padding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method_name",
    ["strip", "lstrip", "rstrip"],
)
def test_strip_methods_preserve_label(
    user_label: ProvenanceLabel, method_name: str
) -> None:
    s = TaintedStr("  padded  ", user_label)
    method = getattr(s, method_name)
    result = method()
    assert isinstance(result, TaintedStr)
    assert result._label.integrity == IntegrityLevel.TRUSTED


@pytest.mark.parametrize(
    "method_name,args",
    [
        ("center", (20, "*")),
        ("ljust", (20, " ")),
        ("rjust", (20, " ")),
        ("zfill", (20,)),
        ("expandtabs", (4,)),
    ],
)
def test_pad_methods_preserve_label(
    user_str: TaintedStr, method_name: str, args: tuple
) -> None:
    method = getattr(user_str, method_name)
    result = method(*args)
    assert isinstance(result, TaintedStr)
    assert result._label.integrity == IntegrityLevel.TRUSTED


# ---------------------------------------------------------------------------
# Substitution
# ---------------------------------------------------------------------------


def test_replace_with_bare_args_keeps_label(web_str) -> None:
    result = web_str.replace("payload", "blocked")
    assert isinstance(result, TaintedStr)
    assert result == "blocked from web"
    assert result._label.integrity == IntegrityLevel.UNTRUSTED


def test_replace_with_tainted_replacement_joins_labels(
    user_str: TaintedStr, web_str: TaintedStr
) -> None:
    result = user_str.replace("typed", web_str)
    assert isinstance(result, TaintedStr)
    assert result._label.integrity == IntegrityLevel.UNTRUSTED


def test_translate_preserves_label(web_str) -> None:
    table = str.maketrans("abc", "xyz")
    result = web_str.translate(table)
    assert isinstance(result, TaintedStr)
    assert result._label.integrity == IntegrityLevel.UNTRUSTED


# ---------------------------------------------------------------------------
# Cross-cutting: secrecy is also preserved
# ---------------------------------------------------------------------------


def test_secrecy_preserves_through_all_operations() -> None:
    label = ProvenanceLabel(
        sources=frozenset(),
        readers=ProvenanceLabel.trusted_user().readers,
        integrity=IntegrityLevel.TRUSTED,
        secrecy=SecrecyLevel.PRIVATE,
        capacity=ProvenanceLabel.trusted_user().capacity,
    )
    s = TaintedStr("private content", label)
    assert s.upper()._label.secrecy == SecrecyLevel.PRIVATE
    assert (s + s)._label.secrecy == SecrecyLevel.PRIVATE
    assert s.split(" ")[0]._label.secrecy == SecrecyLevel.PRIVATE
