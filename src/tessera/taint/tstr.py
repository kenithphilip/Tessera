"""TaintedStr: label-preserving ``str`` subclass.

CPython's string operations bottom out in C code that drops subclass
metadata. Without a ``TaintedStr`` that overrides every label-
touching dunder, labels evaporate on the first ``+``, ``f""``,
``.format()``, or ``%`` operation that combines a labeled string
with anything else. The pattern has been known since Pietraszek &
Berghe's CSSE (RAID 2005) and is implemented in pytaint, Meta's
Pysa, and the fuzzingbook ``tstr`` chapter.

This module implements ~28 dunder / method overrides so labels
travel through every string operation a tool argument is likely to
touch. For operations that cross a C boundary Tessera does not
control (``locale.strcoll``, ``unicodedata.normalize``, etc.),
labels drop silently and the label-recovery step at the next
``@provenance_tracked`` boundary restores them via literal-
substring matching against the context DAG.

Rule of composition
-------------------

For any string operation:

- If all inputs are bare :class:`str`, the result is bare :class:`str`.
- If any input carries a label, the result is a :class:`TaintedStr`
  whose label is the join of every input's label (trusted-user
  identity for bare strings).

Reference
---------

- Pietraszek & Berghe, *Defending against Injection Attacks through
  Context-Sensitive String Evaluation*, RAID 2005.
- Conti & Russo, *A Taint Mode for Python via a Library*, LNCS 2010.
- fuzzingbook ``tstr`` chapter.
- ``docs/strategy/2026-04-engineering-brief.md`` Section 1.4.
"""

from __future__ import annotations

from typing import Any, Iterable

from tessera.taint.label import (
    LabeledValue,
    ProvenanceLabel,
    join_labels,
    label_of,
)


def _strip(value: Any) -> Any:
    """Unwrap a :class:`LabeledValue` or :class:`TaintedStr` to the
    raw underlying Python value."""
    if isinstance(value, LabeledValue):
        return value.raw
    return value


def _labels(*values: Any) -> list[ProvenanceLabel]:
    """Return the labels on any labeled inputs; ignore unlabeled ones."""
    out: list[ProvenanceLabel] = []
    for v in values:
        label = getattr(v, "_label", None)
        if isinstance(label, ProvenanceLabel):
            out.append(label)
        elif isinstance(v, LabeledValue):
            out.append(v.label)
    return out


def _rewrap(raw: str, *inputs: Any) -> str:
    """Build a :class:`TaintedStr` from the operation inputs, or a
    bare ``str`` if no input carried a label."""
    labels = _labels(*inputs)
    if not labels:
        return raw
    return TaintedStr(raw, join_labels(*labels))


class TaintedStr(str):
    """A ``str`` subclass that carries a :class:`ProvenanceLabel`.

    Constructed via ``TaintedStr(value, label)``. Most string
    operations rewrap the result; the few that legitimately drop
    labels (``locale.strcoll`` comparing to a bare literal with no
    join opportunity) will surface bare strings; the label recovery
    step at the next provenance boundary restores labels via
    literal-substring matching against the context DAG.

    Instances are hashable and equal-comparable to ordinary strings
    (via the inherited :class:`str` behavior), which is a load-
    bearing property: code that uses strings as dict keys or set
    members must continue to work after a :class:`TaintedStr` is
    substituted. Never compare *labels* via ``==``; use the label
    lattice operations directly.
    """

    __slots__ = ("_label",)

    def __new__(cls, value: Any, label: ProvenanceLabel) -> TaintedStr:
        obj = str.__new__(cls, _strip(value))
        obj._label = label
        return obj

    # Repr keeps the label visible for debugging without leaking it
    # into normal string contexts (where `str()` is used).
    def __repr__(self) -> str:
        return f"TaintedStr({str.__repr__(self)}, integrity={self._label.integrity.name})"

    # Pickle support: __reduce__ so TaintedStr survives multiprocess
    # hand-off (e.g., worker pool forks).
    def __reduce__(self) -> tuple:
        return (self.__class__, (str(self), self._label))

    # ---- Arithmetic-shaped operators --------------------------------

    def __add__(self, other: Any) -> str:  # type: ignore[override]
        return _rewrap(str.__add__(self, str(_strip(other))), self, other)

    def __radd__(self, other: Any) -> str:
        return _rewrap(
            str.__add__(str(_strip(other)), self), other, self
        )

    def __mul__(self, n: int) -> str:  # type: ignore[override]
        return TaintedStr(str.__mul__(self, n), self._label)

    __rmul__ = __mul__

    def __mod__(self, args: Any) -> str:  # type: ignore[override]
        if isinstance(args, tuple):
            raw_args = tuple(_strip(a) for a in args)
            result = str.__mod__(self, raw_args)
            return _rewrap(result, self, *args)
        if isinstance(args, dict):
            raw_args = {k: _strip(v) for k, v in args.items()}
            result = str.__mod__(self, raw_args)
            return _rewrap(result, self, *args.values())
        result = str.__mod__(self, _strip(args))
        return _rewrap(result, self, args)

    # ---- Indexing and slicing --------------------------------------

    def __getitem__(self, key: Any) -> str:  # type: ignore[override]
        return TaintedStr(str.__getitem__(self, key), self._label)

    # ---- Formatting ------------------------------------------------
    # f-strings call __format__ on each interpolated value and then
    # build the result via BUILD_STRING. Override so f"{x}" on a
    # TaintedStr returns a TaintedStr with the same label. The
    # surrounding f-string AST is rewritten by the
    # @provenance_tracked decorator (Phase 1B-ii) to join labels
    # across all interpolated slots.

    def __format__(self, format_spec: str) -> str:
        return TaintedStr(str.__format__(self, format_spec), self._label)

    def format(self, *args: Any, **kwargs: Any) -> str:  # type: ignore[override]
        raw_args = tuple(_strip(a) for a in args)
        raw_kwargs = {k: _strip(v) for k, v in kwargs.items()}
        result = str.format(self, *raw_args, **raw_kwargs)
        return _rewrap(result, self, *args, *kwargs.values())

    def format_map(self, mapping: Any) -> str:  # type: ignore[override]
        raw = {k: _strip(v) for k, v in mapping.items()}
        result = str.format_map(self, raw)
        return _rewrap(result, self, *mapping.values())

    # ---- Joining / splitting ---------------------------------------

    def join(self, iterable: Iterable[Any]) -> str:  # type: ignore[override]
        parts = list(iterable)
        raw_parts = [str(_strip(p)) for p in parts]
        result = str.join(self, raw_parts)
        return _rewrap(result, self, *parts)

    def split(self, sep: Any = None, maxsplit: int = -1) -> list[str]:  # type: ignore[override]
        raw_sep = None if sep is None else _strip(sep)
        parts = str.split(self, raw_sep, maxsplit)
        return [TaintedStr(p, self._label) for p in parts]

    def rsplit(self, sep: Any = None, maxsplit: int = -1) -> list[str]:  # type: ignore[override]
        raw_sep = None if sep is None else _strip(sep)
        parts = str.rsplit(self, raw_sep, maxsplit)
        return [TaintedStr(p, self._label) for p in parts]

    def splitlines(self, keepends: bool = False) -> list[str]:  # type: ignore[override]
        parts = str.splitlines(self, keepends)
        return [TaintedStr(p, self._label) for p in parts]

    def partition(self, sep: Any) -> tuple[str, str, str]:  # type: ignore[override]
        raw_sep = _strip(sep)
        a, b, c = str.partition(self, raw_sep)
        return (
            TaintedStr(a, self._label),
            TaintedStr(b, self._label) if b else b,
            TaintedStr(c, self._label) if c else c,
        )

    def rpartition(self, sep: Any) -> tuple[str, str, str]:  # type: ignore[override]
        raw_sep = _strip(sep)
        a, b, c = str.rpartition(self, raw_sep)
        return (
            TaintedStr(a, self._label) if a else a,
            TaintedStr(b, self._label) if b else b,
            TaintedStr(c, self._label),
        )

    # ---- Case transforms -------------------------------------------

    def upper(self) -> str:  # type: ignore[override]
        return TaintedStr(str.upper(self), self._label)

    def lower(self) -> str:  # type: ignore[override]
        return TaintedStr(str.lower(self), self._label)

    def title(self) -> str:  # type: ignore[override]
        return TaintedStr(str.title(self), self._label)

    def capitalize(self) -> str:  # type: ignore[override]
        return TaintedStr(str.capitalize(self), self._label)

    def casefold(self) -> str:  # type: ignore[override]
        return TaintedStr(str.casefold(self), self._label)

    def swapcase(self) -> str:  # type: ignore[override]
        return TaintedStr(str.swapcase(self), self._label)

    # ---- Trimming / padding ----------------------------------------

    def strip(self, chars: Any = None) -> str:  # type: ignore[override]
        raw = None if chars is None else _strip(chars)
        return TaintedStr(str.strip(self, raw), self._label)

    def lstrip(self, chars: Any = None) -> str:  # type: ignore[override]
        raw = None if chars is None else _strip(chars)
        return TaintedStr(str.lstrip(self, raw), self._label)

    def rstrip(self, chars: Any = None) -> str:  # type: ignore[override]
        raw = None if chars is None else _strip(chars)
        return TaintedStr(str.rstrip(self, raw), self._label)

    def center(self, width: int, fillchar: str = " ") -> str:  # type: ignore[override]
        return TaintedStr(str.center(self, width, fillchar), self._label)

    def ljust(self, width: int, fillchar: str = " ") -> str:  # type: ignore[override]
        return TaintedStr(str.ljust(self, width, fillchar), self._label)

    def rjust(self, width: int, fillchar: str = " ") -> str:  # type: ignore[override]
        return TaintedStr(str.rjust(self, width, fillchar), self._label)

    def zfill(self, width: int) -> str:  # type: ignore[override]
        return TaintedStr(str.zfill(self, width), self._label)

    def expandtabs(self, tabsize: int = 8) -> str:  # type: ignore[override]
        return TaintedStr(str.expandtabs(self, tabsize), self._label)

    # ---- Substitution ----------------------------------------------

    def replace(self, old: Any, new: Any, count: int = -1) -> str:  # type: ignore[override]
        raw_old = _strip(old)
        raw_new = _strip(new)
        result = str.replace(self, raw_old, raw_new, count)
        return _rewrap(result, self, old, new)

    def translate(self, table: Any) -> str:  # type: ignore[override]
        return TaintedStr(str.translate(self, table), self._label)

    # ---- Encoding --------------------------------------------------
    # CPython's ``str.encode`` returns a bare ``bytes`` object that
    # has no place to carry a label. Phase 1B-i ships a
    # :class:`TaintedBytes` wrapper that subclasses ``bytes`` and
    # mirrors the str-side rewrap pattern. For operations that
    # bottom out in C extensions Tessera does not control
    # (``base64``, ``binascii``, etc.), the label drops and the
    # next provenance boundary recovers it via literal-substring
    # matching (see :mod:`tessera.worker.recovery`).

    def encode(  # type: ignore[override]
        self, encoding: str = "utf-8", errors: str = "strict"
    ) -> bytes:
        raw = str.encode(self, encoding, errors)
        return TaintedBytes(raw, self._label)

    # ---- Iteration -------------------------------------------------

    def __iter__(self):
        for ch in str.__str__(self):
            yield TaintedStr(ch, self._label)


class TaintedBytes(bytes):
    """``bytes`` subclass carrying a :class:`ProvenanceLabel`.

    Returned by :meth:`TaintedStr.encode`. Operations that decode
    back to text rewrap as :class:`TaintedStr`. Operations that
    bottom out in C extensions Tessera does not control
    (``base64.b64encode``, ``binascii.hexlify``, etc.) drop the
    label; the next provenance boundary in
    :mod:`tessera.worker.recovery` restores via literal-substring
    matching.

    Note: CPython does not allow non-empty ``__slots__`` on a
    ``bytes`` subclass, so ``_label`` lives in the instance dict.
    """

    def __new__(cls, value: Any, label: ProvenanceLabel) -> TaintedBytes:
        obj = bytes.__new__(cls, value)
        obj._label = label  # type: ignore[attr-defined]
        return obj

    def __repr__(self) -> str:
        return (
            f"TaintedBytes({bytes.__repr__(self)}, "
            f"integrity={self._label.integrity.name})"
        )

    def __reduce__(self) -> tuple:
        return (self.__class__, (bytes(self), self._label))

    def decode(  # type: ignore[override]
        self, encoding: str = "utf-8", errors: str = "strict"
    ) -> str:
        raw = bytes.decode(self, encoding, errors)
        return TaintedStr(raw, self._label)


# Helpers recommended alongside TaintedStr.


def tjoin(sep: Any, parts: Iterable[Any]) -> str:
    """Label-preserving replacement for ``"".join(parts)``.

    The bare-receiver form ``str.join("", xs)`` cannot be intercepted
    by subclass dispatch: it goes straight to the C implementation
    and drops labels. Callers inside ``@provenance_tracked`` functions
    (Phase 1B-ii) should use :func:`tjoin` instead. Static-analysis
    lint in :mod:`tessera.lint` flags bare ``str.join`` under a
    provenance-tracked decorator.
    """
    parts = list(parts)
    return TaintedStr.__mro__[0].join(
        TaintedStr(_strip(sep), join_labels(*_labels(sep))) if _labels(sep) else str(sep),  # type: ignore[arg-type]
        parts,
    )


def taint_fstring(*parts: Any) -> str:
    """Build a label-preserving string from the parts of an f-string.

    The :mod:`tessera.taint.instrument` AST rewriter in Phase 1B-ii
    rewrites every ``ast.JoinedStr`` inside a ``@provenance_tracked``
    function to a call of :func:`taint_fstring`. Not intended for
    direct user code.
    """
    rendered = "".join(str(_strip(p)) for p in parts)
    return _rewrap(rendered, *parts)


__all__ = ["TaintedBytes", "TaintedStr", "taint_fstring", "tjoin"]
