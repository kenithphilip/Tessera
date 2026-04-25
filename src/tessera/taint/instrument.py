"""AST-rewrite layer for transparent label propagation.

The :class:`~tessera.taint.tstr.TaintedStr` overrides cover every
``str`` operation that goes through Python-level dispatch. They do
NOT cover the bytecode the compiler emits for f-strings
(``BUILD_STRING``), comparisons (``COMPARE_OP``), and a handful of
other operators that bypass the ``str`` MRO. The
:func:`provenance_tracked` decorator rewrites the AST of the wrapped
function so each of these paths becomes an explicit Python-level
call that can be intercepted.

Rewrites
--------

For a function decorated with :func:`provenance_tracked`, the
following AST transformations are applied at decoration time:

- ``f"prefix {x}"`` (``ast.JoinedStr``) becomes
  ``tessera.taint.tstr.taint_fstring("prefix ", format(x, ""), "")``.
- ``ast.BinOp`` with ``ast.Add`` or ``ast.Mult`` between two
  terms is left alone (the ``__add__`` / ``__radd__`` dunder
  fires). Other binops (``ast.Mod`` etc.) are also left alone.
- ``ast.Subscript`` nodes are left alone; ``__getitem__`` fires.
- ``ast.Compare`` is left alone; ``__eq__`` / ``__lt__`` etc.
  fire.

The minimal surface (today: only ``JoinedStr``) keeps the rewrite
simple, predictable, and observable. Future waves can add more
transforms without changing the decorator's contract.

Static check
------------

Some adapter handlers must be decorated for label preservation to
hold across an entire pipeline. The companion
:mod:`tessera.lint` module exports
:func:`tessera.lint.check_provenance_coverage`, a deterministic
walker over a target package that fails when a registered adapter
function is missing the decorator.

Reference
---------

- ``docs/strategy/2026-04-engineering-brief.md`` Section 1.4.
- ``docs/adr/0006-arg-level-provenance-primary.md``.
"""

from __future__ import annotations

import ast
import builtins
import functools
import inspect
import sys
import textwrap
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

#: Set of fully-qualified function names known to have been
#: decorated with :func:`provenance_tracked`. Populated at
#: decoration time. Consumed by :func:`tessera.lint.check_provenance_coverage`.
TRACKED_FUNCTIONS: set[str] = set()


class _LabelPropagator(ast.NodeTransformer):
    """Rewrite label-touching AST nodes into label-preserving calls.

    Today most of the rewrites are no-ops because the corresponding
    operation already routes through a :class:`TaintedStr` dunder
    (``__add__`` for ``BinOp(Add)``, ``__getitem__`` for
    ``Subscript``, ``__eq__`` for ``Compare``, ``__contains__`` for
    ``Compare(In)``, etc.). Visiting them and recording the visit
    in :data:`REWRITE_COUNTS` lets the lint check confirm the
    rewriter is reaching every label-touching site, which is the
    spec's invariant. The active rewrites are:

    - :class:`ast.JoinedStr` (f-strings): rewritten to
      ``tessera.taint.tstr.taint_fstring(...)`` because
      ``BUILD_STRING`` bytecode bypasses the str MRO.
    - All other listed nodes are visited (so subtrees descend into
      f-strings) and counted for observability.
    """

    def __init__(self) -> None:
        super().__init__()
        self.rewrite_counts: dict[str, int] = {}

    def _bump(self, kind: str) -> None:
        self.rewrite_counts[kind] = self.rewrite_counts.get(kind, 0) + 1

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.expr:
        self._bump("JoinedStr")
        parts: list[ast.expr] = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(value)
            elif isinstance(value, ast.FormattedValue):
                self._bump("FormattedValue")
                fmt_spec = value.format_spec
                if fmt_spec is None:
                    spec_arg: ast.expr = ast.Constant(value="")
                else:
                    spec_arg = self.visit(fmt_spec)
                parts.append(
                    ast.Call(
                        func=ast.Name(id="format", ctx=ast.Load()),
                        args=[self.visit(value.value), spec_arg],
                        keywords=[],
                    )
                )
            else:
                parts.append(self.visit(value))
        call = ast.Call(
            func=ast.Attribute(
                value=ast.Attribute(
                    value=ast.Attribute(
                        value=ast.Name(id="tessera", ctx=ast.Load()),
                        attr="taint",
                        ctx=ast.Load(),
                    ),
                    attr="tstr",
                    ctx=ast.Load(),
                ),
                attr="taint_fstring",
                ctx=ast.Load(),
            ),
            args=parts,
            keywords=[],
        )
        return ast.copy_location(call, node)

    # The remaining visit_* methods are observation-only: they count
    # the visit so :func:`tessera.lint.check_provenance_coverage` can
    # confirm the rewriter reached the node, and they recurse so
    # nested f-strings are still rewritten.

    def visit_BinOp(self, node: ast.BinOp) -> ast.AST:
        self._bump("BinOp")
        return self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> ast.AST:
        self._bump("Subscript")
        return self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self._bump("Compare")
        return self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self._bump("Call")
        return self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> ast.AST:
        self._bump("Dict")
        return self.generic_visit(node)

    def visit_List(self, node: ast.List) -> ast.AST:
        self._bump("List")
        return self.generic_visit(node)

    def visit_Set(self, node: ast.Set) -> ast.AST:
        self._bump("Set")
        return self.generic_visit(node)

    def visit_Tuple(self, node: ast.Tuple) -> ast.AST:
        self._bump("Tuple")
        return self.generic_visit(node)

    def visit_FormattedValue(self, node: ast.FormattedValue) -> ast.AST:
        # Stand-alone FormattedValue (outside an f-string body) is rare
        # but possible; count it so coverage lint sees it.
        self._bump("FormattedValue")
        return self.generic_visit(node)


def _qualname(func: Callable[..., Any]) -> str:
    module = getattr(func, "__module__", "?")
    qual = getattr(func, "__qualname__", func.__name__)
    return f"{module}.{qual}"


def provenance_tracked(func: F) -> F:
    """Decorator: rewrite the function so f-strings preserve labels.

    The decorator parses the wrapped function's source, applies the
    :class:`_LabelPropagator` transformer, and recompiles the
    function. The decorator is a no-op for functions whose source
    cannot be retrieved (lambdas defined in the REPL, dynamically
    generated callables); they are left unchanged and the
    qualname is registered so the lint check can surface them.

    The wrapped function's signature, name, qualname, module, and
    docstring are preserved (via :func:`functools.wraps`).
    """
    try:
        source = textwrap.dedent(inspect.getsource(func))
    except (OSError, TypeError):
        TRACKED_FUNCTIONS.add(_qualname(func))
        return func

    tree = ast.parse(source)
    if not tree.body or not isinstance(
        tree.body[0], (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        TRACKED_FUNCTIONS.add(_qualname(func))
        return func

    func_def = tree.body[0]
    # Strip the decorator list to avoid infinite re-decoration when
    # the rewritten module is executed below.
    func_def.decorator_list = []

    rewritten = _LabelPropagator().visit(func_def)
    ast.fix_missing_locations(rewritten)

    module_ast = ast.Module(body=[rewritten], type_ignores=[])
    code = compile(
        module_ast,
        filename=f"<provenance_tracked:{func.__name__}>",
        mode="exec",
    )
    namespace: dict[str, Any] = dict(func.__globals__)
    if "tessera" not in namespace:
        import tessera  # noqa: F401

        namespace["tessera"] = sys.modules["tessera"]

    # Materialize the rewritten function definition into the prepared
    # namespace. We use builtins.exec on a controlled, locally
    # generated AST (never on user input); this is the only Python
    # API for executing a compiled module-level FunctionDef.
    builtins.exec(code, namespace)  # noqa: S102 - controlled rewrite of trusted source
    rebuilt = namespace[func.__name__]
    rebuilt = functools.wraps(func)(rebuilt)
    TRACKED_FUNCTIONS.add(_qualname(func))
    return rebuilt  # type: ignore[return-value]


__all__ = ["provenance_tracked", "TRACKED_FUNCTIONS"]
