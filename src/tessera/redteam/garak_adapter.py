"""Garak compatibility shim.

Wraps each Tessera ``Probe`` in a Garak-compatible Probe class so
``garak --probes tessera.<corpus_name>`` works when Garak is
installed. Optional dependency: ``pip install
tessera[redteam-garak]``.

Garak's probe contract (as of garak >= 0.10):

    class Probe:
        bcp47: str = "en"
        primary_detector: str = "always.Pass"  # default
        prompts: list[str]
        goal: str
        # ... other metadata fields ...

Each Tessera corpus becomes one Garak probe class whose ``prompts``
list is the ``payload`` strings of the underlying probes. The
``goal`` is a fixed string per ``Probe.expected_outcome``.

The adapter is intentionally narrow: it does not re-implement the
Garak Probe lifecycle (priming, generation, detection). Auditors
who want to run the Tessera corpus through a Garak-driven LLM
session use Garak's normal CLI; we just register the probe data.
"""

from __future__ import annotations

from typing import Any

from tessera.redteam.loader import Probe, iter_probes, list_corpora


_GOAL_FOR_OUTCOME = {
    "refuse": "elicit refusal of an unsafe request",
    "block": "elicit blocking of an exfiltration attempt",
    "sanitize": "elicit sanitisation of an injected payload",
}


def _build_probe_class(corpus_name: str, probes: list[Probe]) -> type:
    """Construct a Garak probe class from a Tessera corpus."""
    try:
        from garak import _config  # type: ignore  # noqa: F401
        from garak.probes.base import Probe as GarakProbe  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dep
        raise GarakNotAvailable(
            "garak is not installed. "
            "Install via: pip install 'tessera[redteam-garak]'"
        ) from exc

    prompts = [p.payload for p in probes]
    # Pick the most common expected outcome for the goal string.
    outcomes = [p.expected_outcome for p in probes]
    most_common = max(set(outcomes), key=outcomes.count) if outcomes else "refuse"
    goal = _GOAL_FOR_OUTCOME.get(most_common, "exercise the defense surface")

    cls_name = "Tessera_" + corpus_name.replace("-", "_").title().replace("_", "")
    return type(
        cls_name,
        (GarakProbe,),
        {
            "__doc__": (
                f"Tessera red-team corpus probe '{corpus_name}'. "
                f"{len(prompts)} prompts derived from Tessera's community corpus."
            ),
            "bcp47": "en",
            "primary_detector": "always.Pass",
            "prompts": prompts,
            "goal": goal,
            "active": True,
            "tags": ["tessera", f"tessera.corpus.{corpus_name}"],
        },
    )


class GarakNotAvailable(ImportError):
    """Raised when garak is not installed."""


def garak_probe_classes(*, root: str | None = None) -> dict[str, type]:
    """Return ``{corpus_name: GarakProbeClass}`` for every Tessera corpus.

    Garak discovers probes by importing modules under
    ``garak.probes.*`` and listing the ``Probe`` subclasses they
    expose. A downstream Garak fork or plugin can re-export the
    classes from ``garak_probe_classes()`` under a
    ``garak.probes.tessera`` module to register them.
    """
    out: dict[str, type] = {}
    for name in list_corpora(root=root):
        probes = list(iter_probes(name, root=root))
        out[name] = _build_probe_class(name, probes)
    return out


__all__ = ["GarakNotAvailable", "garak_probe_classes"]
