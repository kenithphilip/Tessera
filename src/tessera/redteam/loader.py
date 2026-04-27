"""Probe corpus loader.

Reads JSONL probe files and validates each entry against
``corpus/schema/probe_v1.json`` (also bundled at
``src/tessera/redteam/probe_v1.schema.json`` in case the wheel
ships without the top-level ``corpus/`` directory).

Resolution order for the corpus root, from highest precedence:

1. The explicit ``root`` argument to ``load_corpus`` /
   ``list_corpora``.
2. The ``TESSERA_REDTEAM_CORPUS_ROOT`` environment variable.
3. The package-data path
   (``src/tessera/redteam/data/probes/``) when one is shipped.
4. The repo-root ``corpus/probes/`` directory (development).

A ``ProbeValidationError`` is raised for any malformed entry; the
error message names the file and the offending field so an auditor
can see exactly which line failed.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator


_VALID_CATEGORIES = {
    "prompt_injection",
    "exfil",
    "jailbreak",
    "tool_description_injection",
    "url_manipulation",
}
_VALID_OUTCOMES = {"refuse", "block", "sanitize"}


class ProbeValidationError(ValueError):
    """Raised when a probe entry violates the v1 schema."""


@dataclass(frozen=True)
class Probe:
    """One red-team probe entry. Mirrors ``probe_v1.json``."""

    probe_id: str
    category: str
    payload: str
    expected_outcome: str
    source: str
    license: str
    submitted_at: str

    @property
    def expects_detection(self) -> bool:
        """Whether a correct defense should flag this probe.

        All current outcomes (``refuse`` / ``block`` / ``sanitize``)
        require some form of scanner action; only a hypothetical
        ``allow`` outcome would not. Kept as a property so future
        outcome additions can override.
        """
        return self.expected_outcome in _VALID_OUTCOMES


def _validate(entry: dict[str, Any], *, source_path: Path, line_no: int) -> Probe:
    required = ("probe_id", "category", "payload", "expected_outcome",
                "source", "license", "submitted_at")
    missing = [k for k in required if k not in entry]
    if missing:
        raise ProbeValidationError(
            f"{source_path.name}:{line_no} missing required fields: {missing}"
        )
    if entry["category"] not in _VALID_CATEGORIES:
        raise ProbeValidationError(
            f"{source_path.name}:{line_no} invalid category "
            f"{entry['category']!r}; allowed: {sorted(_VALID_CATEGORIES)}"
        )
    if entry["expected_outcome"] not in _VALID_OUTCOMES:
        raise ProbeValidationError(
            f"{source_path.name}:{line_no} invalid expected_outcome "
            f"{entry['expected_outcome']!r}; allowed: {sorted(_VALID_OUTCOMES)}"
        )
    if not isinstance(entry["payload"], str) or not entry["payload"]:
        raise ProbeValidationError(
            f"{source_path.name}:{line_no} payload must be a non-empty string"
        )
    return Probe(
        probe_id=str(entry["probe_id"]),
        category=str(entry["category"]),
        payload=str(entry["payload"]),
        expected_outcome=str(entry["expected_outcome"]),
        source=str(entry["source"]),
        license=str(entry["license"]),
        submitted_at=str(entry["submitted_at"]),
    )


def resolve_corpus_root(root: Path | str | None = None) -> Path:
    """Return the corpus root directory.

    Resolution order documented in the module docstring. Raises
    ``FileNotFoundError`` if no candidate exists (with a clear
    message naming each tried path).
    """
    candidates: list[Path] = []

    if root is not None:
        candidates.append(Path(root).expanduser().resolve())

    env = os.environ.get("TESSERA_REDTEAM_CORPUS_ROOT", "").strip()
    if env:
        candidates.append(Path(env).expanduser().resolve())

    here = Path(__file__).resolve()
    candidates.append(here.parent / "data" / "probes")
    candidates.append(here.parents[3] / "corpus" / "probes")

    for path in candidates:
        if path.is_dir():
            return path

    raise FileNotFoundError(
        "no probe corpus found. Tried: "
        + ", ".join(str(p) for p in candidates)
        + ". Set TESSERA_REDTEAM_CORPUS_ROOT or pass root=... explicitly."
    )


def list_corpora(*, root: Path | str | None = None) -> list[str]:
    """Return the sorted list of corpus names available under ``root``.

    A corpus name is the basename of a ``*.jsonl`` file with the
    ``.jsonl`` suffix stripped. The ``MANIFEST.md`` file is ignored.
    """
    corpus_root = resolve_corpus_root(root)
    return sorted(p.stem for p in corpus_root.glob("*.jsonl"))


def iter_probes(
    name: str | None = None,
    *,
    root: Path | str | None = None,
) -> Iterator[Probe]:
    """Yield Probe objects from one (or every) corpus file.

    Args:
        name: Corpus basename (e.g. ``tensor_trust``). When None,
            yields probes from EVERY corpus file under ``root``,
            in name-sorted order.
        root: Override the corpus root directory.

    Yields:
        Validated Probe instances. Skips empty lines.

    Raises:
        ProbeValidationError: On any malformed entry.
        FileNotFoundError: If ``name`` is given and the matching
            file does not exist.
    """
    corpus_root = resolve_corpus_root(root)
    if name is None:
        files: Iterable[Path] = sorted(corpus_root.glob("*.jsonl"))
    else:
        path = corpus_root / f"{name}.jsonl"
        if not path.exists():
            available = ", ".join(p.stem for p in sorted(corpus_root.glob("*.jsonl")))
            raise FileNotFoundError(
                f"corpus {name!r} not found at {path}. Available: {available}"
            )
        files = [path]

    for path in files:
        with path.open(encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ProbeValidationError(
                        f"{path.name}:{line_no} invalid JSON: {exc.msg}"
                    ) from exc
                yield _validate(entry, source_path=path, line_no=line_no)


def load_corpus(
    name: str | None = None,
    *,
    root: Path | str | None = None,
) -> list[Probe]:
    """Eager wrapper around :func:`iter_probes`. Returns a list."""
    return list(iter_probes(name, root=root))
