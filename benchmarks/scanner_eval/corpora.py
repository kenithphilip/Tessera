"""Multi-corpus loader for scanner evaluation.

Each corpus is a frozen dataclass holding a list of payload dicts. Corpora
are stored as JSONL files under benchmarks/scanner_eval/corpora/. Each line
must have the keys: text (str), label (int 0=clean/1=injection), category
(str), source (str).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

_CORPORA_DIR = Path(__file__).parent / "corpora"


@dataclass(frozen=True)
class Corpus:
    """A named collection of labeled text payloads.

    Attributes:
        name: Short identifier for the corpus (matches the JSONL filename stem).
        payloads: List of payload dicts, each containing: text, label,
            category, source.
    """

    name: str
    payloads: list[dict]


def load_corpus(name: str) -> Corpus:
    """Load a corpus from ``benchmarks/scanner_eval/corpora/{name}.jsonl``.

    Args:
        name: Corpus name (JSONL filename stem, e.g. "tessera_community_v1").

    Returns:
        Corpus with all payloads loaded.

    Raises:
        FileNotFoundError: If the JSONL file does not exist.
        ValueError: If any line is missing required keys.
    """
    path = _CORPORA_DIR / f"{name}.jsonl"
    if not path.exists():
        raise FileNotFoundError(f"Corpus not found: {path}")

    required = {"text", "label", "category", "source"}
    payloads: list[dict] = []
    for lineno, line in enumerate(path.read_text().splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        missing = required - record.keys()
        if missing:
            raise ValueError(
                f"Corpus {name!r} line {lineno} missing keys: {missing}"
            )
        payloads.append(record)

    return Corpus(name=name, payloads=payloads)


def load_lakera_gandalf() -> Corpus:
    """Load the Lakera Gandalf-style prompt-injection corpus.

    Returns:
        Corpus named "lakera_gandalf".
    """
    return load_corpus("lakera_gandalf")


def load_tensor_trust() -> Corpus:
    """Load the Tensor Trust adversarial prompt corpus.

    Returns:
        Corpus named "tensor_trust".
    """
    return load_corpus("tensor_trust")


def load_tessera_community_v1() -> Corpus:
    """Load the Tessera community v1 corpus (multi-category injections).

    Returns:
        Corpus named "tessera_community_v1".
    """
    return load_corpus("tessera_community_v1")
