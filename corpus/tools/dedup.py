"""Minhash deduplication for red-team probe corpora.

Reads one or more JSONL probe files, computes a 128-permutation minhash
signature with a 5-character shingle over each payload, and identifies
near-duplicates using Jaccard similarity >= 0.85.

Uses datasketch when available; falls back to a hash-of-shingles
approach that approximates the same threshold without the dependency.

Usage:
    python dedup.py probes/*.jsonl [--dry-run] [--out deduped.jsonl]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


_SHINGLE_SIZE = 5
_NUM_PERMS = 128
_JACCARD_THRESHOLD = 0.85


def _shingles(text: str, k: int = _SHINGLE_SIZE) -> set[str]:
    """Return the set of k-character shingles from text."""
    return {text[i : i + k] for i in range(max(1, len(text) - k + 1))}


def _hash_shingle(shingle: str, seed: int) -> int:
    """Hash a shingle with a seed to produce a 32-bit integer."""
    raw = hashlib.md5((str(seed) + shingle).encode()).digest()
    return struct.unpack("<I", raw[:4])[0]


def _minhash_signature_fallback(text: str) -> list[int]:
    """Compute a 128-permutation minhash signature without datasketch."""
    shs = _shingles(text)
    if not shs:
        return [0] * _NUM_PERMS
    return [min(_hash_shingle(s, seed) for s in shs) for seed in range(_NUM_PERMS)]


def _jaccard_estimate(sig_a: list[int], sig_b: list[int]) -> float:
    """Estimate Jaccard similarity from two minhash signatures."""
    matches = sum(a == b for a, b in zip(sig_a, sig_b))
    return matches / len(sig_a)


def _compute_signatures(
    probes: list[dict],
) -> list[tuple[dict, list[int]]]:
    """Return (probe, signature) pairs, using datasketch when available."""
    try:
        from datasketch import MinHash  # type: ignore[import-untyped]

        results: list[tuple[dict, list[int]]] = []
        for probe in probes:
            mh = MinHash(num_perm=_NUM_PERMS)
            for sh in _shingles(probe["payload"]):
                mh.update(sh.encode())
            results.append((probe, list(mh.hashvalues)))
        return results
    except ImportError:
        return [(p, _minhash_signature_fallback(p["payload"])) for p in probes]


def load_probes(paths: list[Path]) -> list[dict]:
    """Load and parse all probe records from a list of JSONL paths.

    Args:
        paths: JSONL files to load.

    Returns:
        List of parsed probe dicts with a ``_source_file`` key injected.

    Raises:
        ValueError: If a line is not valid JSON.
    """
    probes: list[dict] = []
    for path in paths:
        for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                record = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            record["_source_file"] = str(path)
            probes.append(record)
    return probes


def find_duplicates(
    probes: list[dict],
    threshold: float = _JACCARD_THRESHOLD,
) -> list[tuple[str, str, float]]:
    """Find near-duplicate probe pairs by minhash Jaccard estimate.

    Args:
        probes: Parsed probe records (must have a ``payload`` field).
        threshold: Jaccard similarity above which two probes are duplicates.

    Returns:
        List of (probe_id_a, probe_id_b, similarity) tuples.
    """
    signed = _compute_signatures(probes)
    duplicates: list[tuple[str, str, float]] = []
    for i, (probe_a, sig_a) in enumerate(signed):
        for probe_b, sig_b in signed[i + 1 :]:
            sim = _jaccard_estimate(sig_a, sig_b)
            if sim >= threshold:
                duplicates.append((probe_a["probe_id"], probe_b["probe_id"], sim))
    return duplicates


def deduplicate(
    probes: list[dict],
    threshold: float = _JACCARD_THRESHOLD,
) -> tuple[list[dict], list[tuple[str, str, float]]]:
    """Remove near-duplicates, keeping the first occurrence of each cluster.

    Args:
        probes: All probe records.
        threshold: Jaccard similarity threshold.

    Returns:
        (kept, duplicates) where duplicates are (id_a, id_b, sim) triples.
    """
    signed = _compute_signatures(probes)
    removed: set[str] = set()
    duplicates: list[tuple[str, str, float]] = []

    for i, (probe_a, sig_a) in enumerate(signed):
        if probe_a["probe_id"] in removed:
            continue
        for probe_b, sig_b in signed[i + 1 :]:
            if probe_b["probe_id"] in removed:
                continue
            sim = _jaccard_estimate(sig_a, sig_b)
            if sim >= threshold:
                removed.add(probe_b["probe_id"])
                duplicates.append((probe_a["probe_id"], probe_b["probe_id"], sim))

    kept = [p for p in probes if p["probe_id"] not in removed]
    return kept, duplicates


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Minhash dedup for red-team probe JSONL files."
    )
    parser.add_argument("inputs", nargs="+", type=Path, help="JSONL input files.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report duplicates without writing output.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output JSONL path. Defaults to stdout.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=_JACCARD_THRESHOLD,
        help=f"Jaccard threshold (default {_JACCARD_THRESHOLD}).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point for the dedup CLI.

    Returns:
        0 on success, 1 if duplicates were found (useful for CI).
    """
    args = _parse_args(argv)

    try:
        probes = load_probes(args.inputs)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Loaded {len(probes)} probes from {len(args.inputs)} file(s).")

    kept, duplicates = deduplicate(probes, threshold=args.threshold)

    if duplicates:
        print(f"Found {len(duplicates)} near-duplicate pair(s):")
        for id_a, id_b, sim in duplicates:
            print(f"  {id_a} ~ {id_b}  (Jaccard={sim:.3f})")
    else:
        print("No near-duplicates found.")

    print(f"Kept {len(kept)} probes after dedup (removed {len(duplicates)} extra).")

    if args.dry_run:
        return 1 if duplicates else 0

    # Strip the injected metadata key before writing.
    clean = [{k: v for k, v in p.items() if k != "_source_file"} for p in kept]

    if args.out:
        args.out.write_text("\n".join(json.dumps(r) for r in clean) + "\n")
        print(f"Wrote {len(clean)} probes to {args.out}.")
    else:
        for record in clean:
            print(json.dumps(record))

    return 1 if duplicates else 0


if __name__ == "__main__":
    sys.exit(main())
