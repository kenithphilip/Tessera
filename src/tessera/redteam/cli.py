"""``python -m tessera.redteam`` CLI.

Subcommands:

- ``list``: print the available corpora.
- ``show <corpus>``: print the first few entries of a corpus
  (audit-friendly verification).
- ``run --corpus <name> --scanner <dotted.path>``: run every
  probe in the corpus through the scorer and emit a JSON report.
- ``reproduce --attestation <path>``: rebuild the
  ``benchmarks.scanner_eval`` block of an existing in-toto
  attestation by re-running the same scanner over the same
  corpus, then print a delta report against the recorded numbers.

Designed for external auditors: every command exits 0 on success
and 2 on configuration errors so a CI runner can gate on exit
codes alone.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from itertools import islice
from pathlib import Path
from typing import Any

from tessera.redteam.loader import (
    list_corpora,
    iter_probes,
    resolve_corpus_root,
)
from tessera.redteam.runner import (
    AggregatedReport,
    aggregate,
    resolve_scorer,
    run,
)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def _cmd_list(args: argparse.Namespace) -> int:
    root = resolve_corpus_root(args.root)
    corpora = list_corpora(root=args.root)
    print(f"corpus root: {root}")
    print(f"{len(corpora)} corpora available:")
    for name in corpora:
        path = root / f"{name}.jsonl"
        line_count = sum(1 for _ in path.open(encoding="utf-8"))
        print(f"  {name:30s} ({line_count} probes)")
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    probes = list(islice(iter_probes(args.corpus, root=args.root), args.head))
    print(f"first {len(probes)} probes from {args.corpus}:")
    for probe in probes:
        # Truncate payload for terminal-friendly output.
        body = probe.payload[: args.payload_max] + (
            "..." if len(probe.payload) > args.payload_max else ""
        )
        print(
            f"  [{probe.probe_id[:12]}] {probe.category:25s} "
            f"-> {probe.expected_outcome:8s}  {body!r}"
        )
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        scorer = resolve_scorer(args.scanner)
    except (ImportError, ValueError) as exc:
        print(f"error resolving scanner {args.scanner!r}: {exc}", file=sys.stderr)
        return 2

    probes = list(iter_probes(args.corpus, root=args.root))
    # Status line goes to stderr so stdout stays pure JSON for piping.
    print(
        f"running {len(probes)} probes through {args.scanner} "
        f"(threshold={args.threshold})",
        file=sys.stderr,
    )
    started = time.perf_counter()
    results = run(probes, scorer=scorer, threshold=args.threshold)
    elapsed = time.perf_counter() - started
    report = aggregate(
        results,
        scanner_name=args.scanner,
        threshold=args.threshold,
        elapsed_seconds=elapsed,
    )

    payload = report.to_dict()
    payload["corpus"] = args.corpus or "all"

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {out_path}")
    else:
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")

    print(_summary_line(report), file=sys.stderr)
    return 0


def _cmd_reproduce(args: argparse.Namespace) -> int:
    try:
        attestation = _load_attestation(Path(args.attestation))
    except (FileNotFoundError, ValueError) as exc:
        print(f"error loading attestation: {exc}", file=sys.stderr)
        return 2

    benchmarks = (
        attestation.get("predicate", {}).get("benchmarks", {}).get("scanner_eval", {})
    )
    if not benchmarks:
        print(
            "warning: attestation has no scanner_eval benchmarks block; "
            "the delta report will compare against zero.",
            file=sys.stderr,
        )

    try:
        scorer = resolve_scorer(args.scanner)
    except (ImportError, ValueError) as exc:
        print(f"error resolving scanner {args.scanner!r}: {exc}", file=sys.stderr)
        return 2

    probes = list(iter_probes(args.corpus, root=args.root))
    started = time.perf_counter()
    results = run(probes, scorer=scorer, threshold=args.threshold)
    elapsed = time.perf_counter() - started
    report = aggregate(
        results,
        scanner_name=args.scanner,
        threshold=args.threshold,
        elapsed_seconds=elapsed,
    )

    delta = {
        "attestation_path": str(args.attestation),
        "attestation_id": attestation.get("predicate", {}).get("attestation_id"),
        "tessera_version": attestation.get("predicate", {}).get("tessera_version"),
        "recorded": {
            "precision": benchmarks.get("precision"),
            "recall": benchmarks.get("recall"),
            "f1": benchmarks.get("f1"),
        },
        "reproduced": {
            "precision": round(report.precision, 4),
            "recall": round(report.recall, 4),
            "f1": round(report.f1, 4),
        },
        "delta": _delta_block(benchmarks, report),
    }

    json.dump(delta, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _summary_line(report: AggregatedReport) -> str:
    return (
        f"{report.scanner_name}  "
        f"P={report.precision:.3f}  R={report.recall:.3f}  "
        f"F1={report.f1:.3f}  total={report.total}  "
        f"errors={report.errors}  elapsed={report.elapsed_seconds:.2f}s"
    )


def _load_attestation(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"{path}: empty file")
    # in-toto Statement v1 ships as JSONL with one statement per
    # line; for the v1.0 release we only emit one line.
    first = text.splitlines()[0]
    return json.loads(first)


def _delta_block(
    recorded: dict[str, Any], reproduced: AggregatedReport
) -> dict[str, Any]:
    block: dict[str, Any] = {}
    for key in ("precision", "recall", "f1"):
        before = recorded.get(key)
        after = round(getattr(reproduced, key), 4)
        if before is None or not isinstance(before, (int, float)):
            block[key] = {"before": None, "after": after, "diff": None}
            continue
        block[key] = {
            "before": round(float(before), 4),
            "after": after,
            "diff": round(after - float(before), 4),
        }
    return block


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tessera.redteam",
        description="Tessera community red-team corpus runner",
    )
    parser.add_argument(
        "--root",
        type=str,
        default=None,
        help="Override the corpus root directory.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="list available corpora")
    p_list.set_defaults(handler=_cmd_list)

    p_show = sub.add_parser("show", help="print head of a corpus")
    p_show.add_argument("corpus", help="corpus name (e.g. tensor_trust)")
    p_show.add_argument("--head", type=int, default=3)
    p_show.add_argument("--payload-max", type=int, default=80)
    p_show.set_defaults(handler=_cmd_show)

    p_run = sub.add_parser("run", help="run a corpus through a scorer")
    p_run.add_argument("--corpus", default=None,
                       help="corpus name; omit to run every corpus")
    p_run.add_argument(
        "--scanner",
        default="tessera.scanners.heuristic.injection_score",
        help="dotted import path of a scorer callable",
    )
    p_run.add_argument("--threshold", type=float, default=0.5)
    p_run.add_argument("--output", default=None,
                       help="write JSON report to this file (else stdout)")
    p_run.set_defaults(handler=_cmd_run)

    p_repro = sub.add_parser(
        "reproduce",
        help="re-run a scorer against the corpus an attestation references "
             "and print a delta report",
    )
    p_repro.add_argument("--attestation", required=True,
                         help="path to a .intoto.jsonl attestation file")
    p_repro.add_argument("--corpus", default=None,
                         help="corpus name; omit to use every corpus")
    p_repro.add_argument(
        "--scanner",
        default="tessera.scanners.heuristic.injection_score",
        help="dotted import path of a scorer callable",
    )
    p_repro.add_argument("--threshold", type=float, default=0.5)
    p_repro.set_defaults(handler=_cmd_reproduce)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))
