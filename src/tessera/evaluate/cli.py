"""Command-line interface for the Tessera evaluation toolchain.

Entry point: ``tessera bench emit-scorecard``

Usage::

    tessera bench emit-scorecard \\
        --version 0.12.0 \\
        --out /tmp/release.intoto.jsonl \\
        --sign hmac \\
        [--audit-log /path/to/audit.jsonl] \\
        [--scanner-report /path/to/scanner.json] \\
        [--benchmark-run /path/to/agentdojo.json] ...

All source inputs are optional. Missing files produce empty sections rather
than errors so partial attestations can be emitted early in a CI pipeline.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tessera bench",
        description="Tessera evaluation and attestation toolchain.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    emit = sub.add_parser(
        "emit-scorecard",
        help="Build and optionally sign a Tessera Security Attestation.",
        description=(
            "Emit a Tessera Security Attestation (in-toto Statement v1) "
            "from local benchmark runs, a scanner report, and an audit log. "
            "The output is a JSON-lines file suitable for submission to "
            "Sigstore Rekor or distribution alongside a release."
        ),
    )
    emit.add_argument(
        "--version",
        default="0.0.0",
        help="SemVer of the Tessera release being attested (default: 0.0.0).",
    )
    emit.add_argument(
        "--out",
        required=True,
        help="Output path for the JSON-lines attestation file.",
    )
    emit.add_argument(
        "--sign",
        choices=["none", "hmac", "sigstore"],
        default="none",
        help=(
            "Signing method. 'none' writes the attestation without signing. "
            "'hmac' signs with HMAC-SHA256 (key from TESSERA_SCORECARD_HMAC_KEY "
            "env var, or a dev fallback). 'sigstore' requires the sigstore "
            "Python package."
        ),
    )
    emit.add_argument(
        "--audit-log",
        default=None,
        help="Path to a JSONL hash-chained audit log.",
    )
    emit.add_argument(
        "--scanner-report",
        default=None,
        help="Path to a JSON scanner evaluation report.",
    )
    emit.add_argument(
        "--benchmark-run",
        action="append",
        default=[],
        dest="benchmark_runs",
        metavar="PATH",
        help=(
            "Path to a benchmark run JSON file. "
            "May be repeated for multiple suites."
        ),
    )
    emit.add_argument(
        "--principles-revision",
        type=int,
        default=1,
        help="Integer revision of the principles/v1.yaml document (default: 1).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``tessera bench`` CLI.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).

    Returns:
        Exit code: 0 on success, non-zero on error.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "emit-scorecard":
        from tessera.evaluate.scorecard.emitter import ScorecardEmitter
        from tessera.evaluate.scorecard.sign import SigningMethodUnavailable, sign

        emitter = ScorecardEmitter(
            version=args.version,
            audit_log_path=Path(args.audit_log) if args.audit_log else None,
            scanner_report_path=(
                Path(args.scanner_report) if args.scanner_report else None
            ),
            benchmark_runs=[Path(p) for p in args.benchmark_runs],
            principles_revision=args.principles_revision,
        )

        out_path = emitter.emit(Path(args.out))
        print(f"attestation written: {out_path}")

        if args.sign != "none":
            try:
                envelope = sign(out_path, signing_method=args.sign)
                print(f"envelope written:    {envelope}")
            except SigningMethodUnavailable as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1

        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
