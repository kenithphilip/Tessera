"""CLI implementation for ``tessera mcp mirror``.

Provides two subcommands:

- ``tessera mcp mirror sync``: fetch manifests from the upstream registry,
  re-sign each with the Tessera identity, package as OCI artifacts, and write
  a ``MirrorManifest`` summary.
- ``tessera mcp mirror status``: read back the ``MirrorManifest`` from a
  previous sync and print a human-readable summary.

These commands are wired into :mod:`tessera.cli` under the existing ``mcp``
subparser.

Example usage
-------------

Sync with HMAC signing (air-gapped / CI without Sigstore OIDC)::

    tessera mcp mirror sync \\
        --upstream https://registry.example.com \\
        --out ./mirror-output \\
        --sign hmac

Print the status of the last sync::

    tessera mcp mirror status --out ./mirror-output
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from tessera.mcp.registry_mirror import MirrorManifest, RegistryMirror


def run_mirror_sync(args) -> int:  # type: ignore[no-untyped-def]
    """Implement ``tessera mcp mirror sync``.

    Fetches, re-signs, packages, and writes the ``MirrorManifest``. Exit
    codes: 0 on success, 3 on transport error, 2 on configuration error.
    """
    sign_method = getattr(args, "sign", "hmac")
    upstream = args.upstream
    out_path = Path(args.out)

    hmac_key: bytes | None = None
    sigstore_identity: str | None = None

    if sign_method == "hmac":
        raw_key = os.environ.get("TESSERA_MIRROR_HMAC_KEY", "")
        if raw_key:
            try:
                hmac_key = bytes.fromhex(raw_key)
            except ValueError as exc:
                print(
                    f"TESSERA_MIRROR_HMAC_KEY is not valid hex: {exc}",
                    file=sys.stderr,
                )
                return 2
        else:
            # When no key is configured, RegistryMirror generates one
            # ephemerally. This is fine for local inspection but means
            # successive cron runs produce different signatures. Warn.
            print(
                "warning: TESSERA_MIRROR_HMAC_KEY not set; using ephemeral key. "
                "Set the env var for reproducible signatures.",
                file=sys.stderr,
            )
    elif sign_method == "sigstore":
        sigstore_identity = os.environ.get("TESSERA_MIRROR_SIGSTORE_TOKEN")
    else:
        print(f"unknown --sign value: {sign_method!r}", file=sys.stderr)
        return 2

    mirror = RegistryMirror(
        upstream_url=upstream,
        hmac_key=hmac_key,
        sigstore_identity=sigstore_identity,
        output_dir=out_path,
    )

    limit = int(getattr(args, "limit", 0) or 0)
    try:
        summary = mirror.mirror_all(limit=limit) if limit else mirror.mirror_all()
    except Exception as exc:  # noqa: BLE001
        print(f"mirror sync failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3

    print(
        f"mirrored {len(summary.entries)} manifest(s) -> {mirror.manifest_path()}"
    )
    return 0


def run_mirror_status(args) -> int:  # type: ignore[no-untyped-def]
    """Implement ``tessera mcp mirror status``.

    Reads the ``MirrorManifest`` from the output directory and prints a
    human-readable summary. Exit codes: 0 on success, 2 when the manifest
    file is missing or malformed.
    """
    out_path = Path(args.out)
    manifest_path = out_path / "mirror-manifest.json"
    if not manifest_path.exists():
        print(f"mirror-manifest.json not found in {out_path}", file=sys.stderr)
        return 2

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest = MirrorManifest.from_dict(data)
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"failed to parse mirror manifest: {exc}", file=sys.stderr)
        return 2

    print(f"schema:   {manifest.schema_version}")
    print(f"upstream: {manifest.upstream_registry_url}")
    print(f"signer:   {manifest.mirror_signing_identity}")
    print(f"generated: {manifest.generated_at}")
    print(f"entries:  {len(manifest.entries)}")
    for entry in manifest.entries:
        print(f"  {entry.mirror_tag}  {entry.server_uri}  ({entry.mirrored_at})")
    return 0


def register_mirror_subcommand(mcp_sub) -> None:  # type: ignore[no-untyped-def]
    """Attach the ``mirror`` subparser tree to the existing ``mcp`` subparsers.

    Called from :mod:`tessera.cli` during parser construction.
    """
    import argparse

    mirror_parser = mcp_sub.add_parser(
        "mirror",
        help="sync and inspect the Tessera-signed MCP registry mirror",
    )
    mirror_sub = mirror_parser.add_subparsers(dest="mirror_cmd", required=True)

    sync_parser = mirror_sub.add_parser(
        "sync",
        help=(
            "fetch manifests from the upstream registry, re-sign with the "
            "Tessera identity, and write the mirror OCI artifacts"
        ),
    )
    sync_parser.add_argument(
        "--upstream",
        required=True,
        help="base URL of the upstream MCP registry",
    )
    sync_parser.add_argument(
        "--out",
        default="mirror-output",
        help="output directory for envelopes, OCI layouts, and mirror-manifest.json",
    )
    sync_parser.add_argument(
        "--sign",
        choices=("hmac", "sigstore"),
        default="hmac",
        help=(
            "signing method: hmac for air-gapped / test runs "
            "(reads TESSERA_MIRROR_HMAC_KEY), "
            "sigstore for production (reads TESSERA_MIRROR_SIGSTORE_TOKEN)"
        ),
    )
    sync_parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help=(
            "process at most this many upstream manifests (0 = no cap). "
            "The official MCP registry has ~20k entries; full Sigstore "
            "signing + OCI push of every manifest does not fit in a "
            "20-minute CI cron, so production cron runs typically pass "
            "--limit 50 and rotate which subset is processed each night."
        ),
    )

    status_parser = mirror_sub.add_parser(
        "status",
        help="read and print the MirrorManifest from a previous sync run",
    )
    status_parser.add_argument(
        "--out",
        default="mirror-output",
        help="output directory containing mirror-manifest.json",
    )


def dispatch(args) -> int:  # type: ignore[no-untyped-def]
    """Route a parsed ``mirror`` Namespace to the correct handler."""
    if args.mirror_cmd == "sync":
        return run_mirror_sync(args)
    if args.mirror_cmd == "status":
        return run_mirror_status(args)
    print(f"unknown mirror subcommand: {args.mirror_cmd!r}", file=sys.stderr)
    return 2


__all__ = [
    "dispatch",
    "register_mirror_subcommand",
    "run_mirror_status",
    "run_mirror_sync",
]
