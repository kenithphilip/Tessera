"""AgentMesh CLI entry point.

Usage:
    python -m agentmesh init      # Generate agentmesh.yaml in cwd
    python -m agentmesh check     # Validate config and print policy summary
    python -m agentmesh version   # Print version
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_VERSION = "0.0.1"

_DEFAULT_YAML = """\
# AgentMesh configuration
# See https://github.com/kenithphilip/Tessera for documentation.

# HMAC signing key. Use "auto" for development (generates a random key
# each run). For production, set hmac_key_env to an environment variable
# name that holds a stable key of at least 8 bytes.
hmac_key: "auto"
# hmac_key_env: "AGENTMESH_HMAC_KEY"

# Default minimum trust level required for any tool not listed below.
# Options: untrusted, tool, user, system
default_required_trust: user

# Per-tool trust requirements. Tools listed here override the default.
tool_policies:
  # - name: send_email
  #   required_trust: user
  # - name: web_search
  #   required_trust: tool

# Optional spend cap in USD. Omit or set to null for unlimited.
# budget_usd: 10.00

# Enable OpenTelemetry span export for policy decisions.
# otel_enabled: false
"""


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to the appropriate subcommand."""
    parser = argparse.ArgumentParser(
        prog="agentmesh",
        description="AgentMesh SDK command-line interface.",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="Generate a default agentmesh.yaml in the current directory.")
    sub.add_parser("check", help="Validate agentmesh.yaml and print policy summary.")
    sub.add_parser("version", help="Print the AgentMesh SDK version.")

    args = parser.parse_args(argv)

    if args.command == "init":
        return _cmd_init()
    if args.command == "check":
        return _cmd_check()
    if args.command == "version":
        return _cmd_version()

    parser.print_help()
    return 1


def _cmd_init() -> int:
    """Write a default agentmesh.yaml to the current directory."""
    target = Path.cwd() / "agentmesh.yaml"
    if target.exists():
        print(f"agentmesh.yaml already exists at {target}", file=sys.stderr)
        return 1
    target.write_text(_DEFAULT_YAML, encoding="utf-8")
    print(f"Created {target}")
    return 0


def _cmd_check() -> int:
    """Load and validate agentmesh.yaml, then print a summary."""
    target = Path.cwd() / "agentmesh.yaml"
    if not target.is_file():
        print("No agentmesh.yaml found in current directory.", file=sys.stderr)
        print("Run 'python -m agentmesh init' to create one.", file=sys.stderr)
        return 1

    try:
        from agentmesh.config import AgentMeshConfig
        cfg = AgentMeshConfig.from_yaml_path(target)
    except Exception as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    print(f"Config loaded from {target}")
    print(f"Default required trust: {cfg.default_required_trust.name}")
    print(f"OTEL enabled: {cfg.otel_enabled}")
    if cfg.budget_usd is not None:
        print(f"Budget cap: ${cfg.budget_usd:.2f}")
    else:
        print("Budget cap: unlimited")

    if cfg.tool_policies:
        print(f"\nTool policies ({len(cfg.tool_policies)}):")
        for tp in cfg.tool_policies:
            print(f"  {tp.name}: {tp.required_trust.name}")
    else:
        print("\nNo per-tool policies configured.")

    return 0


def _cmd_version() -> int:
    """Print the version and exit."""
    print(f"agentmesh {_VERSION}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
