"""``python -m tessera.redteam`` entry point."""

from __future__ import annotations

import sys

from tessera.redteam.cli import main

if __name__ == "__main__":
    sys.exit(main())
