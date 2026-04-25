"""Allow `python -m tessera ...` to invoke the CLI.

Without this, `python -m tessera.cli mcp mirror sync ...` would just
import the module and exit with code 0 silently because `cli.py` has
no `if __name__ == "__main__"` guard. The CI registry-mirror workflow
(Wave 4D) ran into this exact silent no-op.
"""

from __future__ import annotations

import sys

from tessera.cli import main


if __name__ == "__main__":
    sys.exit(main() or 0)
