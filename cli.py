#!/usr/bin/env python
"""Run the webhook-toolkit CLI from a source checkout: ``python cli.py <command>``.

The CLI lives in ``src/webhooks/cli.py``; ``pip install`` exposes the same
commands as ``webhook-toolkit <command>``.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from webhooks.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
