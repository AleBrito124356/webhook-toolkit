"""Pytest bootstrap: put the repository root on ``sys.path``.

This lets the tests ``import src.webhooks...`` regardless of where pytest is
invoked from, without installing the package.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
