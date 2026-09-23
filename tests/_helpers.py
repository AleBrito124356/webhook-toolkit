"""Shared helpers for the test-suite (not collected: no ``test_`` prefix)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HANDLERS = REPO_ROOT / "examples" / "handlers"


def load_handler(name: str, secret: str | None = None):
    """Import ``examples/handlers/<name>.py`` fresh, optionally forcing its secret."""
    path = HANDLERS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_example_{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if secret is not None:
        module.SECRET = secret
    return module
