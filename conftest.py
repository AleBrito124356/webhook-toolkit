"""Pytest bootstrap shared by every test.

* Puts the repository root on ``sys.path`` so ``import src.webhooks...`` works
  without installing the package.
* Isolates each test from the developer's machine: provider secrets and
  ``WEBHOOK_*`` settings are removed from the environment, the working
  directory is a fresh temp dir (so a real ``./.env`` is never picked up), and
  ``os.environ`` is restored afterwards (the ``.env`` loader writes to it).
"""

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

_ISOLATED_PREFIXES = ("WEBHOOK_", "GENERIC_WEBHOOK_")
_ISOLATED_NAMES = {
    "GITHUB_WEBHOOK_SECRET",
    "STRIPE_WEBHOOK_SECRET",
    "SLACK_SIGNING_SECRET",
    "SHOPIFY_WEBHOOK_SECRET",
    "STRIPE_TIMESTAMP_TOLERANCE",
}


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    saved = dict(os.environ)
    for name in list(os.environ):
        if name in _ISOLATED_NAMES or name.startswith(_ISOLATED_PREFIXES):
            del os.environ[name]
    monkeypatch.chdir(tmp_path)
    yield
    os.environ.clear()
    os.environ.update(saved)
