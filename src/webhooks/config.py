"""Configuration and secret loading.

All secrets come from environment variables. Values are treated as placeholders
(and therefore ignored for verification) when they still contain the literal
``XXXX`` from ``.env.example`` or an obvious dummy string. This keeps the tool
from reporting confident ``verified: false`` results just because you have not
filled in a real signing secret yet.
"""

from __future__ import annotations

import os

# --- Server defaults --------------------------------------------------------
DEFAULT_DB = os.environ.get("WEBHOOK_DB", "webhooks.db")
DEFAULT_HOST = os.environ.get("WEBHOOK_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("WEBHOOK_PORT", "8000"))

# Stripe / Slack tolerate a small clock skew between sender and receiver.
DEFAULT_TOLERANCE = int(os.environ.get("WEBHOOK_TIMESTAMP_TOLERANCE", "300"))

# --- Provider -> environment variable holding its signing secret ------------
SECRET_ENV = {
    "github": "GITHUB_WEBHOOK_SECRET",
    "stripe": "STRIPE_WEBHOOK_SECRET",
    "slack": "SLACK_SIGNING_SECRET",
    "shopify": "SHOPIFY_WEBHOOK_SECRET",
}

# Obvious dummy values that should never be used as a real secret. Includes the
# non-``X``-run placeholder shipped in ``.env.example`` (the GitHub secret is a
# free-form string, so it has no provider checksum to fail).
_DUMMY = {
    "changeme",
    "change-me",
    "your-secret-here",
    "replace-me",
    "use-a-long-random-string-here",
    "",
}


def is_placeholder(value: str | None) -> bool:
    """Return True when ``value`` is empty or an obvious placeholder.

    Placeholders from ``.env.example`` contain literal ``X`` runs (e.g.
    ``whsec_XXXXXXXX``) which never pass a provider checksum, so we skip
    verification rather than emit a misleading failure.
    """
    if value is None:
        return True
    stripped = value.strip()
    if stripped.lower() in _DUMMY:
        return True
    return "xxxx" in stripped.lower()


def get_secret(provider: str) -> str | None:
    """Return the configured signing secret for ``provider`` or ``None``.

    Placeholder values resolve to ``None`` so callers can distinguish
    "no secret configured" from "wrong secret".
    """
    env_name = SECRET_ENV.get(provider)
    if not env_name:
        return None
    value = os.environ.get(env_name)
    if is_placeholder(value):
        return None
    return value


def all_secrets() -> dict[str, str | None]:
    """Return a ``{provider: secret_or_None}`` map for every known provider."""
    return {provider: get_secret(provider) for provider in SECRET_ENV}
