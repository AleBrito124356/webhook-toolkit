"""Configuration, ``.env`` loading and secret resolution.

Secrets come from environment variables. A ``.env`` file (the one you create
from ``.env.example``) is loaded by the CLI before any command runs; values that
are already set in the real process environment always win over the file.

A secret can be in one of three states, and the toolkit treats them
differently:

``unset``
    The variable is missing or empty. Nothing can be verified or signed.
``placeholder``
    The variable still holds a value shipped in ``.env.example`` (an ``X`` run
    or an obvious dummy string). The passive receiver never reports such a
    capture as *invalid* (a real provider never signs with a placeholder), but
    explicit commands (``verify``, ``replay --sign``) still use the value, with
    a warning, because the bundled example handlers accept it for local demos.
``set``
    A real-looking value. Used everywhere.

Server settings (``WEBHOOK_DB`` and friends) are read *live* through module
attributes, so a ``.env`` loaded at startup is honoured even though this
module was imported earlier.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .verify import GenericScheme

# --- Provider -> environment variable holding its signing secret ------------
SECRET_ENV = {
    "github": "GITHUB_WEBHOOK_SECRET",
    "stripe": "STRIPE_WEBHOOK_SECRET",
    "slack": "SLACK_SIGNING_SECRET",
    "shopify": "SHOPIFY_WEBHOOK_SECRET",
    "generic": "GENERIC_WEBHOOK_SECRET",
}

# The generic HMAC provider is described by these variables. It only takes
# part in header-based detection once GENERIC_WEBHOOK_HEADER is set.
GENERIC_ENV = {
    "signature_header": "GENERIC_WEBHOOK_HEADER",
    "algorithm": "GENERIC_WEBHOOK_ALGORITHM",
    "encoding": "GENERIC_WEBHOOK_ENCODING",
    "prefix": "GENERIC_WEBHOOK_PREFIX",
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
}

_LIVE_SETTINGS = {
    "DEFAULT_DB": ("WEBHOOK_DB", "webhooks.db", str),
    "DEFAULT_HOST": ("WEBHOOK_HOST", "127.0.0.1", str),
    "DEFAULT_PORT": ("WEBHOOK_PORT", "8000", int),
    "DEFAULT_TOLERANCE": ("WEBHOOK_TIMESTAMP_TOLERANCE", "300", int),
}


def __getattr__(name: str):
    """Resolve ``DEFAULT_*`` settings from the environment at access time."""
    if name in _LIVE_SETTINGS:
        env_name, default, cast = _LIVE_SETTINGS[name]
        raw = os.environ.get(env_name) or default
        try:
            return cast(raw)
        except ValueError as exc:
            raise ValueError(f"{env_name}={raw!r} is not a valid {cast.__name__}") from exc
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ---------------------------------------------------------------------------
# .env loading (no python-dotenv dependency)
# ---------------------------------------------------------------------------
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")
_DOUBLE_QUOTE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}


def _unquote(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    quote = value[0]
    if quote in ("'", '"'):
        end = value.find(quote, 1)
        while quote == '"' and end > 0 and value[end - 1] == "\\":
            end = value.find(quote, end + 1)
        inner = value[1:end] if end > 0 else value[1:]
        if quote == '"':
            inner = re.sub(
                r"\\(.)",
                lambda m: _DOUBLE_QUOTE_ESCAPES.get(m.group(1), "\\" + m.group(1)),
                inner,
            )
        return inner
    # Unquoted: an inline comment starts at whitespace followed by "#".
    comment = re.search(r"\s#", value)
    if comment:
        value = value[: comment.start()]
    return value.strip()


def parse_env_file(text: str) -> dict[str, str]:
    """Parse ``.env`` text into a dict.

    Supports ``KEY=value``, ``export KEY=value``, blank lines, ``#`` comments,
    inline comments after unquoted values, and single/double quoted values
    (double quotes understand ``\\n``, ``\\t``, ``\\"`` and ``\\\\``).
    """
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if match:
            values[match.group(1)] = _unquote(match.group(2))
    return values


def load_env_file(path: str | Path | None = None, *, override: bool = False) -> dict[str, str]:
    """Load ``path`` (default: ``./.env`` when it exists) into ``os.environ``.

    Variables that already exist in the process environment are kept unless
    ``override`` is true. Returns the variables that were actually applied.
    An explicit ``path`` that does not exist raises ``FileNotFoundError``; the
    implicit ``./.env`` is optional.
    """
    if path is None:
        candidate = Path.cwd() / ".env"
        if not candidate.is_file():
            return {}
    else:
        candidate = Path(path)
        if not candidate.is_file():
            raise FileNotFoundError(f"env file not found: {candidate}")
    applied: dict[str, str] = {}
    for key, value in parse_env_file(candidate.read_text(encoding="utf-8-sig")).items():
        if override or key not in os.environ:
            os.environ[key] = value
            applied[key] = value
    return applied


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
def is_placeholder(value: str | None) -> bool:
    """Return True when ``value`` is empty or an obvious placeholder.

    Placeholders from ``.env.example`` contain literal ``X`` runs (e.g.
    ``whsec_XXXXXXXX``) or are a well-known dummy phrase.
    """
    if value is None:
        return True
    stripped = value.strip()
    if not stripped or stripped.lower() in _DUMMY:
        return True
    return "xxxx" in stripped.lower()


@dataclass(frozen=True)
class SecretStatus:
    """Where a provider's secret stands. ``repr`` never shows the value."""

    provider: str
    env_var: str | None
    state: str  # "set" | "placeholder" | "unset" | "unknown-provider"
    value: str | None = None

    def __repr__(self) -> str:
        return (
            f"SecretStatus(provider={self.provider!r}, env_var={self.env_var!r}, "
            f"state={self.state!r})"
        )

    @property
    def usable(self) -> bool:
        """True when there is *some* value to sign or verify with."""
        return self.state in ("set", "placeholder")

    def describe(self) -> str:
        if self.state == "set":
            return f"{self.env_var} is set"
        if self.state == "placeholder":
            return f"{self.env_var} is set to a placeholder value"
        if self.state == "unset":
            return f"{self.env_var} is not set"
        return f"no secret variable is defined for provider {self.provider!r}"


def secret_status(provider: str) -> SecretStatus:
    """Classify the configured secret for ``provider`` as set/placeholder/unset."""
    env_name = SECRET_ENV.get(provider)
    if not env_name:
        return SecretStatus(provider, None, "unknown-provider")
    value = os.environ.get(env_name)
    if value is None or not value.strip():
        return SecretStatus(provider, env_name, "unset")
    if is_placeholder(value):
        return SecretStatus(provider, env_name, "placeholder", value)
    return SecretStatus(provider, env_name, "set", value)


def get_secret(provider: str, *, allow_placeholder: bool = False) -> str | None:
    """Return the configured signing secret for ``provider`` or ``None``.

    By default placeholder values resolve to ``None`` so callers can
    distinguish "no real secret configured" from "wrong secret". Pass
    ``allow_placeholder=True`` for explicit, local-only actions such as
    re-signing a replay for an example handler that uses the same placeholder.
    """
    status = secret_status(provider)
    if status.state == "set":
        return status.value
    if status.state == "placeholder" and allow_placeholder:
        return status.value
    return None


def all_secrets(*, allow_placeholder: bool = False) -> dict[str, str | None]:
    """Return a ``{provider: secret_or_None}`` map for every known provider."""
    return {
        provider: get_secret(provider, allow_placeholder=allow_placeholder)
        for provider in SECRET_ENV
    }


def generic_scheme(*, required: bool = False) -> GenericScheme | None:
    """Return the generic HMAC scheme configured through ``GENERIC_WEBHOOK_*``.

    Returns ``None`` when ``GENERIC_WEBHOOK_HEADER`` is unset, unless
    ``required`` is true, in which case the defaults (``X-Signature``, SHA-256,
    hex, no prefix) are used. Raises ``ValueError`` for an unsupported
    algorithm or encoding, naming the variable.
    """
    header = os.environ.get(GENERIC_ENV["signature_header"], "").strip()
    if not header and not required:
        return None
    values = {
        "signature_header": header or GenericScheme.signature_header,
        "algorithm": os.environ.get(GENERIC_ENV["algorithm"], "").strip().lower() or "sha256",
        "encoding": os.environ.get(GENERIC_ENV["encoding"], "").strip().lower() or "hex",
        "prefix": os.environ.get(GENERIC_ENV["prefix"], ""),
    }
    try:
        return GenericScheme(**values)
    except ValueError as exc:
        raise ValueError(f"invalid GENERIC_WEBHOOK_* configuration: {exc}") from exc
