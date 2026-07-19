"""Webhook signature verification for common providers.

Every function is symmetric: a ``sign_*`` helper produces exactly the header
value a provider would send, and a ``verify_*`` helper checks an incoming value
with a constant-time comparison. The signing helpers are what makes
*replay with re-signing* and the test-vector approach possible, so we never
have to hardcode a real-looking token anywhere.

Provider reference
------------------
==========  =============================  ====================================
Provider    Header                         Scheme
==========  =============================  ====================================
GitHub      ``X-Hub-Signature-256``        ``sha256=`` + hex HMAC-SHA256 of body
Stripe      ``Stripe-Signature``           ``t=<ts>,v1=<hex>`` over ``ts.body``
Slack       ``X-Slack-Signature``          ``v0=`` + hex HMAC over ``v0:ts:body``
Shopify     ``X-Shopify-Hmac-Sha256``      base64 HMAC-SHA256 of body
Generic     (caller chooses)               HMAC with configurable digest/encoding
==========  =============================  ====================================

Slack additionally sends the timestamp in ``X-Slack-Request-Timestamp``; Stripe
carries it inside the signature header itself.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Callable

# Header names, kept in one place so the server, CLI and README stay in sync.
GITHUB_HEADER = "X-Hub-Signature-256"
STRIPE_HEADER = "Stripe-Signature"
SLACK_SIGNATURE_HEADER = "X-Slack-Signature"
SLACK_TIMESTAMP_HEADER = "X-Slack-Request-Timestamp"
SHOPIFY_HEADER = "X-Shopify-Hmac-Sha256"

DEFAULT_TOLERANCE_SECONDS = 300


def _as_bytes(value: str | bytes) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8")


# ---------------------------------------------------------------------------
# Generic HMAC helper
# ---------------------------------------------------------------------------
def sign_hmac(
    secret: str | bytes,
    body: str | bytes,
    *,
    algorithm: str = "sha256",
    encoding: str = "hex",
    prefix: str = "",
) -> str:
    """Compute an HMAC of ``body`` and format it as a header value.

    ``encoding`` is ``"hex"`` or ``"base64"``. ``prefix`` is prepended verbatim
    (e.g. ``"sha256="`` for GitHub-style headers).
    """
    digestmod = getattr(hashlib, algorithm)
    mac = hmac.new(_as_bytes(secret), _as_bytes(body), digestmod)
    if encoding == "hex":
        rendered = mac.hexdigest()
    elif encoding == "base64":
        rendered = base64.b64encode(mac.digest()).decode("ascii")
    else:  # pragma: no cover - guarded by callers
        raise ValueError(f"unsupported encoding: {encoding!r}")
    return f"{prefix}{rendered}"


def verify_hmac(
    secret: str | bytes,
    body: str | bytes,
    signature: str | None,
    *,
    algorithm: str = "sha256",
    encoding: str = "hex",
    prefix: str = "",
) -> bool:
    """Constant-time check of a generic HMAC ``signature`` header value."""
    if not signature:
        return False
    expected = sign_hmac(
        secret, body, algorithm=algorithm, encoding=encoding, prefix=prefix
    )
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# GitHub — HMAC-SHA256, header ``X-Hub-Signature-256`` (value ``sha256=<hex>``)
# ---------------------------------------------------------------------------
def sign_github(secret: str | bytes, body: str | bytes) -> str:
    return sign_hmac(secret, body, algorithm="sha256", encoding="hex", prefix="sha256=")


def verify_github(secret: str | bytes, body: str | bytes, signature: str | None) -> bool:
    return verify_hmac(
        secret, body, signature, algorithm="sha256", encoding="hex", prefix="sha256="
    )


# ---------------------------------------------------------------------------
# Stripe — ``Stripe-Signature: t=<ts>,v1=<hex>`` signed over ``<ts>.<body>``
# ---------------------------------------------------------------------------
def _stripe_signed_payload(timestamp: int, body: str | bytes) -> bytes:
    return f"{timestamp}.".encode("utf-8") + _as_bytes(body)


def sign_stripe(secret: str | bytes, body: str | bytes, timestamp: int | None = None) -> str:
    if timestamp is None:
        timestamp = int(time.time())
    signed = _stripe_signed_payload(timestamp, body)
    v1 = hmac.new(_as_bytes(secret), signed, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={v1}"


def parse_stripe_signature(header: str) -> tuple[int | None, list[str]]:
    """Parse a ``Stripe-Signature`` header into ``(timestamp, [v1, ...])``."""
    timestamp: int | None = None
    signatures: list[str] = []
    for part in header.split(","):
        if "=" not in part:
            continue
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError:
                timestamp = None
        elif key == "v1":
            signatures.append(value)
    return timestamp, signatures


def verify_stripe(
    secret: str | bytes,
    body: str | bytes,
    header: str | None,
    *,
    tolerance: int = DEFAULT_TOLERANCE_SECONDS,
    now: int | None = None,
) -> bool:
    if not header:
        return False
    timestamp, signatures = parse_stripe_signature(header)
    if timestamp is None or not signatures:
        return False
    if tolerance:
        current = int(time.time()) if now is None else now
        if abs(current - timestamp) > tolerance:
            return False
    signed = _stripe_signed_payload(timestamp, body)
    expected = hmac.new(_as_bytes(secret), signed, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, candidate) for candidate in signatures)


# ---------------------------------------------------------------------------
# Slack — ``X-Slack-Signature: v0=<hex>`` over ``v0:<ts>:<body>``
# ---------------------------------------------------------------------------
def _slack_basestring(timestamp: int, body: str | bytes) -> bytes:
    return b"v0:" + str(timestamp).encode("ascii") + b":" + _as_bytes(body)


def sign_slack(secret: str | bytes, body: str | bytes, timestamp: int | None = None) -> str:
    if timestamp is None:
        timestamp = int(time.time())
    base = _slack_basestring(timestamp, body)
    digest = hmac.new(_as_bytes(secret), base, hashlib.sha256).hexdigest()
    return f"v0={digest}"


def verify_slack(
    secret: str | bytes,
    body: str | bytes,
    signature: str | None,
    timestamp: str | int | None,
    *,
    tolerance: int = DEFAULT_TOLERANCE_SECONDS,
    now: int | None = None,
) -> bool:
    if not signature or timestamp is None:
        return False
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if tolerance:
        current = int(time.time()) if now is None else now
        if abs(current - ts) > tolerance:
            return False
    expected = sign_slack(secret, body, ts)
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Shopify — ``X-Shopify-Hmac-Sha256``: base64 HMAC-SHA256 of the raw body
# ---------------------------------------------------------------------------
def sign_shopify(secret: str | bytes, body: str | bytes) -> str:
    return sign_hmac(secret, body, algorithm="sha256", encoding="base64")


def verify_shopify(secret: str | bytes, body: str | bytes, signature: str | None) -> bool:
    return verify_hmac(secret, body, signature, algorithm="sha256", encoding="base64")


# ---------------------------------------------------------------------------
# Provider registry + unified request verification
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ProviderSpec:
    name: str
    label: str
    signature_header: str
    algorithm: str
    encoding: str
    needs_timestamp: bool
    env_var: str
    description: str


PROVIDERS: dict[str, ProviderSpec] = {
    "github": ProviderSpec(
        "github", "GitHub", GITHUB_HEADER, "sha256", "hex", False,
        "GITHUB_WEBHOOK_SECRET", "sha256= + hex HMAC-SHA256 of the raw body",
    ),
    "stripe": ProviderSpec(
        "stripe", "Stripe", STRIPE_HEADER, "sha256", "hex", True,
        "STRIPE_WEBHOOK_SECRET", "t=<ts>,v1=<hex> HMAC-SHA256 of '<ts>.<body>'",
    ),
    "slack": ProviderSpec(
        "slack", "Slack", SLACK_SIGNATURE_HEADER, "sha256", "hex", True,
        "SLACK_SIGNING_SECRET", "v0= + hex HMAC-SHA256 of 'v0:<ts>:<body>'",
    ),
    "shopify": ProviderSpec(
        "shopify", "Shopify", SHOPIFY_HEADER, "sha256", "base64", False,
        "SHOPIFY_WEBHOOK_SECRET", "base64 HMAC-SHA256 of the raw body",
    ),
}


class _CaseInsensitiveHeaders:
    """Read-only case-insensitive view over a plain header dict."""

    def __init__(self, headers: dict[str, str] | None):
        self._lower = {}
        for key, value in (headers or {}).items():
            self._lower[key.lower()] = value

    def get(self, name: str) -> str | None:
        return self._lower.get(name.lower())


def detect_provider(headers: dict[str, str] | None) -> str | None:
    """Guess the provider from the set of signature headers present."""
    view = _CaseInsensitiveHeaders(headers)
    if view.get(GITHUB_HEADER):
        return "github"
    if view.get(STRIPE_HEADER):
        return "stripe"
    if view.get(SLACK_SIGNATURE_HEADER):
        return "slack"
    if view.get(SHOPIFY_HEADER):
        return "shopify"
    return None


@dataclass
class VerifyResult:
    ok: bool
    provider: str
    reason: str


def verify_request(
    provider: str,
    secret: str | bytes,
    body: str | bytes,
    headers: dict[str, str],
    *,
    tolerance: int = DEFAULT_TOLERANCE_SECONDS,
    now: int | None = None,
) -> VerifyResult:
    """Verify a captured request against ``provider``'s scheme.

    ``headers`` is looked up case-insensitively so it works with either the
    lowercased dict Starlette produces or a raw header map from the CLI.
    """
    view = _CaseInsensitiveHeaders(headers)

    if provider == "github":
        ok = verify_github(secret, body, view.get(GITHUB_HEADER))
    elif provider == "stripe":
        ok = verify_stripe(
            secret, body, view.get(STRIPE_HEADER), tolerance=tolerance, now=now
        )
    elif provider == "slack":
        ok = verify_slack(
            secret,
            body,
            view.get(SLACK_SIGNATURE_HEADER),
            view.get(SLACK_TIMESTAMP_HEADER),
            tolerance=tolerance,
            now=now,
        )
    elif provider == "shopify":
        ok = verify_shopify(secret, body, view.get(SHOPIFY_HEADER))
    else:
        return VerifyResult(False, provider, f"unknown provider: {provider!r}")

    reason = "signature valid" if ok else "signature mismatch or missing header"
    return VerifyResult(ok, provider, reason)


# Map provider -> the signing function used when replaying with a fresh
# signature. Timestamp-based providers accept an optional ``timestamp`` kwarg.
SIGNERS: dict[str, Callable[..., str]] = {
    "github": sign_github,
    "stripe": sign_stripe,
    "slack": sign_slack,
    "shopify": sign_shopify,
}
