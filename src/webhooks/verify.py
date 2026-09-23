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

Diagnostics
-----------
A plain verifier can only say "no". :func:`diagnose` explains *why*: a missing
or malformed header, a missing or stale timestamp (with the skew in seconds),
or a real mismatch — and for mismatches it re-tries the HMAC under the common
real-world mistakes (a trailing newline added by an editor, CRLF line endings,
JSON that was re-serialized, whitespace or a missing ``whsec_`` prefix in the
secret, hex vs base64, secrets swapped between providers...) to point at the
one that explains the failure.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from typing import Callable

# Header names, kept in one place so the server, CLI and README stay in sync.
GITHUB_HEADER = "X-Hub-Signature-256"
STRIPE_HEADER = "Stripe-Signature"
SLACK_SIGNATURE_HEADER = "X-Slack-Signature"
SLACK_TIMESTAMP_HEADER = "X-Slack-Request-Timestamp"
SHOPIFY_HEADER = "X-Shopify-Hmac-Sha256"
# GitHub still sends the legacy SHA-1 signature alongside the SHA-256 one.
GITHUB_LEGACY_HEADER = "X-Hub-Signature"
GENERIC_DEFAULT_HEADER = "X-Signature"

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


def sign_github_legacy(secret: str | bytes, body: str | bytes) -> str:
    """The legacy ``X-Hub-Signature`` value (``sha1=<hex>``) GitHub also sends."""
    return sign_hmac(secret, body, algorithm="sha1", encoding="hex", prefix="sha1=")


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
# Generic HMAC scheme — any sender that signs HMAC(secret, raw body)
# ---------------------------------------------------------------------------
_HMAC_ALGORITHMS = ("sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "md5")
_ENCODINGS = ("hex", "base64")


@dataclass(frozen=True)
class GenericScheme:
    """A configurable ``HMAC(secret, body)`` scheme for providers not built in.

    ``prefix`` is prepended verbatim to the encoded digest (``"sha256="`` for
    GitHub-style headers, ``""`` for bare digests).
    """

    signature_header: str = GENERIC_DEFAULT_HEADER
    algorithm: str = "sha256"
    encoding: str = "hex"
    prefix: str = ""

    def __post_init__(self) -> None:
        if self.algorithm not in _HMAC_ALGORITHMS:
            raise ValueError(
                f"unsupported HMAC algorithm {self.algorithm!r}; "
                f"choose one of {', '.join(_HMAC_ALGORITHMS)}"
            )
        if self.encoding not in _ENCODINGS:
            raise ValueError(f"unsupported encoding {self.encoding!r}; choose hex or base64")
        if not self.signature_header.strip():
            raise ValueError("signature_header must not be empty")

    def describe(self) -> str:
        return (
            f"{self.signature_header}: {self.prefix}<{self.encoding} "
            f"HMAC-{self.algorithm.upper()} of the raw body>"
        )


def sign_generic(secret: str | bytes, body: str | bytes, scheme: GenericScheme | None = None) -> str:
    scheme = scheme or GenericScheme()
    return sign_hmac(
        secret, body, algorithm=scheme.algorithm, encoding=scheme.encoding, prefix=scheme.prefix
    )


def verify_generic(
    secret: str | bytes,
    body: str | bytes,
    signature: str | None,
    scheme: GenericScheme | None = None,
) -> bool:
    scheme = scheme or GenericScheme()
    return verify_hmac(
        secret,
        body,
        signature,
        algorithm=scheme.algorithm,
        encoding=scheme.encoding,
        prefix=scheme.prefix,
    )


# ---------------------------------------------------------------------------
# Provider registry
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
    "generic": ProviderSpec(
        "generic", "Generic HMAC", GENERIC_DEFAULT_HEADER, "sha256", "hex", False,
        "GENERIC_WEBHOOK_SECRET", "configurable HMAC of the raw body (header, digest, encoding, prefix)",
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

    def keys(self) -> list[str]:
        return list(self._lower)


def detect_provider(
    headers: dict[str, str] | None, *, generic: GenericScheme | None = None
) -> str | None:
    """Guess the provider from the set of signature headers present.

    The generic provider is only considered when a ``generic`` scheme is
    configured, and only after the built-in providers.
    """
    view = _CaseInsensitiveHeaders(headers)
    if view.get(GITHUB_HEADER):
        return "github"
    if view.get(STRIPE_HEADER):
        return "stripe"
    if view.get(SLACK_SIGNATURE_HEADER):
        return "slack"
    if view.get(SHOPIFY_HEADER):
        return "shopify"
    if generic is not None and view.get(generic.signature_header):
        return "generic"
    return None


def signature_header_for(provider: str, generic: GenericScheme | None = None) -> str:
    if provider == "generic":
        return (generic or GenericScheme()).signature_header
    return PROVIDERS[provider].signature_header


# ---------------------------------------------------------------------------
# Diagnostics: explain *why* a signature does not verify
# ---------------------------------------------------------------------------
DIAGNOSIS_CODES = (
    "valid",
    "missing_signature_header",
    "malformed_header",
    "missing_timestamp",
    "timestamp_out_of_tolerance",
    "mismatch",
    "unknown_provider",
)

# Bodies above this size skip the JSON re-serialization guesses (they are
# only there to explain mistakes; a 5 MB webhook is not a typical case).
_MAX_JSON_GUESS_BYTES = 5 * 1024 * 1024
_DIGEST_ALGORITHM_BY_SIZE = {16: "md5", 20: "sha1", 28: "sha224", 32: "sha256", 48: "sha384", 64: "sha512"}
_PREFIX_RE = re.compile(r"^([A-Za-z0-9_-]{1,16})=(.+)$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass
class Diagnosis:
    """Structured explanation of a verification outcome.

    ``code`` is one of :data:`DIAGNOSIS_CODES`. ``reason`` is a one-line
    explanation; ``hints`` are actionable follow-ups. ``skew_seconds`` is
    ``now - timestamp`` for timestamped schemes (positive: the signature is
    in the past).
    """

    provider: str
    code: str
    reason: str
    hints: list[str] = field(default_factory=list)
    skew_seconds: int | None = None
    tolerance: int | None = None

    @property
    def ok(self) -> bool:
        return self.code == "valid"

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "provider": self.provider,
            "code": self.code,
            "reason": self.reason,
            "hints": list(self.hints),
            "skew_seconds": self.skew_seconds,
            "tolerance": self.tolerance,
        }


@dataclass(frozen=True)
class _Format:
    header: str
    prefix: str
    encoding: str
    algorithm: str


def _format_for(provider: str, scheme: GenericScheme | None) -> _Format:
    if provider == "github":
        return _Format(GITHUB_HEADER, "sha256=", "hex", "sha256")
    if provider == "stripe":
        return _Format(STRIPE_HEADER, "", "hex", "sha256")
    if provider == "slack":
        return _Format(SLACK_SIGNATURE_HEADER, "v0=", "hex", "sha256")
    if provider == "shopify":
        return _Format(SHOPIFY_HEADER, "", "base64", "sha256")
    scheme = scheme or GenericScheme()
    return _Format(scheme.signature_header, scheme.prefix, scheme.encoding, scheme.algorithm)


def _label(provider: str) -> str:
    return PROVIDERS[provider].label if provider in PROVIDERS else provider


def _signed_message(provider: str, body: bytes, timestamp: int | None) -> bytes:
    if timestamp is None:
        return body
    if provider == "stripe":
        return _stripe_signed_payload(timestamp, body)
    if provider == "slack":
        return _slack_basestring(timestamp, body)
    return body


def _mac(key: bytes, message: bytes, algorithm: str) -> bytes:
    return hmac.new(key, message, getattr(hashlib, algorithm)).digest()


def _looks_like_hex_digest(text: str) -> bool:
    return bool(_HEX_RE.match(text)) and len(text) // 2 in _DIGEST_ALGORITHM_BY_SIZE and len(text) % 2 == 0


def _decode_digest(text: str, encoding: str) -> bytes | None:
    if encoding == "hex":
        if not _HEX_RE.match(text) or len(text) % 2:
            return None
        return bytes.fromhex(text)
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def _strict_ok(
    provider: str,
    key: bytes,
    body: bytes,
    view: _CaseInsensitiveHeaders,
    tolerance: int,
    now: int | None,
    scheme: GenericScheme | None,
) -> bool:
    """The exact yes/no the individual ``verify_*`` functions give."""
    if provider == "github":
        return verify_github(key, body, view.get(GITHUB_HEADER))
    if provider == "stripe":
        return verify_stripe(key, body, view.get(STRIPE_HEADER), tolerance=tolerance, now=now)
    if provider == "slack":
        return verify_slack(
            key,
            body,
            view.get(SLACK_SIGNATURE_HEADER),
            view.get(SLACK_TIMESTAMP_HEADER),
            tolerance=tolerance,
            now=now,
        )
    if provider == "shopify":
        return verify_shopify(key, body, view.get(SHOPIFY_HEADER))
    scheme = scheme or GenericScheme()
    return verify_generic(key, body, view.get(scheme.signature_header), scheme)


def _body_variants(body: bytes) -> list[tuple[str, bytes, str]]:
    """(description, bytes, advice) for the ways a body commonly gets altered."""
    newline_advice = (
        "Something changed the bytes after they were signed (an editor saving the file, "
        "`echo`, a shell heredoc). Verify the exact bytes that were received."
    )
    variants: list[tuple[str, bytes, str]] = []
    if body.endswith(b"\r\n"):
        variants.append(("with the trailing CRLF removed", body[:-2], newline_advice))
    elif body.endswith(b"\n"):
        variants.append(("with the trailing newline removed", body[:-1], newline_advice))
    variants.append(("with a trailing newline added", body + b"\n", newline_advice))
    crlf_advice = (
        "Line endings were converted (git core.autocrlf or a Windows editor rewrites LF "
        "as CRLF). Store and verify the raw bytes, e.g. mark fixtures as binary in "
        ".gitattributes."
    )
    if b"\r\n" in body:
        lf = body.replace(b"\r\n", b"\n")
        variants.append(("with CRLF line endings converted to LF", lf, crlf_advice))
        if lf.endswith(b"\n"):
            variants.append(
                ("with CRLF converted to LF and the trailing newline removed", lf[:-1], crlf_advice)
            )
    elif b"\n" in body:
        variants.append(("with LF line endings converted to CRLF", body.replace(b"\n", b"\r\n"), crlf_advice))

    stripped = body.strip()
    if len(body) <= _MAX_JSON_GUESS_BYTES and stripped[:1] in (b"{", b"["):
        try:
            document = json.loads(body)
        except ValueError:
            document = None
        if document is not None:
            json_advice = (
                "The body you are checking is not the byte stream that was signed: it was "
                "parsed and re-serialized somewhere. Verify the raw request bytes "
                "(e.g. `await request.body()`) before any JSON parsing or pretty-printing."
            )
            renderings = [
                ("re-serialized as compact JSON (no spaces)",
                 json.dumps(document, separators=(",", ":"), ensure_ascii=False)),
                ("re-serialized with json.dumps defaults (', ' and ': ' separators, non-ASCII escaped)",
                 json.dumps(document)),
                ("pretty-printed with 2-space indentation",
                 json.dumps(document, indent=2, ensure_ascii=False)),
                ("pretty-printed with 4-space indentation",
                 json.dumps(document, indent=4, ensure_ascii=False)),
                ("re-serialized as compact JSON with non-ASCII escaped",
                 json.dumps(document, separators=(",", ":"))),
                ("re-serialized as compact JSON with sorted keys",
                 json.dumps(document, separators=(",", ":"), sort_keys=True, ensure_ascii=False)),
            ]
            for description, text in renderings:
                variants.append((description, text.encode("utf-8"), json_advice))

    unique: list[tuple[str, bytes, str]] = []
    seen = {body}
    for description, candidate, advice in variants:
        if candidate not in seen:
            seen.add(candidate)
            unique.append((description, candidate, advice))
    return unique


def _secret_variants(
    provider: str, key: bytes, other_secrets: dict[str, str | bytes | None] | None
) -> list[tuple[str, bytes, str]]:
    """(description, key, advice) for the ways a secret is commonly mangled."""
    text = key.decode("utf-8", errors="replace")
    variants: list[tuple[str, bytes, str]] = []
    if key.strip() != key:
        variants.append(
            (
                "the secret with surrounding whitespace removed",
                key.strip(),
                "Your configured secret has leading/trailing whitespace or a newline "
                "(typical after copy-paste or `echo secret > file`). Remove it.",
            )
        )
    core = text.strip()
    if core.startswith("whsec_whsec_"):
        variants.append(
            (
                "the secret with its duplicated 'whsec_' prefix removed",
                core[len("whsec_"):].encode("utf-8"),
                "Your configured secret has 'whsec_' twice. Copy the value exactly as the "
                "Stripe dashboard shows it.",
            )
        )
    if core.startswith("whsec_"):
        rest = core[len("whsec_"):]
        variants.append(
            (
                "the secret without its 'whsec_' prefix",
                rest.encode("utf-8"),
                "The sender used the secret without its 'whsec_' prefix. Stripe's HMAC key "
                "is the whole string, prefix included.",
            )
        )
        decoded = _decode_digest(rest, "base64") if rest else None
        if decoded:
            variants.append(
                (
                    "the base64-decoded secret (Svix / Standard Webhooks scheme)",
                    decoded,
                    "Svix / Standard Webhooks senders (Clerk, Resend, ...) sign with the "
                    "base64-decoded part after 'whsec_'; Stripe uses the literal string. "
                    "Check which service actually sent this.",
                )
            )
    elif provider == "stripe" and core:
        variants.append(
            (
                "the secret with a 'whsec_' prefix added",
                b"whsec_" + core.encode("utf-8"),
                "Your configured secret is missing its 'whsec_' prefix. Copy the full "
                "signing secret from the Stripe dashboard.",
            )
        )
    if len(core) >= 32 and len(core) % 2 == 0 and _HEX_RE.match(core):
        variants.append(
            (
                "the hex-decoded secret",
                bytes.fromhex(core),
                "The sender used the hex-decoded bytes of the secret as the HMAC key "
                "instead of the text itself.",
            )
        )
    for other, other_secret in (other_secrets or {}).items():
        if other == provider or not other_secret:
            continue
        other_key = _as_bytes(other_secret)
        if other_key == key:
            continue
        env_var = PROVIDERS[other].env_var if other in PROVIDERS else other
        variants.append(
            (
                f"the secret configured for {_label(other)} ({env_var})",
                other_key,
                "The secrets look swapped between providers: check which variable holds "
                "which secret.",
            )
        )
    return variants


def _search_explanations(
    provider: str,
    key: bytes,
    body: bytes,
    timestamp: int | None,
    candidates: list[tuple[bytes, str]],
    other_secrets: dict[str, str | bytes | None] | None,
) -> tuple[str, list[str]] | None:
    """Find the single change that makes the signature match.

    Returns ``(explanation, hints)`` or ``None``. Single changes are tried
    before combinations so the simplest explanation wins.
    """

    def matches(test_key: bytes, message: bytes) -> bool:
        return any(
            hmac.compare_digest(_mac(test_key, message, algorithm), raw)
            for raw, algorithm in candidates
        )

    bodies = _body_variants(body)
    secrets_ = _secret_variants(provider, key, other_secrets)

    for description, candidate, advice in bodies:
        if matches(key, _signed_message(provider, candidate, timestamp)):
            return f"signature matches the payload {description}", [advice]
    for description, candidate_key, advice in secrets_:
        if matches(candidate_key, _signed_message(provider, body, timestamp)):
            return f"signature matches {description}", [advice]
    if provider in ("stripe", "slack") and timestamp is not None:
        if matches(key, body):
            what = "'<timestamp>.<body>'" if provider == "stripe" else "'v0:<timestamp>:<body>'"
            return (
                "signature is an HMAC of the body alone, without the timestamp",
                [f"{_label(provider)} signs {what}; the sender left the timestamp out."],
            )
    for body_description, candidate, body_advice in bodies:
        for key_description, candidate_key, key_advice in secrets_:
            if matches(candidate_key, _signed_message(provider, candidate, timestamp)):
                return (
                    f"signature matches the payload {body_description}, using {key_description}",
                    [body_advice, key_advice],
                )
    return None


_NO_EXPLANATION_HINT = (
    "No common mistake explains it. Most likely this is not the secret the sender "
    "uses (every Stripe endpoint, GitHub webhook and Slack app has its own), or the "
    "body was modified after signing."
)


def _missing_header_hints(
    provider: str,
    fmt: _Format,
    view: _CaseInsensitiveHeaders,
    key: bytes,
    body: bytes,
    headers: dict[str, str] | None,
    scheme: GenericScheme | None,
) -> list[str]:
    hints: list[str] = []
    if provider == "github":
        legacy = view.get(GITHUB_LEGACY_HEADER)
        if legacy:
            if hmac.compare_digest(sign_github_legacy(key, body), legacy.strip()):
                hints.append(
                    "Only the legacy X-Hub-Signature (SHA-1) header is present, and it matches "
                    "your secret: body and secret are right, but whatever delivered this "
                    "dropped X-Hub-Signature-256."
                )
            else:
                hints.append(
                    "Only the legacy X-Hub-Signature (SHA-1) header is present, and it does "
                    "not match this secret either."
                )
    other = detect_provider(headers, generic=scheme if provider != "generic" else None)
    if other and other != provider:
        hints.append(
            f"The request carries a {_label(other)} signature "
            f"({signature_header_for(other, scheme)}). Did you pick the wrong provider?"
        )
    lookalikes = [
        name for name in view.keys()
        if ("signature" in name or "hmac" in name) and name != fmt.header.lower()
    ]
    if lookalikes and not hints:
        hints.append("Signature-like headers present: " + ", ".join(sorted(lookalikes)) + ".")
    return hints


def diagnose(
    provider: str,
    secret: str | bytes,
    body: str | bytes,
    headers: dict[str, str] | None,
    *,
    tolerance: int = DEFAULT_TOLERANCE_SECONDS,
    now: int | None = None,
    scheme: GenericScheme | None = None,
    other_secrets: dict[str, str | bytes | None] | None = None,
) -> Diagnosis:
    """Verify a request and explain the outcome.

    ``other_secrets`` maps other provider names to their configured secrets;
    they are only used to recognise secrets swapped between providers.
    ``scheme`` configures the ``generic`` provider. The result's ``ok`` is
    exactly what the matching ``verify_*`` function returns.
    """
    if provider not in PROVIDERS:
        return Diagnosis(provider, "unknown_provider", f"unknown provider: {provider!r}")
    key = _as_bytes(secret)
    raw_body = _as_bytes(body)
    view = _CaseInsensitiveHeaders(headers)
    fmt = _format_for(provider, scheme)
    label = _label(provider)
    tol = tolerance or None

    if _strict_ok(provider, key, raw_body, view, tolerance, now, scheme):
        skew = None
        if provider in ("stripe", "slack"):
            ts = (
                parse_stripe_signature(view.get(STRIPE_HEADER) or "")[0]
                if provider == "stripe"
                else int(view.get(SLACK_TIMESTAMP_HEADER))
            )
            skew = (int(time.time()) if now is None else now) - ts if ts is not None else None
        return Diagnosis(provider, "valid", "signature valid", skew_seconds=skew, tolerance=tol)

    header_value = (view.get(fmt.header) or "").strip()
    if not header_value:
        return Diagnosis(
            provider,
            "missing_signature_header",
            f"no {fmt.header} header",
            _missing_header_hints(provider, fmt, view, key, raw_body, headers, scheme),
            tolerance=tol,
        )

    hints: list[str] = []
    timestamp: int | None = None
    digest_texts: list[str]

    if provider == "stripe":
        parts: dict[str, list[str]] = {}
        for item in header_value.split(","):
            name, sep, value = item.strip().partition("=")
            if sep:
                parts.setdefault(name.strip(), []).append(value.strip())
        if "t" not in parts:
            return Diagnosis(
                provider,
                "missing_timestamp",
                "Stripe-Signature has no t=<timestamp> element",
                ["Stripe signs '<timestamp>.<body>' and sends the timestamp as t=... in the "
                 "same header; without it no signature can be checked."],
                tolerance=tol,
            )
        try:
            timestamp = int(parts["t"][0])
        except ValueError:
            return Diagnosis(
                provider, "malformed_header",
                f"Stripe-Signature timestamp t={parts['t'][0]!r} is not an integer",
                tolerance=tol,
            )
        if not parts.get("v1"):
            legacy = ["Only a v0 signature is present. Stripe verifies v1, computed with your "
                      "endpoint's signing secret."] if parts.get("v0") else []
            return Diagnosis(
                provider, "malformed_header", "Stripe-Signature has no v1=<signature> element",
                legacy, tolerance=tol,
            )
        digest_texts = parts["v1"]
    elif provider == "slack":
        raw_ts = (view.get(SLACK_TIMESTAMP_HEADER) or "").strip()
        if not raw_ts:
            return Diagnosis(
                provider,
                "missing_timestamp",
                "no X-Slack-Request-Timestamp header",
                ["Slack signs 'v0:<timestamp>:<body>', so the signature cannot be checked "
                 "without the X-Slack-Request-Timestamp value (CLI: --timestamp)."],
                tolerance=tol,
            )
        try:
            timestamp = int(raw_ts)
        except ValueError:
            return Diagnosis(
                provider, "missing_timestamp",
                f"X-Slack-Request-Timestamp is not an integer: {raw_ts!r}", tolerance=tol,
            )
        digest_texts = [header_value]
    else:
        digest_texts = [header_value]

    # --- header format: prefix, encoding, digest size --------------------------
    format_issues: list[str] = []
    candidates: list[tuple[bytes, str]] = []
    other_encoding = "base64" if fmt.encoding == "hex" else "hex"
    expected_size = hashlib.new(fmt.algorithm).digest_size
    for text in digest_texts:
        digest_text = text.strip()
        if fmt.prefix:
            if digest_text.startswith(fmt.prefix):
                digest_text = digest_text[len(fmt.prefix):]
            else:
                match = _PREFIX_RE.match(digest_text)
                if match and not _decode_digest(digest_text, fmt.encoding):
                    format_issues.append(
                        f"{fmt.header} uses the prefix '{match.group(1)}=' instead of '{fmt.prefix}'"
                    )
                    digest_text = match.group(2)
                else:
                    format_issues.append(f"{fmt.header} is missing the '{fmt.prefix}' prefix")
        elif provider != "stripe":
            match = _PREFIX_RE.match(digest_text)
            if match and _decode_digest(digest_text, fmt.encoding) is None and (
                _decode_digest(match.group(2), fmt.encoding) or _looks_like_hex_digest(match.group(2))
            ):
                format_issues.append(f"{fmt.header} has an unexpected '{match.group(1)}=' prefix")
                digest_text = match.group(2)
        if fmt.encoding == "base64" and _looks_like_hex_digest(digest_text):
            raw = bytes.fromhex(digest_text)
            format_issues.append(f"the digest is hex-encoded but {label} sends base64")
        else:
            raw = _decode_digest(digest_text, fmt.encoding)
            if raw is None:
                raw = _decode_digest(digest_text, other_encoding)
                if raw is None:
                    format_issues.append(f"the digest in {fmt.header} is not valid {fmt.encoding}")
                    continue
                format_issues.append(
                    f"the digest is {other_encoding}-encoded but {label} uses {fmt.encoding}"
                )
        algorithm = _DIGEST_ALGORITHM_BY_SIZE.get(len(raw))
        if len(raw) != expected_size:
            format_issues.append(
                f"the digest is {len(raw)} bytes ({(algorithm or 'unknown algorithm').upper()}); "
                f"{label} uses {fmt.algorithm.upper()} ({expected_size} bytes)"
            )
        candidates.append((raw, algorithm or fmt.algorithm))

    current = int(time.time()) if now is None else now
    skew = current - timestamp if timestamp is not None else None
    if timestamp is not None and timestamp > 10**11:
        hints.append("The timestamp looks like milliseconds; providers use Unix seconds.")

    def mac_matches() -> bool:
        message = _signed_message(provider, raw_body, timestamp)
        return any(
            hmac.compare_digest(_mac(key, message, algorithm), raw) for raw, algorithm in candidates
        )

    def explain() -> list[str]:
        found = _search_explanations(provider, key, raw_body, timestamp, candidates, other_secrets)
        if found is None:
            return [_NO_EXPLANATION_HINT]
        explanation, advice = found
        return [explanation[0].upper() + explanation[1:] + "."] + advice

    if format_issues:
        if candidates and mac_matches():
            hints.append(
                "The digest itself is correct for this body and secret; only the header "
                "format is wrong."
            )
        elif candidates:
            hints.extend(explain())
        return Diagnosis(
            provider, "malformed_header", format_issues[0], format_issues[1:] + hints,
            skew_seconds=skew, tolerance=tol,
        )

    if tolerance and skew is not None and abs(skew) > tolerance:
        direction = "old" if skew > 0 else "in the future"
        reason = f"timestamp is {abs(skew)} s {direction}, tolerance {tolerance} s"
        if mac_matches():
            if skew > 0:
                hints.append(
                    "The signature itself is valid for that timestamp, so body and secret are "
                    "right: the delivery is just stale. Replay it with --sign to re-sign it with "
                    "a fresh timestamp, or check an old capture with --tolerance 0."
                )
            else:
                hints.append(
                    "The signature itself is valid for that timestamp, so body and secret are "
                    "right: the sender's clock is ahead of this machine's (or this one is "
                    "behind). Sync the clocks, or check with --tolerance 0."
                )
        else:
            hints.append("The signature does not match either:")
            hints.extend(explain())
        return Diagnosis(
            provider, "timestamp_out_of_tolerance", reason, hints, skew_seconds=skew, tolerance=tol
        )

    if mac_matches():
        # Same bytes, different text: e.g. uppercase hex. Strict verifiers
        # compare the canonical string, so this still fails.
        return Diagnosis(
            provider,
            "malformed_header",
            f"{fmt.header} carries the right digest in a non-canonical form (e.g. uppercase hex)",
            hints + ["Send the digest exactly as the provider formats it (lowercase hex)."],
            skew_seconds=skew,
            tolerance=tol,
        )

    found = _search_explanations(provider, key, raw_body, timestamp, candidates, other_secrets)
    if found is not None:
        explanation, advice = found
        return Diagnosis(provider, "mismatch", explanation, hints + advice, skew_seconds=skew, tolerance=tol)
    return Diagnosis(
        provider,
        "mismatch",
        "signature does not match this body and secret",
        hints + [_NO_EXPLANATION_HINT],
        skew_seconds=skew,
        tolerance=tol,
    )


# ---------------------------------------------------------------------------
# Unified request verification (stable API, now with a real reason)
# ---------------------------------------------------------------------------
@dataclass
class VerifyResult:
    ok: bool
    provider: str
    reason: str
    code: str = ""
    hints: list[str] = field(default_factory=list)


def verify_request(
    provider: str,
    secret: str | bytes,
    body: str | bytes,
    headers: dict[str, str],
    *,
    tolerance: int = DEFAULT_TOLERANCE_SECONDS,
    now: int | None = None,
    scheme: GenericScheme | None = None,
    other_secrets: dict[str, str | bytes | None] | None = None,
) -> VerifyResult:
    """Verify a captured request against ``provider``'s scheme.

    ``headers`` is looked up case-insensitively so it works with either the
    lowercased dict Starlette produces or a raw header map from the CLI. The
    ``reason`` comes from :func:`diagnose`, so a failure says *why*.
    """
    diagnosis = diagnose(
        provider,
        secret,
        body,
        headers,
        tolerance=tolerance,
        now=now,
        scheme=scheme,
        other_secrets=other_secrets,
    )
    return VerifyResult(diagnosis.ok, provider, diagnosis.reason, diagnosis.code, diagnosis.hints)


# Map provider -> the signing function used when replaying with a fresh
# signature. Timestamp-based providers accept an optional ``timestamp`` kwarg.
# The generic provider needs a scheme, see :func:`sign_generic`.
SIGNERS: dict[str, Callable[..., str]] = {
    "github": sign_github,
    "stripe": sign_stripe,
    "slack": sign_slack,
    "shopify": sign_shopify,
}
