"""Replay stored events to a target URL, optionally re-signing them.

The interesting part is ``build_replay_request``: it is a pure function that
turns a stored event into the request that *would* be sent, without performing
any I/O. That makes re-signing trivially testable and keeps the network call in
one small place (:func:`send_replay`).

Re-signing matters because Stripe and Slack reject signatures whose timestamp is
outside a tolerance window. A payload captured yesterday will not verify today
unless you re-sign it with a fresh timestamp — which is exactly what happens
when a secret is supplied.
"""

from __future__ import annotations

import functools
import ssl
import time
from dataclasses import dataclass

import httpx

from .storage import StoredEvent
from .verify import (
    GITHUB_LEGACY_HEADER,
    PROVIDERS,
    SIGNERS,
    SLACK_TIMESTAMP_HEADER,
    GenericScheme,
    sign_generic,
    sign_github_legacy,
)

# Headers that describe the *original* connection or message framing, never the
# payload. Copying them onto a new request produces invalid HTTP: a captured
# ``Transfer-Encoding: chunked`` next to the ``Content-Length`` httpx computes
# is rejected outright by strict parsers such as Node's llhttp. ``host`` and
# ``content-length`` are recomputed for the new target; ``accept-encoding`` is
# left to the HTTP client so it can decode the response it asked for.
HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "expect",
        "host",
        "content-length",
        "accept-encoding",
    }
)
# Backwards-compatible alias.
_STRIP_HEADERS = HOP_BY_HOP_HEADERS
_FRAMING_HEADERS = frozenset({"content-length", "transfer-encoding"})


@dataclass
class ReplayRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes
    resigned: bool = False

    def header(self, name: str) -> str | None:
        target = name.lower()
        for key, value in self.headers.items():
            if key.lower() == target:
                return value
        return None


@dataclass
class ReplayResult:
    ok: bool
    status_code: int | None
    url: str
    elapsed_ms: float
    error: str | None = None
    response_snippet: str = ""
    resigned: bool = False


def _connection_tokens(headers: dict[str, str]) -> set[str]:
    """Header names listed in ``Connection`` are hop-by-hop too (RFC 9110 7.6.1)."""
    tokens: set[str] = set()
    for key, value in headers.items():
        if key.lower() == "connection":
            tokens.update(t.strip().lower() for t in value.split(",") if t.strip())
    return tokens


def _clean_headers(headers: dict[str, str], overrides: dict[str, str] | None) -> dict[str, str]:
    drop = HOP_BY_HOP_HEADERS | _connection_tokens(headers)
    cleaned = {k: v for k, v in headers.items() if k.lower() not in drop}
    for key, value in (overrides or {}).items():
        if key.lower() in _FRAMING_HEADERS:
            # The HTTP client frames the body itself; a manual value would
            # contradict it and produce an invalid request.
            continue
        # Replace case-insensitively so we do not end up with duplicate keys.
        for existing in list(cleaned):
            if existing.lower() == key.lower():
                del cleaned[existing]
        cleaned[key] = value
    return cleaned


def _has_header(headers: dict[str, str], name: str) -> bool:
    return any(existing.lower() == name.lower() for existing in headers)


def set_header(headers: dict[str, str], name: str, value: str) -> None:
    """Set ``name`` in ``headers``, replacing any existing key case-insensitively."""
    for existing in list(headers):
        if existing.lower() == name.lower():
            del headers[existing]
    headers[name] = value


_set_header = set_header


def build_replay_request(
    event: StoredEvent,
    target_url: str,
    *,
    provider: str | None = None,
    secret: str | bytes | None = None,
    override_body: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
    now: int | None = None,
    scheme: GenericScheme | None = None,
) -> ReplayRequest:
    """Return the request to send when replaying ``event`` to ``target_url``.

    When both ``provider`` and ``secret`` are given, the provider's signature
    header (and Slack's timestamp header) are recomputed over the outgoing body
    so the receiving handler accepts the replay. ``scheme`` describes the
    ``generic`` provider's header, digest and encoding.
    """
    body = event.body if override_body is None else override_body
    headers = _clean_headers(event.headers, extra_headers)

    resolved_provider = provider or event.provider
    resigned = False
    if secret is not None and resolved_provider == "generic":
        scheme = scheme or GenericScheme()
        _set_header(headers, scheme.signature_header, sign_generic(secret, body, scheme))
        resigned = True
    elif secret is not None and resolved_provider in SIGNERS:
        spec = PROVIDERS[resolved_provider]
        signer = SIGNERS[resolved_provider]
        if spec.needs_timestamp:
            timestamp = int(time.time()) if now is None else now
            signature = signer(secret, body, timestamp)
            if resolved_provider == "slack":
                _set_header(headers, SLACK_TIMESTAMP_HEADER, str(timestamp))
        else:
            signature = signer(secret, body)
        _set_header(headers, spec.signature_header, signature)
        if resolved_provider == "github" and _has_header(headers, GITHUB_LEGACY_HEADER):
            # Keep GitHub's legacy SHA-1 header consistent with the new body.
            _set_header(headers, GITHUB_LEGACY_HEADER, sign_github_legacy(secret, body))
        resigned = True

    return ReplayRequest(
        method=event.method, url=target_url, headers=headers, body=body, resigned=resigned
    )


@functools.lru_cache(maxsize=1)
def default_ssl_context() -> ssl.SSLContext:
    """The TLS context for outgoing requests, built once.

    Building it loads the CA bundle, which costs ~150 ms per HTTP client on
    Windows; reusing it makes a replay to a local handler take a few ms.
    """
    return httpx.create_ssl_context()


def make_client(
    *, timeout: float = 10.0, transport: httpx.BaseTransport | None = None
) -> httpx.Client:
    """An ``httpx.Client`` for replays/forwards (``transport`` is for tests)."""
    return httpx.Client(timeout=timeout, verify=default_ssl_context(), transport=transport)


def send_replay(
    request: ReplayRequest,
    *,
    timeout: float = 10.0,
    client: httpx.Client | None = None,
) -> ReplayResult:
    """Send a prepared :class:`ReplayRequest` and capture the outcome.

    Pass ``client`` to reuse one connection pool across many sends.
    """
    if client is None:
        with make_client(timeout=timeout) as own_client:
            return send_replay(request, timeout=timeout, client=own_client)
    start = time.perf_counter()
    try:
        response = client.request(
            request.method,
            request.url,
            headers=request.headers,
            content=request.body,
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return ReplayResult(False, None, request.url, elapsed, error=str(exc))
    elapsed = (time.perf_counter() - start) * 1000
    snippet = response.text[:500]
    return ReplayResult(
        ok=response.is_success,
        status_code=response.status_code,
        url=request.url,
        elapsed_ms=elapsed,
        response_snippet=snippet,
    )


def replay_event(
    event: StoredEvent,
    target_url: str,
    *,
    provider: str | None = None,
    secret: str | bytes | None = None,
    override_body: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 10.0,
    now: int | None = None,
    scheme: GenericScheme | None = None,
) -> ReplayResult:
    """Build and send a replay in one call, returning the result."""
    request = build_replay_request(
        event,
        target_url,
        provider=provider,
        secret=secret,
        override_body=override_body,
        extra_headers=extra_headers,
        now=now,
        scheme=scheme,
    )
    result = send_replay(request, timeout=timeout)
    result.resigned = request.resigned
    return result
