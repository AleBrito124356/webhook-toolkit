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

import time
from dataclasses import dataclass

import httpx

from .storage import StoredEvent
from .verify import PROVIDERS, SIGNERS, SLACK_TIMESTAMP_HEADER

# Hop-by-hop / recomputed headers we never forward verbatim.
_STRIP_HEADERS = {"host", "content-length", "connection", "accept-encoding"}


@dataclass
class ReplayRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes

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


def _clean_headers(headers: dict[str, str], overrides: dict[str, str] | None) -> dict[str, str]:
    cleaned = {k: v for k, v in headers.items() if k.lower() not in _STRIP_HEADERS}
    for key, value in (overrides or {}).items():
        # Replace case-insensitively so we do not end up with duplicate keys.
        for existing in list(cleaned):
            if existing.lower() == key.lower():
                del cleaned[existing]
        cleaned[key] = value
    return cleaned


def _set_header(headers: dict[str, str], name: str, value: str) -> None:
    for existing in list(headers):
        if existing.lower() == name.lower():
            del headers[existing]
    headers[name] = value


def build_replay_request(
    event: StoredEvent,
    target_url: str,
    *,
    provider: str | None = None,
    secret: str | bytes | None = None,
    override_body: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
    now: int | None = None,
) -> ReplayRequest:
    """Return the request to send when replaying ``event`` to ``target_url``.

    When both ``provider`` and ``secret`` are given, the provider's signature
    header (and Slack's timestamp header) are recomputed over the outgoing body
    so the receiving handler accepts the replay.
    """
    body = event.body if override_body is None else override_body
    headers = _clean_headers(event.headers, extra_headers)

    resolved_provider = provider or event.provider
    resigned = False
    if secret is not None and resolved_provider in SIGNERS:
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
        resigned = True

    return ReplayRequest(method=event.method, url=target_url, headers=headers, body=body)


def send_replay(request: ReplayRequest, *, timeout: float = 10.0) -> ReplayResult:
    """Send a prepared :class:`ReplayRequest` and capture the outcome."""
    start = time.perf_counter()
    try:
        response = httpx.request(
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
    )
    result = send_replay(request, timeout=timeout)
    result.resigned = secret is not None and (provider or event.provider) in SIGNERS
    return result
