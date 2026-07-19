"""Fan-out inbound webhooks to one or more local dev URLs.

This is a miniature version of the "smee" idea: instead of relaying through a
public service, the receiver forwards each captured event straight to the local
handlers you are working on. Every target is attempted independently with a
small retry budget, and a per-target status is returned so you can see which
handler accepted the delivery.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from .replay import build_replay_request
from .storage import StoredEvent


@dataclass
class ForwardResult:
    target: str
    ok: bool
    status_code: int | None
    attempts: int
    elapsed_ms: float
    error: str | None = None


@dataclass
class TargetStats:
    """Running counters for one forward target, shown in the live console."""

    target: str
    delivered: int = 0
    failed: int = 0
    last_status: int | None = None

    def record(self, result: ForwardResult) -> None:
        if result.ok:
            self.delivered += 1
        else:
            self.failed += 1
        self.last_status = result.status_code


def forward_event(
    event: StoredEvent,
    targets: list[str],
    *,
    retries: int = 2,
    timeout: float = 5.0,
    backoff: float = 0.5,
    secret_map: dict[str, str] | None = None,
) -> list[ForwardResult]:
    """Deliver ``event`` to every URL in ``targets``.

    ``retries`` is the number of *additional* attempts after the first, applied
    only to connection errors and 5xx responses. ``secret_map`` optionally maps
    a provider name to a secret; when the event's provider matches, the outgoing
    copy is re-signed for that target.
    """
    results: list[ForwardResult] = []
    with httpx.Client(timeout=timeout) as client:
        for target in targets:
            secret = None
            if secret_map and event.provider:
                secret = secret_map.get(event.provider)
            request = build_replay_request(
                event, target, provider=event.provider, secret=secret
            )
            results.append(_deliver(client, request, retries, backoff))
    return results


def _deliver(client: httpx.Client, request, retries: int, backoff: float) -> ForwardResult:
    attempts = 0
    start = time.perf_counter()
    last_error: str | None = None
    last_status: int | None = None
    for attempt in range(retries + 1):
        attempts = attempt + 1
        try:
            response = client.request(
                request.method,
                request.url,
                headers=request.headers,
                content=request.body,
            )
            last_status = response.status_code
            if response.is_success:
                elapsed = (time.perf_counter() - start) * 1000
                return ForwardResult(request.url, True, response.status_code, attempts, elapsed)
            if response.status_code < 500:
                # 4xx is a definitive rejection; retrying will not help.
                break
            last_error = f"HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            last_error = str(exc)
        if attempt < retries:
            time.sleep(backoff * (attempt + 1))
    elapsed = (time.perf_counter() - start) * 1000
    return ForwardResult(request.url, False, last_status, attempts, elapsed, error=last_error)
