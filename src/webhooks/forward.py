"""Fan-out inbound webhooks to one or more local dev URLs.

This is a miniature version of the "smee" idea: instead of relaying through a
public service, the receiver forwards each captured event straight to the local
handlers you are working on.

* Targets are delivered **concurrently** (one worker thread each), so a dead or
  slow handler never delays the others' results.
* Each target has a small retry budget: connection errors and 5xx responses
  are retried with a linear backoff; a 4xx is a definitive answer and is not.
* A target can be restricted to one provider with ``provider=URL`` (e.g.
  ``github=http://127.0.0.1:3001/webhooks/github``; ``unsigned=URL`` takes
  requests without a known signature), so one receiver can feed several
  handlers without each of them rejecting the others' events.
* :class:`TargetStats` keeps running counters per target; the receiver prints
  them in the live console and serves them at ``GET /api/forward``.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

import httpx

from .replay import build_replay_request, make_client
from .storage import StoredEvent, utcnow_iso
from .verify import PROVIDERS, GenericScheme

_ROUTE_PREFIXES = tuple(sorted(PROVIDERS)) + ("unsigned",)


@dataclass(frozen=True)
class ForwardTarget:
    """Where to forward, optionally only for one provider's events."""

    url: str
    provider: str | None = None

    @classmethod
    def parse(cls, spec: "str | ForwardTarget") -> "ForwardTarget":
        """Parse ``URL`` or ``provider=URL``."""
        if isinstance(spec, ForwardTarget):
            return spec
        spec = spec.strip()
        name, sep, rest = spec.partition("=")
        provider = name.strip().lower() if sep else None
        url = rest.strip() if provider in _ROUTE_PREFIXES else spec
        if provider not in _ROUTE_PREFIXES:
            provider = None
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError(
                f"invalid forward target {spec!r}: expected an http(s) URL or provider=URL "
                f"(provider one of {', '.join(_ROUTE_PREFIXES)})"
            )
        return cls(url, provider)

    @property
    def label(self) -> str:
        return f"{self.provider}={self.url}" if self.provider else self.url

    def accepts(self, event: StoredEvent) -> bool:
        if self.provider is None:
            return True
        if self.provider == "unsigned":
            return not event.provider
        return event.provider == self.provider


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
    """Running counters for one forward target.

    Shown in the live console after every delivery and served by the
    receiver at ``GET /api/forward``. ``record`` is thread-safe.
    """

    target: str
    delivered: int = 0
    failed: int = 0
    last_status: int | None = None
    last_error: str | None = None
    last_event_id: int | None = None
    last_at: str | None = None
    total_ms: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def record(self, result: ForwardResult, event_id: int | None = None) -> None:
        with self._lock:
            if result.ok:
                self.delivered += 1
                self.last_error = None
            else:
                self.failed += 1
                self.last_error = result.error or (
                    f"HTTP {result.status_code}" if result.status_code else "failed"
                )
            self.last_status = result.status_code
            self.last_event_id = event_id
            self.last_at = utcnow_iso()
            self.total_ms += result.elapsed_ms

    @property
    def avg_ms(self) -> float | None:
        attempts = self.delivered + self.failed
        return round(self.total_ms / attempts, 1) if attempts else None

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "target": self.target,
                "delivered": self.delivered,
                "failed": self.failed,
                "last_status": self.last_status,
                "last_error": self.last_error,
                "last_event_id": self.last_event_id,
                "last_at": self.last_at,
                "avg_ms": self.avg_ms,
            }


def forward_event(
    event: StoredEvent,
    targets: list["str | ForwardTarget"],
    *,
    retries: int = 2,
    timeout: float = 5.0,
    backoff: float = 0.5,
    secret_map: dict[str, str] | None = None,
    scheme: GenericScheme | None = None,
    transport: httpx.BaseTransport | None = None,
    on_result: Callable[[ForwardTarget, ForwardResult], None] | None = None,
) -> list[ForwardResult]:
    """Deliver ``event`` to every target that accepts it, concurrently.

    ``retries`` is the number of *additional* attempts after the first, applied
    only to connection errors and 5xx responses. ``secret_map`` optionally maps
    a provider name to a secret; when the event's provider matches, the outgoing
    copy is re-signed. ``on_result`` is called from the worker thread as soon
    as each target finishes (used for the live console). Results are returned
    in target order; targets restricted to another provider are skipped.
    ``transport`` is an ``httpx`` transport, for tests.
    """
    selected = [t for t in (ForwardTarget.parse(spec) for spec in targets) if t.accepts(event)]
    if not selected:
        return []
    secret = None
    if secret_map and event.provider:
        secret = secret_map.get(event.provider)

    def deliver(target: ForwardTarget) -> ForwardResult:
        request = build_replay_request(
            event, target.url, provider=event.provider, secret=secret, scheme=scheme
        )
        with make_client(timeout=timeout, transport=transport) as client:
            result = _deliver(client, request, retries, backoff)
        result.target = target.label
        if on_result is not None:
            on_result(target, result)
        return result

    results: list[ForwardResult | None] = [None] * len(selected)
    with ThreadPoolExecutor(max_workers=len(selected), thread_name_prefix="forward") as pool:
        futures = {pool.submit(deliver, target): index for index, target in enumerate(selected)}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return [r for r in results if r is not None]


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
                last_error = f"HTTP {response.status_code}"
                break
            last_error = f"HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            last_error = str(exc) or type(exc).__name__
        if attempt < retries:
            time.sleep(backoff * (attempt + 1))
    elapsed = (time.perf_counter() - start) * 1000
    return ForwardResult(request.url, False, last_status, attempts, elapsed, error=last_error)
