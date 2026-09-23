"""FastAPI receiver, live console, inspector and its JSON API.

Routes the tool keeps for itself (everything else is captured):

=========================================  ==================================
``GET /``                                  the inline HTML inspector
``GET /favicon.ico``                       inline SVG icon (so the browser's own
                                           favicon request is not captured)
``GET /api/events``                        captures, newest first; filters
                                           ``provider``, ``verified``, ``q``
                                           (path substring), paging with
                                           ``limit``/``offset``
``DELETE /api/events``                     delete every capture
``GET /api/events/{id}``                   one capture + live signature diagnosis
``GET /api/events/{id}/raw``               the exact body bytes (download)
``DELETE /api/events/{id}``                delete one capture
``POST /api/events/{id}/replay``           replay it (JSON: to, sign, secret,
                                           body, headers...)
``POST /api/events/{id}/curl``             the same replay as a curl command
``GET /api/forward``                       per-target forwarding counters
``GET /api/status``                        version, secret states, targets
``ANY /{path}``                            the catch-all receiver
=========================================  ==================================

Because the catch-all is registered last, the explicit routes win only for
their exact path *and* method; e.g. ``POST /api/events`` is still captured.
FastAPI's ``/docs``, ``/redoc`` and ``/openapi.json`` are turned off so those
paths are captured like any other.

The mutating API routes refuse cross-site browser requests (``Origin`` /
``Sec-Fetch-Site`` checks), and replay only accepts ``application/json``, so a
web page you visit cannot make the inspector send requests on your behalf.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx
from fastapi import BackgroundTasks, FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from rich.console import Console
from rich.markup import escape
from starlette.concurrency import run_in_threadpool

from . import __version__, config
from .forward import ForwardResult, ForwardTarget, TargetStats, forward_event
from .inbound import assess
from .inspector import INSPECTOR_HTML
from .replay import ReplayRequest, build_replay_request, send_replay, to_curl
from .storage import Storage, StoredEvent
from .verify import PROVIDERS, GenericScheme, detect_provider

console = Console(soft_wrap=True, highlight=False)

# Methods the receiver accepts. Webhooks are almost always POST, but capturing
# the rest makes the tool useful for debugging arbitrary callbacks too (HEAD
# health checks, CORS preflights, validation GETs).
_RECEIVER_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect width="32" height="32" rx="7" fill="#2563eb"/>'
    '<path d="M9 17.5l4.5 4.5L23 11" fill="none" stroke="#fff" stroke-width="3.2" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


@dataclass
class ServerState:
    storage: Storage
    forward_targets: list[str] = field(default_factory=list)
    verify_inbound: bool = True
    stats: dict[str, TargetStats] = field(default_factory=dict)
    generic: GenericScheme | None = None
    targets: list[ForwardTarget] = field(default_factory=list)
    forward_retries: int = 2
    forward_backoff: float = 0.5
    forward_timeout: float = 5.0
    forward_transport: httpx.BaseTransport | None = None

    def __post_init__(self) -> None:
        self.targets = [ForwardTarget.parse(spec) for spec in self.forward_targets]
        for target in self.targets:
            self.stats.setdefault(target.label, TargetStats(target.label))


class ReplayPayload(BaseModel):
    """Body of ``POST /api/events/{id}/replay`` and ``/curl``."""

    model_config = ConfigDict(extra="forbid")

    to: str
    sign: bool = False
    secret: str | None = None
    provider: str | None = None
    body: str | None = None
    body_base64: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: float = Field(10.0, gt=0, le=120)


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------
def _verify_label(event: StoredEvent) -> str:
    """Console label for a capture's verification state."""
    if event.verified == 1:
        return "[green]verified[/]"
    if event.verified == 0:
        return "[red]invalid[/]"
    if not event.provider:
        return "[dim]unsigned[/]"
    return "[yellow]not checked[/]"


def _log_event(event: StoredEvent) -> None:
    provider = event.provider or "unknown"
    console.print(
        f"[bold cyan]#{event.id}[/] [bold]{event.method}[/] {escape(event.path)} "
        f"[dim]| {provider} |[/] {_verify_label(event)} "
        f"[dim]| {len(event.body)} B | {event.received_at}[/]"
    )
    if event.verified != 1 and event.provider and event.verify_reason:
        console.print(f"   [dim]{escape(event.verify_reason)}[/]")


def _log_forward(event_id: int | None, result: ForwardResult, stats: TargetStats) -> None:
    status = (
        f"[green]{result.status_code} ok[/]"
        if result.ok
        else f"[red]{escape(result.error or str(result.status_code))}[/]"
    )
    attempts = "attempt" if result.attempts == 1 else "attempts"
    console.print(
        f"   forward #{event_id} -> {escape(result.target)} {status} "
        f"[dim]({result.attempts} {attempts}, {result.elapsed_ms:.0f} ms) | "
        f"totals: {stats.delivered} delivered, {stats.failed} failed[/]"
    )


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------
def _error(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


def _refuse_cross_site(request: Request) -> JSONResponse | None:
    """Reject browser requests coming from another site (CSRF guard)."""
    site = request.headers.get("sec-fetch-site")
    if site and site not in ("same-origin", "none"):
        return _error(403, f"cross-site request refused (Sec-Fetch-Site: {site})")
    origin = request.headers.get("origin")
    if origin is not None:
        host = request.headers.get("host", "")
        if origin == "null" or urlsplit(origin).netloc.lower() != host.lower():
            return _error(403, f"cross-origin request refused (Origin: {origin})")
    return None


async def _read_replay_payload(request: Request) -> ReplayPayload | JSONResponse:
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/json":
        return _error(415, "send the replay options as application/json")
    try:
        data = await request.json()
    except ValueError:
        return _error(400, "request body is not valid JSON")
    try:
        payload = ReplayPayload.model_validate(data)
    except ValidationError as exc:
        return JSONResponse({"detail": exc.errors(include_url=False)}, status_code=422)
    target = urlsplit(payload.to)
    if target.scheme not in ("http", "https") or not target.netloc:
        return _error(422, f"'to' must be an http(s) URL, got {payload.to!r}")
    if payload.provider is not None and payload.provider not in PROVIDERS:
        return _error(422, f"unknown provider {payload.provider!r}")
    return payload


def _prepare_replay(
    state: ServerState, event: StoredEvent, payload: ReplayPayload
) -> tuple[ReplayRequest, list[str]] | JSONResponse:
    provider = payload.provider or event.provider
    warnings: list[str] = []
    secret: str | None = payload.secret
    if secret is None and payload.sign:
        if not provider:
            return _error(
                400, f"event #{event.id} has no detected provider; choose one to re-sign it"
            )
        status = config.secret_status(provider)
        if not status.usable:
            return _error(400, f"cannot re-sign: {status.describe()}")
        if status.state == "placeholder":
            warnings.append(
                f"re-signed with the placeholder value of {status.env_var}: only handlers "
                "using the same placeholder will accept it"
            )
        secret = status.value
    override: bytes | None = None
    if payload.body_base64 is not None:
        try:
            override = base64.b64decode(payload.body_base64, validate=True)
        except (binascii.Error, ValueError):
            return _error(400, "body_base64 is not valid base64")
    elif payload.body is not None:
        override = payload.body.encode("utf-8")
    scheme = state.generic
    if provider == "generic" and scheme is None:
        scheme = config.generic_scheme(required=True)
    replay_request = build_replay_request(
        event,
        payload.to,
        provider=provider,
        secret=secret.encode("utf-8") if secret is not None else None,
        override_body=override,
        extra_headers=payload.headers,
        scheme=scheme,
    )
    return replay_request, warnings


def _filters(provider: str | None, verified: str | None, q: str | None) -> dict:
    return {
        "provider": provider or None,
        "verified": verified if verified not in (None, "", "all") else None,
        "path_contains": q or None,
    }


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
def create_app(
    db_path: str,
    *,
    forward_targets: list[str] | None = None,
    verify_inbound: bool = True,
    forward_retries: int = 2,
    forward_backoff: float = 0.5,
    forward_timeout: float = 5.0,
    forward_transport: httpx.BaseTransport | None = None,
) -> FastAPI:
    """Build a configured FastAPI application.

    ``forward_targets`` are ``URL`` or ``provider=URL`` strings. The
    ``forward_*`` knobs tune retries; ``forward_transport`` replaces the HTTP
    transport (tests use ``httpx.MockTransport``).
    """
    # No auto-generated docs: /docs, /redoc and /openapi.json must be captured
    # by the receiver like every other path.
    app = FastAPI(
        title="webhook-toolkit",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    state = ServerState(
        storage=Storage(db_path),
        forward_targets=list(forward_targets or []),
        verify_inbound=verify_inbound,
        # Read once: an invalid GENERIC_WEBHOOK_* setting fails at startup,
        # not on the first request.
        generic=config.generic_scheme(),
        forward_retries=forward_retries,
        forward_backoff=forward_backoff,
        forward_timeout=forward_timeout,
        forward_transport=forward_transport,
    )
    app.state.wt = state

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse(INSPECTOR_HTML, headers={"Cache-Control": "no-store"})

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        return Response(
            FAVICON_SVG,
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    # -- read API ------------------------------------------------------------
    @app.get("/api/events")
    async def api_events(
        limit: int = 100,
        offset: int = 0,
        provider: str | None = None,
        verified: str | None = None,
        q: str | None = None,
        summary: bool = False,
    ) -> JSONResponse:
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        filters = _filters(provider, verified, q)
        try:
            events = state.storage.list(limit=limit, offset=offset, **filters)
            count = state.storage.count(**filters)
        except ValueError as exc:
            return _error(422, str(exc))
        items = []
        for event in events:
            item = event.to_public_dict()
            if summary:
                item.pop("body_text", None)
                item.pop("headers", None)
            items.append(item)
        return JSONResponse(
            {
                "count": count,
                "total": state.storage.count() if any(filters.values()) else count,
                "offset": offset,
                "limit": limit,
                "events": items,
            }
        )

    @app.get("/api/events/{event_id:int}")
    async def api_event(event_id: int) -> JSONResponse:
        event = state.storage.get(event_id)
        if event is None:
            return _error(404, f"no event #{event_id}")
        document = event.to_public_dict()
        document["assessment"] = assess(event, generic=state.generic).to_dict()
        return JSONResponse(document)

    @app.get("/api/events/{event_id:int}/raw")
    async def api_event_raw(event_id: int) -> Response:
        event = state.storage.get(event_id)
        if event is None:
            return _error(404, f"no event #{event_id}")
        # Never serve captured bytes with their own content type on this
        # origin: a captured HTML body must not render as a page here.
        return Response(
            event.body,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="event-{event_id}.bin"',
                "X-Content-Type-Options": "nosniff",
                "X-Original-Content-Type": event.content_type or "",
            },
        )

    @app.get("/api/forward")
    async def api_forward() -> JSONResponse:
        return JSONResponse(
            {"targets": [state.stats[target.label].to_dict() for target in state.targets]}
        )

    @app.get("/api/status")
    async def api_status() -> JSONResponse:
        providers = {}
        for name in PROVIDERS:
            status = config.secret_status(name)
            providers[name] = {"state": status.state, "env_var": status.env_var}
        return JSONResponse(
            {
                "version": __version__,
                "database": state.storage.path,
                "total": state.storage.count(),
                "tolerance": config.DEFAULT_TOLERANCE,
                "providers": providers,
                "generic": (
                    {
                        "signature_header": state.generic.signature_header,
                        "algorithm": state.generic.algorithm,
                        "encoding": state.generic.encoding,
                        "prefix": state.generic.prefix,
                    }
                    if state.generic
                    else None
                ),
                "forward_targets": [target.label for target in state.targets],
            }
        )

    # -- mutating API ---------------------------------------------------------
    @app.delete("/api/events/{event_id:int}")
    async def api_delete_event(event_id: int, request: Request) -> Response:
        refused = _refuse_cross_site(request)
        if refused is not None:
            return refused
        if not state.storage.delete(event_id):
            return _error(404, f"no event #{event_id}")
        return JSONResponse({"deleted": 1, "id": event_id})

    @app.delete("/api/events")
    async def api_clear(request: Request) -> Response:
        refused = _refuse_cross_site(request)
        if refused is not None:
            return refused
        return JSONResponse({"deleted": state.storage.clear()})

    async def _replay_common(event_id: int, request: Request):
        refused = _refuse_cross_site(request)
        if refused is not None:
            return refused
        event = state.storage.get(event_id)
        if event is None:
            return _error(404, f"no event #{event_id}")
        payload = await _read_replay_payload(request)
        if isinstance(payload, JSONResponse):
            return payload
        prepared = _prepare_replay(state, event, payload)
        if isinstance(prepared, JSONResponse):
            return prepared
        replay_request, warnings = prepared
        return event, payload, replay_request, warnings

    @app.post("/api/events/{event_id:int}/replay")
    async def api_replay(event_id: int, request: Request) -> JSONResponse:
        prepared = await _replay_common(event_id, request)
        if isinstance(prepared, JSONResponse):
            return prepared
        _event, payload, replay_request, warnings = prepared
        # Blocking I/O in the threadpool: a replay may target this very server.
        result = await run_in_threadpool(send_replay, replay_request, timeout=payload.timeout)
        result.resigned = replay_request.resigned
        return JSONResponse(
            {
                "ok": result.ok,
                "status_code": result.status_code,
                "url": result.url,
                "elapsed_ms": round(result.elapsed_ms, 1),
                "error": result.error,
                "response_snippet": result.response_snippet,
                "resigned": result.resigned,
                "warnings": warnings,
                "request": {
                    "method": replay_request.method,
                    "url": replay_request.url,
                    "headers": replay_request.headers,
                    "size": len(replay_request.body),
                },
            }
        )

    @app.post("/api/events/{event_id:int}/curl")
    async def api_curl(event_id: int, request: Request) -> JSONResponse:
        prepared = await _replay_common(event_id, request)
        if isinstance(prepared, JSONResponse):
            return prepared
        _event, _payload, replay_request, warnings = prepared
        return JSONResponse(
            {"curl": to_curl(replay_request), "resigned": replay_request.resigned, "warnings": warnings}
        )

    # -- the catch-all receiver -------------------------------------------------
    @app.api_route("/{full_path:path}", methods=_RECEIVER_METHODS)
    async def receive(full_path: str, request: Request, background: BackgroundTasks) -> JSONResponse:
        body = await request.body()
        headers = dict(request.headers)
        query = dict(request.query_params)
        provider = detect_provider(headers, generic=state.generic)

        event = StoredEvent(
            method=request.method,
            path="/" + full_path,
            headers=headers,
            body=body,
            query=query,
            source_ip=request.client.host if request.client else None,
            provider=provider,
        )
        if state.verify_inbound:
            assessment = assess(event, generic=state.generic)
            event.verified = assessment.verified
            event.verify_reason = assessment.reason

        state.storage.insert(event)
        _log_event(event)

        if state.targets:
            background.add_task(forward_and_log, state, event)

        return JSONResponse(
            {
                "status": "received",
                "id": event.id,
                "provider": provider,
                "verified": event.verified,
                "reason": event.verify_reason,
            }
        )

    return app


def forward_and_log(state: ServerState, event: StoredEvent) -> list[ForwardResult]:
    """Fan ``event`` out to the configured targets, updating stats as each ends."""

    def on_result(target: ForwardTarget, result: ForwardResult) -> None:
        stats = state.stats[target.label]
        stats.record(result, event.id)
        _log_forward(event.id, result, stats)

    return forward_event(
        event,
        state.targets,
        retries=state.forward_retries,
        backoff=state.forward_backoff,
        timeout=state.forward_timeout,
        scheme=state.generic,
        transport=state.forward_transport,
        on_result=on_result,
    )


# Backwards-compatible name.
_forward_and_log = forward_and_log


def serve(
    db_path: str,
    *,
    host: str | None = None,
    port: int | None = None,
    forward_targets: list[str] | None = None,
) -> None:
    """Run the receiver with uvicorn (blocking)."""
    import uvicorn

    host = host or config.DEFAULT_HOST
    port = config.DEFAULT_PORT if port is None else port

    app = create_app(db_path, forward_targets=forward_targets)
    targets = app.state.wt.targets
    console.rule("[bold]webhook-toolkit")
    console.print(f"Inspector : [link]http://{host}:{port}/[/]")
    console.print(f"Receiver  : any method on http://{host}:{port}/<any-path>")
    console.print(f"API       : http://{host}:{port}/api/events")
    console.print(f"Database  : {escape(db_path)}")
    if targets:
        console.print(f"Forwarding: {escape(', '.join(t.label for t in targets))}")
    console.rule(style="dim")
    uvicorn.run(app, host=host, port=port, log_level="warning")
