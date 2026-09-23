"""FastAPI receiver, live console and web inspector.

The app exposes:

* ``GET /``            -> the inline HTML inspector
* ``GET /favicon.ico`` -> an inline SVG icon (so browsers do not pollute the
  capture list with their automatic favicon request)
* ``GET /api/events``  -> recent captures as JSON (consumed by the inspector)
* ``ANY /{path}``      -> the catch-all receiver that stores every inbound request

Because the catch-all is registered last, the explicit ``GET`` routes win for
their exact paths while a ``POST /`` (or any other method/path) falls through to
the receiver. FastAPI's ``/docs``, ``/redoc`` and ``/openapi.json`` are turned
off so those paths are captured like any other.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import BackgroundTasks, FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from rich.console import Console
from rich.table import Table

from . import __version__, config
from .forward import TargetStats, forward_event
from .inspector import INSPECTOR_HTML
from .storage import Storage, StoredEvent
from .verify import detect_provider, verify_request

console = Console()

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

    def __post_init__(self) -> None:
        for target in self.forward_targets:
            self.stats.setdefault(target, TargetStats(target))


def _verify_inbound(event: StoredEvent) -> int | None:
    """Return 1/0/None for a captured event using any configured secret.

    * no provider detected, or no secret configured -> ``None``
    * a real secret -> ``1`` / ``0``
    * a placeholder secret -> ``1`` when the capture was signed with that very
      placeholder (a local demo or the bundled fixture), otherwise ``None``: a
      real provider never signs with a placeholder, so "invalid" would mislead.
    """
    if not event.provider:
        return None
    status = config.secret_status(event.provider)
    if not status.usable:
        return None
    result = verify_request(
        event.provider,
        status.value.encode("utf-8"),
        event.body,
        event.headers,
        tolerance=config.DEFAULT_TOLERANCE,
    )
    if result.ok:
        return 1
    return 0 if status.state == "set" else None


def _log_event(event: StoredEvent) -> None:
    verdict = {1: "[green]verified[/]", 0: "[red]invalid[/]", None: "[yellow]no secret[/]"}[
        event.verified
    ]
    provider = event.provider or "unknown"
    console.print(
        f"[bold cyan]#{event.id}[/] [bold]{event.method}[/] {event.path} "
        f"[dim]| {provider} |[/] {verdict} "
        f"[dim]| {len(event.body)} B | {event.received_at}[/]"
    )


def _log_forward(event_id: int, results, stats: dict[str, TargetStats]) -> None:
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("forward #%d -> target" % event_id, overflow="fold")
    table.add_column("status")
    table.add_column("attempts", justify="right")
    for result in results:
        if result.target in stats:
            stats[result.target].record(result)
        status = (
            f"[green]{result.status_code} ok[/]"
            if result.ok
            else f"[red]{result.error or result.status_code}[/]"
        )
        table.add_row(result.target, status, str(result.attempts))
    console.print(table)


def create_app(
    db_path: str,
    *,
    forward_targets: list[str] | None = None,
    verify_inbound: bool = True,
) -> FastAPI:
    """Build a configured FastAPI application."""
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
    )
    app.state.wt = state

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse(INSPECTOR_HTML)

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        return Response(
            FAVICON_SVG,
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/api/events")
    async def api_events(limit: int = 100, offset: int = 0) -> JSONResponse:
        limit = max(1, min(limit, 500))
        events = state.storage.list(limit=limit, offset=max(0, offset))
        return JSONResponse(
            {
                "count": state.storage.count(),
                "events": [event.to_public_dict() for event in events],
            }
        )

    @app.api_route("/{full_path:path}", methods=_RECEIVER_METHODS)
    async def receive(full_path: str, request: Request, background: BackgroundTasks) -> JSONResponse:
        body = await request.body()
        headers = dict(request.headers)
        query = dict(request.query_params)
        provider = detect_provider(headers)

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
            event.verified = _verify_inbound(event)

        state.storage.insert(event)
        _log_event(event)

        if state.forward_targets:
            background.add_task(_forward_and_log, state, event)

        return JSONResponse(
            {
                "status": "received",
                "id": event.id,
                "provider": provider,
                "verified": event.verified,
            }
        )

    return app


def _forward_and_log(state: ServerState, event: StoredEvent) -> None:
    results = forward_event(event, state.forward_targets)
    _log_forward(event.id, results, state.stats)


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
    targets = forward_targets or []
    console.rule("[bold]webhook-toolkit")
    console.print(f"Inspector : [link]http://{host}:{port}/[/]")
    console.print(f"Receiver  : any method on http://{host}:{port}/<any-path>")
    console.print(f"Database  : {db_path}")
    if targets:
        console.print(f"Forwarding: {', '.join(targets)}")
    console.rule(style="dim")
    uvicorn.run(app, host=host, port=port, log_level="warning")
