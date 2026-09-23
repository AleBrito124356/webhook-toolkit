#!/usr/bin/env python
"""webhook-toolkit command-line interface.

Commands
--------
  serve      Run the receiver, live console and web inspector.
  forward    Run the receiver and fan-out every capture to local dev URLs.
  replay     Replay a stored event to a target URL, optionally re-signing it.
  verify     Check a payload + signature pair for any supported provider.
  list       Show recent captured events.
  export     Write all stored events to a JSON fixture file.
  import     Load events from a JSON fixture file.

Run ``python cli.py <command> --help`` for per-command options.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make ``src`` importable when running the script directly from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402

from src.webhooks import config  # noqa: E402
from src.webhooks import fixtures  # noqa: E402
from src.webhooks.replay import replay_event  # noqa: E402
from src.webhooks.server import serve  # noqa: E402
from src.webhooks.storage import Storage  # noqa: E402
from src.webhooks.verify import PROVIDERS, SLACK_TIMESTAMP_HEADER, verify_request  # noqa: E402

console = Console()


def _read_payload(source: str) -> bytes:
    """Read a payload from a file path, or from stdin when ``source`` is ``-``."""
    if source == "-":
        return sys.stdin.buffer.read()
    return Path(source).read_bytes()


def _parse_headers(pairs: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for pair in pairs or []:
        if ":" not in pair:
            raise SystemExit(f"invalid --header {pair!r}; expected 'Name: value'")
        name, _, value = pair.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def _resolve_secret(provider: str, *, purpose: str) -> str | None:
    """Return the configured secret for an explicit action, or print why not.

    Placeholder values are accepted with a warning: the bundled example
    handlers use exactly those values, so signing with them is what makes the
    local walkthrough work. They will never match a real provider.
    """
    status = config.secret_status(provider)
    if status.state == "set":
        return status.value
    if status.state == "placeholder":
        console.print(
            f"[yellow]warning: {status.env_var} is set to a placeholder value; "
            f"using it for {purpose}. That only matches handlers configured with "
            f"the same placeholder (like the bundled examples), never a real provider.[/]"
        )
        return status.value
    console.print(
        f"[red]{purpose}: no secret for {provider!r}. {status.env_var} is not set - "
        f"export it, add it to .env (see .env.example), or pass --secret.[/]"
    )
    return None


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------
def cmd_serve(args: argparse.Namespace) -> int:
    serve(args.db, host=args.host, port=args.port, forward_targets=args.forward)
    return 0


def cmd_forward(args: argparse.Namespace) -> int:
    serve(args.db, host=args.host, port=args.port, forward_targets=args.to)
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    storage = Storage(args.db)
    event = storage.get(args.id)
    if event is None:
        console.print(f"[red]No event with id {args.id} in {args.db}[/]")
        return 1

    provider = args.provider or event.provider
    secret = args.secret
    if secret is None and args.sign:
        if not provider:
            console.print(
                f"[red]--sign: event #{args.id} has no detected provider, so there is "
                f"no signature scheme to apply. Pass --provider.[/]"
            )
            return 2
        secret = _resolve_secret(provider, purpose="--sign")
        if secret is None:
            return 2
    override_body = _read_payload(args.body) if args.body else None
    extra_headers = _parse_headers(args.header)

    result = replay_event(
        event,
        args.to,
        provider=provider,
        secret=secret.encode("utf-8") if secret else None,
        override_body=override_body,
        extra_headers=extra_headers,
        timeout=args.timeout,
    )

    tag = "[green]OK[/]" if result.ok else "[red]FAIL[/]"
    resign = " [dim](re-signed)[/]" if result.resigned else ""
    console.print(
        f"{tag} replay #{args.id} -> {result.url}{resign} "
        f"[dim]| status {result.status_code} | {result.elapsed_ms:.0f} ms[/]"
    )
    if result.error:
        console.print(f"  [red]{result.error}[/]")
    elif result.response_snippet:
        console.print(f"  [dim]{result.response_snippet}[/]")
    return 0 if result.ok else 1


def cmd_verify(args: argparse.Namespace) -> int:
    if args.provider not in PROVIDERS:
        console.print(f"[red]Unknown provider {args.provider!r}[/]")
        return 2
    spec = PROVIDERS[args.provider]
    secret = args.secret
    if secret is None:
        secret = _resolve_secret(args.provider, purpose="verify")
        if secret is None:
            return 2

    body = _read_payload(args.payload)
    headers = {spec.signature_header: args.signature}
    if spec.needs_timestamp and args.timestamp is not None and args.provider == "slack":
        headers[SLACK_TIMESTAMP_HEADER] = str(args.timestamp)

    result = verify_request(
        args.provider,
        secret.encode("utf-8"),
        body,
        headers,
        tolerance=args.tolerance,
        now=args.now,
    )
    if result.ok:
        console.print(f"[green]VALID[/] {spec.label} signature ({result.reason})")
        return 0
    console.print(f"[red]INVALID[/] {spec.label} signature ({result.reason})")
    return 1


def cmd_list(args: argparse.Namespace) -> int:
    storage = Storage(args.db)
    events = storage.list(limit=args.limit)
    if not events:
        console.print("[dim]No events captured yet.[/]")
        return 0
    table = Table(title=f"{storage.count()} events in {args.db}")
    table.add_column("id", justify="right")
    table.add_column("method")
    table.add_column("path", overflow="fold")
    table.add_column("provider")
    table.add_column("verified")
    table.add_column("received_at")
    verdict = {1: "[green]yes[/]", 0: "[red]no[/]", None: "[yellow]-[/]"}
    for event in events:
        table.add_row(
            str(event.id),
            event.method,
            event.path,
            event.provider or "-",
            verdict[event.verified],
            event.received_at,
        )
    console.print(table)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    storage = Storage(args.db)
    count = fixtures.export_to_file(storage, args.file)
    console.print(f"[green]Exported {count} events[/] -> {args.file}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    storage = Storage(args.db)
    count = fixtures.import_from_file(storage, args.file)
    console.print(f"[green]Imported {count} events[/] from {args.file}")
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhook-toolkit",
        description="Receive, verify, inspect and replay webhooks locally.",
    )
    env_help = (
        "load environment variables from FILE (default: ./.env when present); "
        "variables already set in the shell take precedence"
    )
    parser.add_argument("--env-file", metavar="FILE", help=env_help)
    # Also accept --env-file after the sub-command without clobbering a value
    # given before it.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--env-file", metavar="FILE", default=argparse.SUPPRESS, help=env_help)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_parser(name: str, **kwargs) -> argparse.ArgumentParser:
        return sub.add_parser(name, parents=[common], **kwargs)

    def add_db(p: argparse.ArgumentParser) -> None:
        p.add_argument("--db", default=config.DEFAULT_DB, help="SQLite database path")

    p_serve = add_parser("serve", help="run the receiver and inspector")
    add_db(p_serve)
    p_serve.add_argument("--host", default=config.DEFAULT_HOST)
    p_serve.add_argument("--port", type=int, default=config.DEFAULT_PORT)
    p_serve.add_argument(
        "--forward", action="append", default=[], metavar="URL",
        help="also fan-out each capture to URL (repeatable)",
    )
    p_serve.set_defaults(func=cmd_serve)

    p_forward = add_parser("forward", help="receive and fan-out to local URLs")
    add_db(p_forward)
    p_forward.add_argument("--host", default=config.DEFAULT_HOST)
    p_forward.add_argument("--port", type=int, default=config.DEFAULT_PORT)
    p_forward.add_argument(
        "--to", action="append", required=True, metavar="URL",
        help="forward target URL (repeatable, at least one)",
    )
    p_forward.set_defaults(func=cmd_forward)

    p_replay = add_parser("replay", help="replay a stored event to a URL")
    add_db(p_replay)
    p_replay.add_argument("id", type=int, help="stored event id")
    p_replay.add_argument("--to", required=True, metavar="URL", help="target URL")
    p_replay.add_argument("--provider", choices=sorted(PROVIDERS), help="override detected provider")
    p_replay.add_argument("--secret", help="signing secret (implies re-signing)")
    p_replay.add_argument("--sign", action="store_true", help="re-sign using the env secret")
    p_replay.add_argument("--body", metavar="FILE", help="replace the body with FILE (modify-then-replay)")
    p_replay.add_argument("--header", action="append", default=[], metavar="'Name: value'",
                          help="add/override a header (repeatable)")
    p_replay.add_argument("--timeout", type=float, default=10.0)
    p_replay.set_defaults(func=cmd_replay)

    p_verify = add_parser("verify", help="check a payload + signature pair")
    p_verify.add_argument("--provider", required=True, choices=sorted(PROVIDERS))
    p_verify.add_argument("--payload", required=True, metavar="FILE", help="payload file, or - for stdin")
    p_verify.add_argument("--signature", required=True, help="the provider signature header value")
    p_verify.add_argument("--secret", help="signing secret (defaults to the provider env var)")
    p_verify.add_argument("--timestamp", type=int, help="Slack request timestamp (X-Slack-Request-Timestamp)")
    p_verify.add_argument("--tolerance", type=int, default=config.DEFAULT_TOLERANCE,
                          help="timestamp tolerance in seconds; 0 disables the time check")
    p_verify.add_argument("--now", type=int, help="override the current epoch time (testing)")
    p_verify.set_defaults(func=cmd_verify)

    p_list = add_parser("list", help="show recent captured events")
    add_db(p_list)
    p_list.add_argument("--limit", type=int, default=50)
    p_list.set_defaults(func=cmd_list)

    p_export = add_parser("export", help="export stored events to a fixture")
    add_db(p_export)
    p_export.add_argument("file", help="output JSON file")
    p_export.set_defaults(func=cmd_export)

    p_import = add_parser("import", help="import events from a fixture")
    add_db(p_import)
    p_import.add_argument("file", help="input JSON file")
    p_import.set_defaults(func=cmd_import)

    return parser


def _load_env(argv: list[str]) -> int:
    """Load ``--env-file`` (or ./.env) *before* building the parser.

    Defaults such as ``--db`` and ``--port`` come from the environment, so the
    file has to be applied first. Returns a non-zero exit code on failure.
    """
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--env-file")
    known, _ = pre.parse_known_args(argv)
    try:
        config.load_env_file(known.env_file)
    except (FileNotFoundError, UnicodeDecodeError) as exc:
        console.print(f"[red]{exc}[/]")
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    status = _load_env(argv)
    if status:
        return status
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
