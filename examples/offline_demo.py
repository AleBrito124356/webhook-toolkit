#!/usr/bin/env python
"""One-command offline demo of the whole webhook loop — no tunnel, no provider.

    python examples/offline_demo.py

It starts, on ephemeral loopback ports only:

* the webhook-toolkit receiver (with a temporary database),
* the example GitHub push handler and Stripe payment handler,

generates fresh random signing secrets for this run, and then exercises every
feature against them: all bundled samples are signed and delivered, the
receiver's diagnosis is checked on tampered/stale/wrongly-signed deliveries,
stored events are replayed (with and without re-signing, and with an edited
body) to the real handlers, samples are sent straight to the handlers, the
inspector's JSON API is driven like the browser does (filters, diagnosis,
replay, curl, the cross-site guard), and a second receiver fans every capture
out to both handlers plus a failing target.

Every step prints the equivalent CLI command. The script ends with a pass/fail
summary and exits 0 only when every check passed.
"""

from __future__ import annotations

import importlib
import json
import os
import secrets
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))  # for examples.handlers
sys.path.insert(0, str(REPO_ROOT / "src"))  # for the webhooks package

import httpx  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.markup import escape  # noqa: E402

from webhooks import config  # noqa: E402
from webhooks._stdio import ensure_utf8_stdio  # noqa: E402
from webhooks import samples  # noqa: E402
from webhooks.replay import replay_event, send_replay  # noqa: E402
from webhooks.server import create_app  # noqa: E402
from webhooks.storage import Storage  # noqa: E402
from webhooks.testing import BackgroundServer  # noqa: E402

console = Console(highlight=False, soft_wrap=True)


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


class Report:
    def __init__(self) -> None:
        self.checks: list[Check] = []

    def section(self, title: str, command: str | None = None) -> None:
        console.rule(f"[bold]{title}")
        if command:
            console.print(f"[dim]$ {escape(command)}[/]")

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append(Check(name, ok, detail))
        tag = "[green]PASS[/]" if ok else "[red]FAIL[/]"
        console.print(f"{tag} {escape(name)}" + (f" [dim]- {escape(detail)}[/]" if detail else ""))
        return ok

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]


def _demo_secrets() -> dict[str, str]:
    """Fresh, random, obviously-local secrets for this run only."""
    return {
        "github": "demo-" + secrets.token_hex(16),
        "stripe": "whsec_demo" + secrets.token_hex(16),
        "slack": "demo" + secrets.token_hex(16),
        "shopify": "shpss_demo" + secrets.token_hex(16),
    }


def _load_handler(name: str, secret: str):
    module = importlib.import_module(f"examples.handlers.{name}")
    module.SECRET = secret  # explicit, whatever the environment said at import
    return module


def _json(result) -> dict:
    try:
        return json.loads(result.response_snippet)
    except ValueError:
        return {}


def run(report: Report) -> None:
    demo = _demo_secrets()
    for provider, value in demo.items():
        os.environ[config.SECRET_ENV[provider]] = value
    os.environ["WEBHOOK_TIMESTAMP_TOLERANCE"] = "300"

    github_handler = _load_handler("github_push_handler", demo["github"])
    stripe_handler = _load_handler("stripe_payment_handler", demo["stripe"])

    workdir = tempfile.TemporaryDirectory(prefix="webhook-toolkit-demo-")
    db_path = str(Path(workdir.name) / "demo.db")
    storage = Storage(db_path)

    with BackgroundServer(create_app(db_path)) as receiver, BackgroundServer(
        github_handler.app
    ) as gh, BackgroundServer(stripe_handler.app) as st:
        console.print(f"receiver       {receiver.url}   (inspector: {receiver.url}/)")
        console.print(f"github handler {gh.url}/webhooks/github")
        console.print(f"stripe handler {st.url}/webhooks/stripe")
        console.print(f"database       {db_path}")

        # 1. Every sample, signed, through the receiver ------------------------
        report.section(
            "1. Every sample is detected and verified by the receiver",
            f"python cli.py send <provider> <event> --to {receiver.url} --sign",
        )
        stored_ids: dict[str, int] = {}
        for template in samples.list_samples():
            rendered = samples.render_sample(template)
            request = samples.build_sample_request(
                rendered, receiver.url, secret=demo[template.provider]
            )
            result = send_replay(request, timeout=10)
            data = _json(result)
            ok = result.status_code == 200 and data.get("provider") == template.provider and data.get("verified") == 1
            report.check(
                f"{template.provider}/{template.event}",
                ok,
                f"#{data.get('id')} {data.get('reason')}" if data else (result.error or str(result.status_code)),
            )
            stored_ids[f"{template.provider}/{template.event}"] = data.get("id")

        # 2. The receiver explains what is wrong ------------------------------
        report.section("2. Broken deliveries are explained, not just rejected")
        push = samples.render_sample(samples.get_sample("github", "push"))
        request = samples.build_sample_request(push, receiver.url, secret=demo["github"])
        request.body += b"\n"  # an editor/tool appended a newline after signing
        data = _json(send_replay(request))
        report.check(
            "tampered GitHub push (newline appended after signing)",
            data.get("verified") == 0 and "trailing newline removed" in (data.get("reason") or ""),
            data.get("reason", ""),
        )

        order = samples.render_sample(samples.get_sample("shopify", "orders/create"))
        request = samples.build_sample_request(order, receiver.url, secret="not-the-shop-secret")
        data = _json(send_replay(request))
        report.check(
            "Shopify order signed with the wrong secret",
            data.get("verified") == 0 and data.get("reason") == "signature does not match this body and secret",
            data.get("reason", ""),
        )

        hour_ago = int(time.time()) - 3600
        payment = samples.render_sample(
            samples.get_sample("stripe", "payment_intent.succeeded"), now=hour_ago
        )
        request = samples.build_sample_request(
            payment, receiver.url, secret=demo["stripe"], now=hour_ago
        )
        data = _json(send_replay(request))
        stale_id = data.get("id")
        report.check(
            "Stripe payment signed an hour ago",
            data.get("verified") == 0 and (data.get("reason") or "").startswith("timestamp is 360"),
            data.get("reason", ""),
        )

        # 3. Replay stored events to the real handlers ----------------------------
        report.section(
            "3. Replay stored events to the example handlers",
            f"python cli.py replay {stale_id} --to {st.url}/webhooks/stripe [--sign]",
        )
        stale = storage.get(stale_id)
        result = replay_event(stale, f"{st.url}/webhooks/stripe")
        report.check(
            "stale Stripe event replayed as-is is rejected (timestamp tolerance)",
            result.status_code == 400,
            f"status {result.status_code}",
        )
        result = replay_event(stale, f"{st.url}/webhooks/stripe", secret=demo["stripe"])
        report.check(
            "the same event re-signed with a fresh timestamp is accepted",
            result.status_code == 200 and result.resigned,
            f"status {result.status_code} {result.response_snippet}",
        )

        push_event = storage.get(stored_ids["github/push"])
        result = replay_event(push_event, f"{gh.url}/webhooks/github", secret=demo["github"])
        report.check(
            "stored GitHub push replayed (re-signed) to the push handler",
            result.status_code == 200 and _json(result).get("commits") == 1,
            f"status {result.status_code} {result.response_snippet}",
        )

        edited = json.loads(push_event.body)
        edited["commits"].append(dict(edited["commits"][0], message="Second commit, added while replaying"))
        result = replay_event(
            push_event,
            f"{gh.url}/webhooks/github",
            secret=demo["github"],
            override_body=json.dumps(edited).encode("utf-8"),
        )
        report.check(
            "modify-then-replay: edited push body, re-signed, accepted",
            result.status_code == 200 and _json(result).get("commits") == 2,
            f"status {result.status_code} {result.response_snippet}",
        )
        result = replay_event(
            push_event, f"{gh.url}/webhooks/github", override_body=json.dumps(edited).encode("utf-8")
        )
        report.check(
            "the edited body without re-signing is rejected by the handler",
            result.status_code == 401,
            f"status {result.status_code}",
        )

        # 4. Samples straight to the handlers ---------------------------------------
        report.section(
            "4. Samples sent straight to the handlers",
            f"python cli.py send stripe payment_intent.payment_failed --to {st.url}/webhooks/stripe --sign",
        )
        for provider, event, url in [
            ("github", "push", f"{gh.url}/webhooks/github"),
            ("github", "ping", f"{gh.url}/webhooks/github"),
            ("stripe", "payment_intent.payment_failed", f"{st.url}/webhooks/stripe"),
            ("stripe", "checkout.session.completed", f"{st.url}/webhooks/stripe"),
        ]:
            rendered = samples.render_sample(samples.get_sample(provider, event))
            result = send_replay(samples.build_sample_request(rendered, url, secret=demo[provider]))
            report.check(f"{provider}/{event} -> handler", result.status_code == 200, result.response_snippet)

        overridden = samples.render_sample(
            samples.get_sample("stripe", "payment_intent.succeeded"),
            overrides=["data.object.amount=125000", "data.object.currency=eur"],
        )
        result = send_replay(
            samples.build_sample_request(overridden, f"{st.url}/webhooks/stripe", secret=demo["stripe"])
        )
        report.check(
            "--set overrides change the body and the signature still verifies",
            result.status_code == 200,
            "amount=125000 currency=eur",
        )

        # 5. The inspector's JSON API ---------------------------------------------
        report.section("5. The inspector API: filters, diagnosis, replay, curl", f"open {receiver.url}/")
        listing = httpx.get(f"{receiver.url}/api/events", params={"limit": 1}).json()
        report.check(
            "GET /api/events reports the true total",
            listing.get("count") == storage.count(),
            f"{listing.get('count')} events stored",
        )
        invalid = httpx.get(f"{receiver.url}/api/events", params={"verified": "0"}).json()
        report.check(
            "filter verified=0 returns exactly the three broken deliveries",
            invalid.get("count") == 3,
            ", ".join(f"#{e['id']} {e['path']}" for e in invalid.get("events", [])),
        )
        detail = httpx.get(f"{receiver.url}/api/events/{stale_id}").json()
        diagnosis = (detail.get("assessment") or {}).get("diagnosis") or {}
        report.check(
            "event detail carries the diagnosis and its hints",
            diagnosis.get("code") == "timestamp_out_of_tolerance" and bool(diagnosis.get("hints")),
            diagnosis.get("hints", [""])[0][:90],
        )
        edited_payment = json.loads(stale.body)
        edited_payment["data"]["object"]["amount"] = 4200
        replayed = httpx.post(
            f"{receiver.url}/api/events/{stale_id}/replay",
            json={"to": f"{st.url}/webhooks/stripe", "sign": True, "body": json.dumps(edited_payment)},
            timeout=15,
        ).json()
        report.check(
            "POST /api/events/{id}/replay: edited, re-signed, accepted (what the Replay button does)",
            replayed.get("status_code") == 200 and replayed.get("resigned") is True,
            f"status {replayed.get('status_code')} {replayed.get('response_snippet', '')}",
        )
        curl = httpx.post(
            f"{receiver.url}/api/events/{stale_id}/curl",
            json={"to": f"{st.url}/webhooks/stripe", "sign": True},
        ).json()
        report.check(
            "POST /api/events/{id}/curl renders the replay as a curl command",
            curl.get("curl", "").startswith("curl -sS -X POST") and "Stripe-Signature: t=" in curl.get("curl", ""),
        )
        refused = httpx.delete(f"{receiver.url}/api/events", headers={"Origin": "http://evil.example"})
        report.check(
            "a cross-site page cannot clear the captures",
            refused.status_code == 403 and storage.count() == listing.get("count"),
            f"status {refused.status_code}",
        )

        # 6. Fan-out forwarding --------------------------------------------------------
        flaky = FastAPI()

        @flaky.post("/flaky")
        async def always_unavailable():
            return JSONResponse({"detail": "maintenance"}, status_code=503)

        fan_db = str(Path(workdir.name) / "forward.db")
        with BackgroundServer(flaky) as down:
            targets = [
                f"github={gh.url}/webhooks/github",
                f"stripe={st.url}/webhooks/stripe",
                f"{down.url}/flaky",
            ]
            report.section(
                "6. Fan-out: one receiver feeding both handlers (and a failing one)",
                "python cli.py forward --to github=" + targets[0].split("=", 1)[1]
                + " --to stripe=" + targets[1].split("=", 1)[1] + " --to " + targets[2],
            )
            fan_app = create_app(fan_db, forward_targets=targets, forward_retries=1, forward_backoff=0.05)
            with BackgroundServer(fan_app) as fan:
                for provider, event in (("github", "push"), ("stripe", "payment_intent.succeeded")):
                    rendered = samples.render_sample(samples.get_sample(provider, event))
                    send_replay(samples.build_sample_request(rendered, fan.url, secret=demo[provider]))
                deadline = time.monotonic() + 10
                while True:
                    stats = {t["target"]: t for t in httpx.get(f"{fan.url}/api/forward").json()["targets"]}
                    done = sum(t["delivered"] + t["failed"] for t in stats.values())
                    if done >= 4 or time.monotonic() > deadline:
                        break
                    time.sleep(0.05)
            gh_stats, st_stats, down_stats = (stats[t] for t in targets)
            report.check(
                "github= target got only the GitHub event",
                gh_stats["delivered"] == 1 and gh_stats["failed"] == 0,
                f"delivered {gh_stats['delivered']}, last status {gh_stats['last_status']}",
            )
            report.check(
                "stripe= target got only the Stripe event",
                st_stats["delivered"] == 1 and st_stats["failed"] == 0,
                f"delivered {st_stats['delivered']}, last status {st_stats['last_status']}",
            )
            report.check(
                "a 503 target is retried, counted as failed, and does not block the others",
                down_stats["failed"] == 2 and down_stats["last_error"] == "HTTP 503",
                f"failed {down_stats['failed']}, last error {down_stats['last_error']}",
            )
    workdir.cleanup()


def main() -> int:
    ensure_utf8_stdio()
    report = Report()
    started = time.perf_counter()
    try:
        run(report)
    except Exception as exc:  # a crash is a failed demo, with the reason shown
        report.check("demo completed without errors", False, f"{type(exc).__name__}: {exc}")
    elapsed = time.perf_counter() - started
    console.rule("[bold]Summary")
    passed = len(report.checks) - len(report.failed)
    colour = "green" if not report.failed else "red"
    console.print(
        f"[{colour}]{passed}/{len(report.checks)} checks passed[/] in {elapsed:.1f} s, "
        f"loopback only, no tunnel and no provider account."
    )
    for check in report.failed:
        console.print(f"[red]failed:[/] {escape(check.name)} [dim]{escape(check.detail)}[/]")
    return 0 if not report.failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
