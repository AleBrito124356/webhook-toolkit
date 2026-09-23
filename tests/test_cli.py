"""CLI commands driven through ``main([...])``, end to end where it matters."""

import os

import pytest

from webhooks import cli
from _helpers import REPO_ROOT, load_handler
from webhooks import verify
from webhooks.storage import Storage, StoredEvent
from webhooks.testing import BackgroundServer

DEMO_SECRET = "cli" + "-" + "demo" + "-" + "secret"
STRIPE_PLACEHOLDER = "whsec_" + "X" * 28
GITHUB_PLACEHOLDER = "use-a-long-random-string-here"
STRIPE_BODY = (
    b'{"id": "evt_test", "type": "payment_intent.succeeded", '
    b'"data": {"object": {"id": "pi_test", "amount": 2000, "currency": "usd"}}}'
)


@pytest.fixture()
def db(tmp_path):
    return str(tmp_path / "cli.db")


def _store_stripe_event(db, *, signed_at=1_600_000_000):
    storage = Storage(db)
    header = verify.sign_stripe("whatever-the-provider-used", STRIPE_BODY, signed_at)
    return storage.insert(
        StoredEvent(
            method="POST",
            path="/webhooks/stripe",
            headers={"content-type": "application/json", "stripe-signature": header},
            body=STRIPE_BODY,
            provider="stripe",
        )
    )


# --- .env handling --------------------------------------------------------------
def _write_github_payload(tmp_path, secret):
    payload = tmp_path / "payload.json"
    payload.write_bytes(b'{"zen": "Keep it logically awesome."}')
    return payload, verify.sign_github(secret, payload.read_bytes())


def test_verify_reads_secret_from_dotenv_in_cwd(tmp_path, capsys):
    payload, signature = _write_github_payload(tmp_path, DEMO_SECRET)
    (tmp_path / ".env").write_text(f"GITHUB_WEBHOOK_SECRET={DEMO_SECRET}\n", encoding="utf-8")
    code = cli.main(["verify", "--provider", "github", "--payload", str(payload), "--signature", signature])
    assert code == 0
    assert "VALID" in capsys.readouterr().out


@pytest.mark.parametrize("position", ["before", "after"])
def test_env_file_option_in_either_position(tmp_path, capsys, position):
    payload, signature = _write_github_payload(tmp_path, DEMO_SECRET)
    env_file = tmp_path / "custom.env"
    env_file.write_text(f'GITHUB_WEBHOOK_SECRET="{DEMO_SECRET}"\n', encoding="utf-8")
    command = ["verify", "--provider", "github", "--payload", str(payload), "--signature", signature]
    argv = ["--env-file", str(env_file), *command] if position == "before" else [*command, "--env-file", str(env_file)]
    assert cli.main(argv) == 0


def test_missing_env_file_is_a_usage_error(tmp_path, capsys):
    assert cli.main(["--env-file", str(tmp_path / "missing.env"), "list"]) == 2
    assert "env file not found" in capsys.readouterr().err


def test_verify_with_placeholder_secret_warns_and_still_checks(tmp_path, capsys):
    os.environ["GITHUB_WEBHOOK_SECRET"] = GITHUB_PLACEHOLDER
    payload, signature = _write_github_payload(tmp_path, GITHUB_PLACEHOLDER)
    code = cli.main(["verify", "--provider", "github", "--payload", str(payload), "--signature", signature])
    captured = capsys.readouterr()
    assert code == 0
    assert "VALID" in captured.out
    assert "placeholder" in captured.err  # warnings go to stderr


def test_verify_without_any_secret_says_the_variable_is_not_set(tmp_path, capsys):
    payload, signature = _write_github_payload(tmp_path, DEMO_SECRET)
    code = cli.main(["verify", "--provider", "github", "--payload", str(payload), "--signature", signature])
    assert code == 2
    assert "GITHUB_WEBHOOK_SECRET is not set" in capsys.readouterr().err


# --- replay --sign against the real example handlers ---------------------------
def test_replay_sign_with_placeholder_reaches_stripe_example_handler(db, capsys):
    # The documented walkthrough: handler and toolkit both on the .env.example
    # placeholder. This used to fail with 400 because --sign refused to sign.
    os.environ["STRIPE_WEBHOOK_SECRET"] = STRIPE_PLACEHOLDER
    handler = load_handler("stripe_payment_handler", secret=STRIPE_PLACEHOLDER)
    event_id = _store_stripe_event(db)
    with BackgroundServer(handler.app) as server:
        code = cli.main(
            ["replay", str(event_id), "--db", db, "--to", server.url + "/webhooks/stripe", "--sign"]
        )
    captured = capsys.readouterr()
    assert code == 0, captured
    assert "status 200" in captured.out and "re-signed" in captured.out
    assert "placeholder" in captured.err  # the user is warned


def test_replay_without_sign_is_rejected_by_stripe_handler(db, capsys):
    handler = load_handler("stripe_payment_handler", secret=DEMO_SECRET)
    event_id = _store_stripe_event(db)
    with BackgroundServer(handler.app) as server:
        code = cli.main(["replay", str(event_id), "--db", db, "--to", server.url + "/webhooks/stripe"])
    assert code == 1
    assert "status 400" in capsys.readouterr().out


def test_replay_sign_with_real_secret_reaches_github_example_handler(db, capsys):
    os.environ["GITHUB_WEBHOOK_SECRET"] = DEMO_SECRET
    handler = load_handler("github_push_handler", secret=DEMO_SECRET)
    cli.main(["import", str(REPO_ROOT / "examples" / "fixtures" / "github_push.json"), "--db", db])
    with BackgroundServer(handler.app) as server:
        code = cli.main(["replay", "1", "--db", db, "--to", server.url + "/webhooks/github", "--sign"])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "status 200" in out


def test_replay_sign_without_secret_fails_fast(db, capsys):
    event_id = _store_stripe_event(db)
    code = cli.main(["replay", str(event_id), "--db", db, "--to", "http://127.0.0.1:9/x", "--sign"])
    assert code == 2
    assert "STRIPE_WEBHOOK_SECRET is not set" in capsys.readouterr().err


def test_replay_sign_needs_a_provider(db, capsys):
    Storage(db).insert(StoredEvent(method="POST", path="/x", headers={}, body=b"{}"))
    code = cli.main(["replay", "1", "--db", db, "--to", "http://127.0.0.1:9/x", "--sign"])
    assert code == 2
    assert "--provider" in capsys.readouterr().err


def test_replay_unknown_id(db, capsys):
    assert cli.main(["replay", "99", "--db", db, "--to", "http://127.0.0.1:9/x"]) == 1


# --- verify diagnostics: the five scenarios that used to print the same sentence --
def _verify(tmp_path, capsys, provider, body, *extra):
    payload = tmp_path / "body.bin"
    payload.write_bytes(body)
    code = cli.main(["verify", "--provider", provider, "--payload", str(payload), *extra])
    return code, capsys.readouterr()


def test_verify_explains_trailing_newline(tmp_path, capsys):
    body = b'{"ref":"refs/heads/main"}'
    signature = verify.sign_github(DEMO_SECRET, body)
    code, out = _verify(tmp_path, capsys, "github", body + b"\n", "--signature", signature, "--secret", DEMO_SECRET)
    assert code == 1
    assert "signature matches the payload with the trailing newline removed" in out.out
    assert "code: mismatch" in out.out


def test_verify_explains_wrong_secret(tmp_path, capsys):
    body = b'{"ref":"refs/heads/main"}'
    signature = verify.sign_github("the-senders-secret", body)
    code, out = _verify(tmp_path, capsys, "github", body, "--signature", signature, "--secret", DEMO_SECRET)
    assert code == 1
    assert "signature does not match this body and secret" in out.out
    assert "No common mistake explains it" in out.out


def test_verify_explains_stale_stripe_signature(tmp_path, capsys):
    now = 1_760_000_000
    signature = verify.sign_stripe(DEMO_SECRET, STRIPE_BODY, now - 3600)
    code, out = _verify(
        tmp_path, capsys, "stripe", STRIPE_BODY,
        "--signature", signature, "--secret", DEMO_SECRET, "--now", str(now),
    )
    assert code == 1
    assert "timestamp is 3600 s old, tolerance 300 s" in out.out
    assert "timestamp skew: 3600 s" in out.out
    # Same capture, time check disabled -> valid.
    code, out = _verify(
        tmp_path, capsys, "stripe", STRIPE_BODY,
        "--signature", signature, "--secret", DEMO_SECRET, "--now", str(now), "--tolerance", "0",
    )
    assert code == 0


def test_verify_explains_slack_without_timestamp(tmp_path, capsys):
    now = 1_760_000_000
    signature = verify.sign_slack(DEMO_SECRET, b"token=x&command=/deploy", now)
    code, out = _verify(
        tmp_path, capsys, "slack", b"token=x&command=/deploy",
        "--signature", signature, "--secret", DEMO_SECRET, "--now", str(now),
    )
    assert code == 1
    assert "no X-Slack-Request-Timestamp header" in out.out
    code, _ = _verify(
        tmp_path, capsys, "slack", b"token=x&command=/deploy", "--signature", signature,
        "--secret", DEMO_SECRET, "--now", str(now), "--timestamp", str(now),
    )
    assert code == 0


def test_verify_generic_provider_with_options(tmp_path, capsys):
    scheme = verify.GenericScheme("X-Acme-Signature", "sha512", "base64", "sha512=")
    body = b'{"order": 42}'
    signature = verify.sign_generic(DEMO_SECRET, body, scheme)
    args = [
        "--signature", signature, "--secret", DEMO_SECRET, "--signature-header", "X-Acme-Signature",
        "--algorithm", "sha512", "--encoding", "base64", "--prefix", "sha512=",
    ]
    code, out = _verify(tmp_path, capsys, "generic", body, *args)
    assert code == 0 and "VALID Generic HMAC signature" in out.out
    code, out = _verify(tmp_path, capsys, "generic", body, *args[:-2])  # prefix not declared
    assert code == 1
    assert "X-Acme-Signature has an unexpected 'sha512=' prefix" in out.out
    assert "digest itself is correct" in out.out


def test_verify_generic_reads_env_configuration(tmp_path, capsys):
    os.environ["GENERIC_WEBHOOK_HEADER"] = "X-Acme-Signature"
    os.environ["GENERIC_WEBHOOK_ALGORITHM"] = "sha1"
    os.environ["GENERIC_WEBHOOK_SECRET"] = DEMO_SECRET
    body = b"payload"
    signature = verify.sign_hmac(DEMO_SECRET, body, algorithm="sha1")
    code, out = _verify(tmp_path, capsys, "generic", body, "--signature", signature)
    assert code == 0, out
    os.environ["GENERIC_WEBHOOK_ENCODING"] = "base32"
    code, out = _verify(tmp_path, capsys, "generic", body, "--signature", signature)
    assert code == 2 and "GENERIC_WEBHOOK" in out.err


def test_verify_json_output(tmp_path, capsys):
    body = b'{"a":1}'
    signature = verify.sign_github(DEMO_SECRET, body)
    code, out = _verify(tmp_path, capsys, "github", body + b"\r\n", "--signature", signature,
                        "--secret", DEMO_SECRET, "--json")
    import json

    document = json.loads(out.out)
    assert code == 1
    assert document["code"] == "mismatch"
    assert document["reason"] == "signature matches the payload with the trailing CRLF removed"
    assert document["hints"]


def test_verify_extra_header_reveals_legacy_github_signature(tmp_path, capsys):
    body = b'{"a":1}'
    legacy = verify.sign_github_legacy(DEMO_SECRET, body)
    code, out = _verify(tmp_path, capsys, "github", body, "--secret", DEMO_SECRET,
                        "--header", f"X-Hub-Signature: {legacy}")
    assert code == 1
    assert "no X-Hub-Signature-256 header" in out.out
    assert "dropped X-Hub-Signature-256" in out.out


def test_verify_detects_swapped_secrets_from_env(tmp_path, capsys):
    os.environ["SHOPIFY_WEBHOOK_SECRET"] = "shopify-" + DEMO_SECRET
    body = b'{"a":1}'
    signature = verify.sign_github("shopify-" + DEMO_SECRET, body)
    code, out = _verify(tmp_path, capsys, "github", body, "--signature", signature, "--secret", DEMO_SECRET)
    assert code == 1
    assert "secret configured for Shopify (SHOPIFY_WEBHOOK_SECRET)" in out.out


# --- show / list ------------------------------------------------------------------
def test_show_explains_a_stored_capture(db, capsys):
    os.environ["STRIPE_WEBHOOK_SECRET"] = DEMO_SECRET
    event_id = _store_stripe_event(db)  # signed long ago with another secret
    assert cli.main(["show", str(event_id), "--db", db]) == 0
    out = capsys.readouterr().out
    assert "INVALID" in out and "code: timestamp_out_of_tolerance" in out
    assert cli.main(["show", str(event_id), "--db", db, "--tolerance", "0"]) == 0
    assert "code: mismatch" in capsys.readouterr().out


def test_show_json_and_unknown_id(db, capsys):
    import json

    event_id = _store_stripe_event(db)
    assert cli.main(["show", str(event_id), "--db", db, "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["assessment"]["secret_state"] == "unset"
    assert document["assessment"]["reason"] == "not checked: STRIPE_WEBHOOK_SECRET is not set"
    assert cli.main(["show", "404", "--db", db]) == 1


def test_list_shows_reason_column(db, capsys):
    Storage(db).insert(
        StoredEvent(method="POST", path="/x", headers={}, body=b"{}", verify_reason="unsigned: no known signature header")
    )
    assert cli.main(["list", "--db", db]) == 0
    out = capsys.readouterr().out
    assert "reason" in out and "unsigned" in out


def test_list_empty(db, capsys):
    assert cli.main(["list", "--db", db]) == 0
    assert "No events captured yet" in capsys.readouterr().out


def test_cp1252_redirected_output_is_switched_to_utf8(monkeypatch):
    import io
    import sys

    from webhooks._stdio import ensure_utf8_stdio

    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", stream)
    ensure_utf8_stdio()
    stream.write("\u2500 rule \u2026")
    stream.flush()
    assert raw.getvalue().decode("utf-8") == "\u2500 rule \u2026"


# --- serve / forward / export / replay options ------------------------------------------
def test_serve_prints_banner_and_runs_uvicorn(db, capsys, monkeypatch):
    import uvicorn

    calls = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.update(app=app, **kw))
    code = cli.main(["serve", "--db", db, "--port", "8123", "--forward", "github=http://127.0.0.1:3001/webhooks/github"])
    out = capsys.readouterr().out
    assert code == 0
    assert calls["port"] == 8123 and calls["host"] == "127.0.0.1"
    assert "Inspector : http://127.0.0.1:8123/" in out
    assert "Forwarding: github=http://127.0.0.1:3001/webhooks/github" in out


def test_serve_reads_host_and_port_from_env_file(tmp_path, capsys, monkeypatch):
    import uvicorn

    calls = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.update(kw))
    (tmp_path / ".env").write_text("WEBHOOK_PORT=8456\nWEBHOOK_DB=from-env.db\n", encoding="utf-8")
    assert cli.main(["serve"]) == 0
    assert calls["port"] == 8456
    assert "Database  : from-env.db" in capsys.readouterr().out


def test_forward_rejects_invalid_targets(db, capsys):
    assert cli.main(["forward", "--db", db, "--to", "paypal=http://x/y"]) == 2
    assert "invalid forward target" in capsys.readouterr().err


def test_export_writes_a_fixture(db, tmp_path, capsys):
    _store_stripe_event(db)
    out_file = tmp_path / "out.json"
    assert cli.main(["export", str(out_file), "--db", db]) == 0
    import json

    assert json.loads(out_file.read_text(encoding="utf-8"))["count"] == 1
    assert "Exported 1 events" in capsys.readouterr().out


def test_replay_with_edited_body_and_header_file(db, tmp_path, capsys):
    os.environ["STRIPE_WEBHOOK_SECRET"] = DEMO_SECRET
    handler = load_handler("stripe_payment_handler", secret=DEMO_SECRET)
    event_id = _store_stripe_event(db)
    edited = tmp_path / "edited.json"
    edited.write_bytes(STRIPE_BODY.replace(b"2000", b"9900"))
    with BackgroundServer(handler.app) as server:
        code = cli.main([
            "replay", str(event_id), "--db", db, "--to", server.url + "/webhooks/stripe",
            "--sign", "--body", str(edited), "--header", "X-Debug: 1",
        ])
    assert code == 0 and "status 200" in capsys.readouterr().out


def test_replay_generic_provider_resigns_with_env_scheme(db, capsys):
    os.environ.update(GENERIC_WEBHOOK_SECRET=DEMO_SECRET, GENERIC_WEBHOOK_HEADER="X-Acme-Signature")
    Storage(db).insert(StoredEvent(method="POST", path="/acme", headers={}, body=b"{}"))
    port_holder = {}
    from fastapi import FastAPI, Request

    app = FastAPI()

    @app.post("/acme")
    async def acme(request: Request):
        body = await request.body()
        port_holder["ok"] = verify.verify_generic(
            DEMO_SECRET, body, request.headers.get("x-acme-signature"), verify.GenericScheme("X-Acme-Signature")
        )
        return {"ok": port_holder["ok"]}

    with BackgroundServer(app) as server:
        code = cli.main(["replay", "1", "--db", db, "--to", server.url + "/acme", "--provider", "generic", "--sign"])
    assert code == 0 and port_holder["ok"] is True


def test_invalid_header_argument(db):
    _store_stripe_event(db)
    with pytest.raises(SystemExit, match="expected 'Name: value'"):
        cli.main(["replay", "1", "--db", db, "--to", "http://127.0.0.1:9/", "--header", "no-colon"])


def test_verify_reads_payload_from_stdin(monkeypatch, capsys):
    import io

    body = b'{"a":1}'
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(body)))
    signature = verify.sign_github(DEMO_SECRET, body)
    assert cli.main(["verify", "--provider", "github", "--payload", "-", "--signature", signature, "--secret", DEMO_SECRET]) == 0


def test_version_flag(capsys):
    from webhooks import __version__

    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"webhook-toolkit {__version__}"


def test_legacy_src_import_path_still_works_from_the_repo_root():
    import subprocess
    import sys

    code = "import src.webhooks.verify as v; print(v.verify_github('s', b'x', v.sign_github('s', b'x')))"
    result = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True, timeout=60)
    assert result.stdout.strip() == "True", result.stderr
