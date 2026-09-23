"""CLI commands driven through ``main([...])``, end to end where it matters."""

import os

import pytest

import cli
from _helpers import REPO_ROOT, load_handler
from src.webhooks import verify
from src.webhooks.storage import Storage, StoredEvent
from src.webhooks.testing import BackgroundServer

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
    assert "env file not found" in capsys.readouterr().out


def test_verify_with_placeholder_secret_warns_and_still_checks(tmp_path, capsys):
    os.environ["GITHUB_WEBHOOK_SECRET"] = GITHUB_PLACEHOLDER
    payload, signature = _write_github_payload(tmp_path, GITHUB_PLACEHOLDER)
    code = cli.main(["verify", "--provider", "github", "--payload", str(payload), "--signature", signature])
    out = capsys.readouterr().out
    assert code == 0
    assert "placeholder" in out and "VALID" in out


def test_verify_without_any_secret_says_the_variable_is_not_set(tmp_path, capsys):
    payload, signature = _write_github_payload(tmp_path, DEMO_SECRET)
    code = cli.main(["verify", "--provider", "github", "--payload", str(payload), "--signature", signature])
    assert code == 2
    assert "GITHUB_WEBHOOK_SECRET is not set" in capsys.readouterr().out


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
    out = capsys.readouterr().out
    assert code == 0, out
    assert "status 200" in out and "re-signed" in out
    assert "placeholder" in out  # the user is warned


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
    assert "STRIPE_WEBHOOK_SECRET is not set" in capsys.readouterr().out


def test_replay_sign_needs_a_provider(db, capsys):
    Storage(db).insert(StoredEvent(method="POST", path="/x", headers={}, body=b"{}"))
    code = cli.main(["replay", "1", "--db", db, "--to", "http://127.0.0.1:9/x", "--sign"])
    assert code == 2
    assert "--provider" in capsys.readouterr().out


def test_replay_unknown_id(db, capsys):
    assert cli.main(["replay", "99", "--db", db, "--to", "http://127.0.0.1:9/x"]) == 1
