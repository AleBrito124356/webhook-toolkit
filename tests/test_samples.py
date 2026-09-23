"""Offline event simulator: templates, rendering, signing and the send command."""

import json
import os
from urllib.parse import parse_qs

import pytest
from fastapi.testclient import TestClient

from webhooks import cli
from _helpers import load_handler
from webhooks import samples, verify
from webhooks.inbound import assess
from webhooks.server import create_app
from webhooks.storage import Storage
from webhooks.testing import BackgroundServer

SECRETS = {
    "github": "gh" + "-" + "sample-secret",
    "stripe": "whsec_" + "sample-secret",
    "slack": "slack" + "-" + "sample-secret",
    "shopify": "shop" + "-" + "sample-secret",
}
ALL = samples.list_samples()


def _configure_secrets():
    for provider, secret in SECRETS.items():
        os.environ[verify.PROVIDERS[provider].env_var] = secret


@pytest.fixture()
def receiver(tmp_path):
    _configure_secrets()
    with TestClient(create_app(str(tmp_path / "samples.db"))) as client:
        yield client


def _post(client, request):
    path = request.url.split("://", 1)[1].split("/", 1)[1]
    return client.request(request.method, "/" + path, content=request.body, headers=request.headers)


# --- catalogue ---------------------------------------------------------------------
def test_catalogue_covers_every_provider_with_the_advertised_events():
    events = {(t.provider, t.event) for t in ALL}
    assert events == {
        ("github", "ping"), ("github", "push"), ("github", "pull_request.opened"), ("github", "issues.opened"),
        ("stripe", "payment_intent.succeeded"), ("stripe", "payment_intent.payment_failed"),
        ("stripe", "checkout.session.completed"), ("stripe", "invoice.paid"),
        ("slack", "url_verification"), ("slack", "app_mention"), ("slack", "slash_command"),
        ("shopify", "orders/create"), ("shopify", "products/update"), ("shopify", "app/uninstalled"),
    }
    assert samples.providers() == ["github", "shopify", "slack", "stripe"]


def test_unknown_samples_list_what_exists():
    with pytest.raises(KeyError, match="available: .*push"):
        samples.get_sample("github", "star")
    with pytest.raises(KeyError, match="choose one of"):
        samples.get_sample("paypal", "anything")


# --- every sample through the real receiver ----------------------------------------------
@pytest.mark.parametrize("template", ALL, ids=lambda t: f"{t.provider}:{t.event}")
def test_signed_sample_is_detected_and_verified(receiver, template):
    rendered = samples.render_sample(template)
    request = samples.build_sample_request(rendered, "http://testserver", secret=SECRETS[template.provider])
    data = _post(receiver, request).json()
    assert data["provider"] == template.provider
    assert data["verified"] == 1, data["reason"]


@pytest.mark.parametrize("template", ALL, ids=lambda t: f"{t.provider}:{t.event}")
def test_sample_signed_with_wrong_secret_is_diagnosed_as_mismatch(receiver, template):
    rendered = samples.render_sample(template)
    request = samples.build_sample_request(rendered, "http://testserver", secret="wrong-secret")
    data = _post(receiver, request).json()
    assert data["verified"] == 0
    stored = rendered.to_stored_event(request.headers)
    assessment = assess(stored)
    assert assessment.diagnosis.code == "mismatch"


def test_samples_carry_realistic_companion_headers():
    push = samples.render_sample(samples.get_sample("github", "push"))
    assert push.headers["X-GitHub-Event"] == "push"
    assert len(push.headers["X-GitHub-Delivery"]) == 36
    # A named placeholder ties the header to the body.
    assert push.headers["X-GitHub-Hook-Installation-Target-ID"] == str(push.document["repository"]["id"])
    order = samples.render_sample(samples.get_sample("shopify", "orders/create"))
    assert order.headers["X-Shopify-Topic"] == "orders/create"
    assert order.document["admin_graphql_api_id"].endswith(str(order.document["id"]))
    slash = samples.render_sample(samples.get_sample("slack", "slash_command"), now=1_700_000_000)
    assert slash.headers["X-Slack-Request-Timestamp"] == "1700000000"
    assert parse_qs(slash.body.decode())["command"] == ["/deploy"]


def test_github_samples_also_get_the_legacy_sha1_signature():
    rendered = samples.render_sample(samples.get_sample("github", "ping"))
    request = samples.build_sample_request(rendered, "http://x", secret=SECRETS["github"])
    assert request.header(verify.GITHUB_LEGACY_HEADER) == verify.sign_github_legacy(SECRETS["github"], request.body)


def test_every_render_is_a_fresh_delivery():
    template = samples.get_sample("stripe", "invoice.paid")
    first, second = samples.render_sample(template), samples.render_sample(template)
    assert first.document["id"] != second.document["id"]
    assert samples.render_sample(template, seed=7, now=1).body == samples.render_sample(template, seed=7, now=1).body


def test_typed_placeholders_and_body_formats():
    rendered = samples.render_sample(samples.get_sample("stripe", "payment_intent.succeeded"), now=1_700_000_000)
    assert rendered.document["created"] == 1_700_000_000  # an int, not "1700000000"
    assert rendered.body.startswith(b'{\n  "id": "evt_')  # Stripe sends pretty JSON
    ping = samples.render_sample(samples.get_sample("github", "ping"))
    assert isinstance(ping.document["hook_id"], int)
    assert b": " not in ping.body  # GitHub sends compact JSON


def test_unknown_placeholder_is_an_error():
    template = samples.SampleTemplate("github", "x", "", "POST", "/", {}, {"a": "{{nonsense}}"})
    with pytest.raises(ValueError, match="nonsense"):
        samples.render_sample(template)


# --- overrides -------------------------------------------------------------------------
def test_set_override_changes_the_body_and_the_signature_still_verifies():
    rendered = samples.render_sample(
        samples.get_sample("stripe", "payment_intent.succeeded"),
        overrides=["data.object.amount=5000", 'data.object.currency="eur"', "data.object.metadata.rush=true"],
    )
    obj = json.loads(rendered.body)["data"]["object"]
    assert obj["amount"] == 5000 and obj["currency"] == "eur" and obj["metadata"]["rush"] is True
    request = samples.build_sample_request(rendered, "http://x", secret=SECRETS["stripe"])
    assert verify.verify_stripe(SECRETS["stripe"], request.body, request.header(verify.STRIPE_HEADER))


def test_override_list_index_and_new_keys():
    rendered = samples.render_sample(
        samples.get_sample("github", "push"),
        overrides={"commits.0.message": "Edited", "extra.nested.flag": 1},
    )
    assert rendered.document["commits"][0]["message"] == "Edited"
    assert rendered.document["extra"] == {"nested": {"flag": 1}}


@pytest.mark.parametrize(
    "override,message",
    [
        ("commits.9.message=x", "not a valid index"),
        ("ref.deeper=x", "cannot descend"),
        ("no-equals-sign", "expected dotted.path=value"),
        ("=value", "the path is empty"),
    ],
)
def test_bad_overrides_are_rejected(override, message):
    with pytest.raises(ValueError, match=message):
        samples.render_sample(samples.get_sample("github", "push"), overrides=[override])


def test_parse_value():
    assert samples.parse_value("5000") == 5000
    assert samples.parse_value('"5000"') == "5000"
    assert samples.parse_value("null") is None
    assert samples.parse_value("hello world") == "hello world"


def test_resolve_url_uses_the_sample_path_only_when_none_given():
    assert samples.resolve_url("http://127.0.0.1:8000", "/webhooks/github") == "http://127.0.0.1:8000/webhooks/github"
    assert samples.resolve_url("http://127.0.0.1:8000/", "/webhooks/github") == "http://127.0.0.1:8000/webhooks/github"
    assert samples.resolve_url("http://h/custom", "/webhooks/github") == "http://h/custom"


# --- the example handlers accept the samples ----------------------------------------------
@pytest.mark.parametrize(
    "handler_name,provider,event,path",
    [
        ("github_push_handler", "github", "push", "/webhooks/github"),
        ("stripe_payment_handler", "stripe", "payment_intent.succeeded", "/webhooks/stripe"),
    ],
)
def test_example_handlers_accept_signed_samples(handler_name, provider, event, path):
    handler = load_handler(handler_name, secret=SECRETS[provider])
    rendered = samples.render_sample(samples.get_sample(provider, event))
    request = samples.build_sample_request(rendered, "http://testserver" + path, secret=SECRETS[provider])
    with TestClient(handler.app) as client:
        response = client.post(path, content=request.body, headers=request.headers)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "ok"


# --- CLI: samples / send ---------------------------------------------------------------------
def test_cli_samples_lists_every_provider(capsys):
    assert cli.main(["samples"]) == 0
    out = capsys.readouterr().out
    for provider in ("github", "stripe", "slack", "shopify"):
        assert provider in out
    assert cli.main(["samples", "paypal"]) == 2


def test_cli_send_dry_run_prints_a_signed_request(capsys):
    code = cli.main(["send", "slack", "url_verification", "--dry-run", "--secret", SECRETS["slack"], "--now", "1700000000"])
    out = capsys.readouterr().out
    assert code == 0
    assert "POST http://127.0.0.1/webhooks/slack/events" in out
    assert "X-Slack-Signature: v0=" in out
    assert '"type":"url_verification"' in out


def test_cli_send_store_seeds_the_database_with_verified_events(tmp_path, capsys):
    _configure_secrets()
    db = str(tmp_path / "seed.db")
    assert cli.main(["send", "shopify", "orders/create", "--store", "--sign", "--db", db, "--count", "3"]) == 0
    events = Storage(db).all()
    assert len(events) == 3
    assert {e.verified for e in events} == {1}
    assert len({e.body for e in events}) == 3  # fresh ids every time
    assert "stored shopify/orders/create" in capsys.readouterr().out


def test_cli_send_to_live_receiver_and_handler(tmp_path, capsys):
    _configure_secrets()
    db = str(tmp_path / "live.db")
    with BackgroundServer(create_app(db)) as server:
        code = cli.main(["send", "github", "issues.opened", "--to", server.url, "--sign"])
    assert code == 0
    assert "status 200" in capsys.readouterr().out
    stored = Storage(db).all()
    assert stored[0].path == "/webhooks/github" and stored[0].verified == 1

    handler = load_handler("stripe_payment_handler", secret=SECRETS["stripe"])
    with BackgroundServer(handler.app) as server:
        good = cli.main(["send", "stripe", "invoice.paid", "--to", server.url + "/webhooks/stripe", "--sign"])
        unsigned = cli.main(["send", "stripe", "invoice.paid", "--to", server.url + "/webhooks/stripe"])
    captured = capsys.readouterr()
    assert good == 0 and unsigned == 1
    assert "unsigned" in captured.err


@pytest.mark.parametrize(
    "argv,message",
    [
        (["send", "github", "star", "--dry-run"], "available:"),
        (["send", "github", "push"], "--to URL"),
        (["send", "github", "push", "--dry-run", "--count", "0"], "--count"),
        (["send", "github", "push", "--dry-run", "--set", "commits.5.id=1"], "not a valid index"),
        (["send", "github", "push", "--store", "--sign"], "GITHUB_WEBHOOK_SECRET is not set"),
    ],
)
def test_cli_send_usage_errors(tmp_path, capsys, argv, message):
    assert cli.main(argv + ["--db", str(tmp_path / "x.db")]) == 2
    assert message in capsys.readouterr().err


def test_cli_send_reports_connection_errors(capsys):
    code = cli.main(["send", "github", "ping", "--to", "http://127.0.0.1:9/webhooks", "--secret", "x", "--timeout", "2"])
    assert code == 1
    assert "FAIL" in capsys.readouterr().out
