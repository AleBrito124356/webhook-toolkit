"""The inspector's JSON API: listing, detail, raw, delete, replay, curl, status."""

import base64
import json
import os
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from _helpers import load_handler
from webhooks import verify
from webhooks.server import create_app
from webhooks.testing import BackgroundServer

SECRET = "api" + "-" + "test" + "-" + "secret"
BODY = b'{"ref":"refs/heads/main","repository":{"full_name":"octo-org/demo"},"commits":[]}'


@pytest.fixture()
def client(tmp_path):
    with TestClient(create_app(str(tmp_path / "api.db"))) as test_client:
        yield test_client


def _push(client, body=BODY, secret=SECRET, path="/webhooks/github"):
    headers = {"Content-Type": "application/json", "X-GitHub-Event": "push",
               verify.GITHUB_HEADER: verify.sign_github(secret, body)}
    return client.post(path, content=body, headers=headers).json()["id"]


def _seed(client):
    os.environ["GITHUB_WEBHOOK_SECRET"] = SECRET
    _push(client)                                   # 1 github verified
    _push(client, secret="wrong")                   # 2 github invalid
    client.post("/webhooks/other", content=b"{}")  # 3 unsigned
    client.post("/stripe/hook", content=b"{}", headers={verify.STRIPE_HEADER: "t=1,v1=ab"})  # 4 stripe, not checked


# --- listing ------------------------------------------------------------------------
def test_list_filters_and_totals(client):
    _seed(client)
    def ids(**params):
        data = client.get("/api/events", params=params).json()
        return [e["id"] for e in data["events"]], data["count"], data["total"]

    assert ids() == ([4, 3, 2, 1], 4, 4)
    assert ids(provider="github") == ([2, 1], 2, 4)
    assert ids(provider="unsigned") == ([3], 1, 4)
    assert ids(verified="1") == ([1], 1, 4)
    assert ids(verified="0") == ([2], 1, 4)
    assert ids(verified="none") == ([4, 3], 2, 4)
    assert ids(q="STRIPE/") == ([4], 1, 4)  # case-insensitive substring
    assert ids(q="webhooks") == ([3, 2, 1], 3, 4)
    assert ids(provider="github", verified="0") == ([2], 1, 4)


def test_list_paging_and_summary(client):
    for i in range(7):
        client.post(f"/p/{i}", content=b"x" * i)
    page = client.get("/api/events", params={"limit": 3, "offset": 3, "summary": "true"}).json()
    assert [e["path"] for e in page["events"]] == ["/p/3", "/p/2", "/p/1"]
    assert page["count"] == 7 and page["offset"] == 3 and page["limit"] == 3
    assert "body_text" not in page["events"][0] and "headers" not in page["events"][0]
    full = client.get("/api/events", params={"limit": 1}).json()
    assert full["events"][0]["body_text"] == "xxxxxx"


def test_list_rejects_bad_verified_filter(client):
    assert client.get("/api/events", params={"verified": "maybe"}).status_code == 422


# --- detail / raw ------------------------------------------------------------------------
def test_detail_includes_live_diagnosis(client):
    os.environ["GITHUB_WEBHOOK_SECRET"] = SECRET
    event_id = _push(client, body=BODY)
    tampered = client.post(
        "/webhooks/github", content=BODY + b"\n",
        headers={verify.GITHUB_HEADER: verify.sign_github(SECRET, BODY)},
    ).json()["id"]
    good = client.get(f"/api/events/{event_id}").json()
    assert good["assessment"]["verified"] == 1
    bad = client.get(f"/api/events/{tampered}").json()
    diagnosis = bad["assessment"]["diagnosis"]
    assert diagnosis["code"] == "mismatch"
    assert diagnosis["reason"] == "signature matches the payload with the trailing newline removed"
    assert diagnosis["hints"]
    assert client.get("/api/events/999").status_code == 404


def test_raw_returns_exact_bytes_as_a_download(client):
    raw = b"<script>alert(1)</script>\x00\xff"
    event_id = client.post("/x", content=raw, headers={"Content-Type": "text/html"}).json()["id"]
    response = client.get(f"/api/events/{event_id}/raw")
    assert response.content == raw
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "attachment" in response.headers["content-disposition"]
    assert response.headers["x-original-content-type"] == "text/html"
    assert client.get("/api/events/999/raw").status_code == 404


def test_non_numeric_event_path_is_captured_not_routed(client):
    assert client.get("/api/events/not-a-number").json()["status"] == "received"
    assert client.post("/api/events", content=b"{}").json()["status"] == "received"


# --- delete / clear + CSRF guard ---------------------------------------------------------
def test_delete_one_and_clear_all(client):
    for _ in range(3):
        client.post("/x", content=b"{}")
    assert client.delete("/api/events/2").json() == {"deleted": 1, "id": 2}
    assert client.delete("/api/events/2").status_code == 404
    assert client.get("/api/events").json()["count"] == 2
    assert client.delete("/api/events").json() == {"deleted": 2}
    assert client.get("/api/events").json()["count"] == 0


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "http://evil.example"},
        {"Origin": "null"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "same-site"},
    ],
)
def test_mutating_routes_refuse_cross_site_requests(client, headers):
    client.post("/x", content=b"{}")
    assert client.delete("/api/events/1", headers=headers).status_code == 403
    assert client.delete("/api/events", headers=headers).status_code == 403
    response = client.post("/api/events/1/replay", json={"to": "http://127.0.0.1:9/"}, headers=headers)
    assert response.status_code == 403
    assert client.get("/api/events").json()["count"] == 1


def test_same_origin_browser_requests_are_allowed(client):
    client.post("/x", content=b"{}")
    headers = {"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"}
    assert client.delete("/api/events/1", headers=headers).status_code == 200


# --- replay ------------------------------------------------------------------------------------
def test_replay_requires_json(client):
    client.post("/x", content=b"{}")
    form = client.post("/api/events/1/replay", data={"to": "http://127.0.0.1:9/"})
    assert form.status_code == 415
    broken = client.post("/api/events/1/replay", content=b"{", headers={"Content-Type": "application/json"})
    assert broken.status_code == 400


@pytest.mark.parametrize(
    "payload,status",
    [
        ({"to": "ftp://example.com/x"}, 422),
        ({"to": "not a url"}, 422),
        ({"to": "http://127.0.0.1:9/", "provider": "paypal"}, 422),
        ({"to": "http://127.0.0.1:9/", "unexpected": 1}, 422),
        ({"to": "http://127.0.0.1:9/", "timeout": 0}, 422),
        ({"to": "http://127.0.0.1:9/", "body_base64": "***"}, 400),
    ],
)
def test_replay_validates_options(client, payload, status):
    client.post("/x", content=b"{}")
    assert client.post("/api/events/1/replay", json=payload).status_code == status


def test_replay_unknown_event_is_404(client):
    assert client.post("/api/events/5/replay", json={"to": "http://127.0.0.1:9/"}).status_code == 404


def test_replay_sign_needs_a_provider_and_a_secret(client):
    client.post("/x", content=b"{}")
    no_provider = client.post("/api/events/1/replay", json={"to": "http://127.0.0.1:9/", "sign": True})
    assert no_provider.status_code == 400 and "no detected provider" in no_provider.json()["detail"]
    _push(client)
    no_secret = client.post("/api/events/2/replay", json={"to": "http://127.0.0.1:9/", "sign": True})
    assert no_secret.status_code == 400
    assert no_secret.json()["detail"] == "cannot re-sign: GITHUB_WEBHOOK_SECRET is not set"


def test_replay_with_edited_body_is_resigned_and_accepted_by_a_real_handler(client):
    os.environ["GITHUB_WEBHOOK_SECRET"] = SECRET
    handler = load_handler("github_push_handler", secret=SECRET)
    event_id = _push(client)
    edited = json.loads(BODY)
    edited["commits"] = [{"id": "a" * 40, "message": "edited in the inspector", "author": {"name": "Mona"}}]
    with BackgroundServer(handler.app) as server:
        target = server.url + "/webhooks/github"
        accepted = client.post(
            f"/api/events/{event_id}/replay",
            json={"to": target, "sign": True, "body": json.dumps(edited), "headers": {"X-Debug": "1"}},
        ).json()
        rejected = client.post(
            f"/api/events/{event_id}/replay", json={"to": target, "body": json.dumps(edited)}
        ).json()
    assert accepted["ok"] is True and accepted["status_code"] == 200, accepted
    assert accepted["resigned"] is True
    assert json.loads(accepted["response_snippet"])["commits"] == 1
    assert accepted["request"]["headers"]["X-Debug"] == "1"
    assert rejected["ok"] is False and rejected["status_code"] == 401


def test_replay_with_placeholder_secret_warns(client):
    os.environ["GITHUB_WEBHOOK_SECRET"] = "use-a-long-random-string-here"
    handler = load_handler("github_push_handler", secret="use-a-long-random-string-here")
    event_id = _push(client, secret="whatever")
    with BackgroundServer(handler.app) as server:
        data = client.post(
            f"/api/events/{event_id}/replay", json={"to": server.url + "/webhooks/github", "sign": True}
        ).json()
    assert data["status_code"] == 200
    assert "placeholder" in data["warnings"][0]


def test_replay_binary_body_via_base64_and_connection_errors(client):
    client.post("/x", content=b"{}")
    data = client.post(
        "/api/events/1/replay",
        json={"to": "http://127.0.0.1:9/nothing", "body_base64": base64.b64encode(b"\x00\x01").decode(), "timeout": 2},
    ).json()
    assert data["ok"] is False and data["status_code"] is None and data["error"]
    assert data["request"]["size"] == 2


def test_replay_to_the_receiver_itself_does_not_deadlock(tmp_path):
    with BackgroundServer(create_app(str(tmp_path / "self.db"))) as server:
        import httpx

        httpx.post(server.url + "/first", content=b"{}")
        data = httpx.post(
            server.url + "/api/events/1/replay", json={"to": server.url + "/second"}, timeout=10
        ).json()
        assert data["status_code"] == 200
        paths = [e["path"] for e in httpx.get(server.url + "/api/events").json()["events"]]
    assert paths == ["/second", "/first"]


# --- curl ---------------------------------------------------------------------------------------
def test_curl_command_reflects_the_replay(client):
    os.environ["GITHUB_WEBHOOK_SECRET"] = SECRET
    event_id = _push(client)
    data = client.post(
        f"/api/events/{event_id}/curl", json={"to": "http://127.0.0.1:3001/webhooks/github", "sign": True}
    ).json()
    assert data["resigned"] is True
    assert data["curl"].startswith("curl -sS -X POST 'http://127.0.0.1:3001/webhooks/github'")
    assert "-H 'X-Hub-Signature-256: sha256=" in data["curl"]
    assert "content-length" not in data["curl"].lower()


@pytest.mark.skipif(not (shutil.which("bash") and shutil.which("curl")), reason="needs bash and curl")
def test_generated_curl_command_really_verifies(client):
    os.environ["GITHUB_WEBHOOK_SECRET"] = SECRET
    handler = load_handler("github_push_handler", secret=SECRET)
    body = b'{"ref":"refs/heads/main","commits":[{"id":"abc","message":"it\'s \\"quoted\\"\\n"}]}\n'
    event_id = _push(client, body=body)
    with BackgroundServer(handler.app) as server:
        command = client.post(
            f"/api/events/{event_id}/curl", json={"to": server.url + "/webhooks/github", "sign": True}
        ).json()["curl"]
        completed = subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=30)
    assert '"status":"ok"' in completed.stdout, completed.stdout + completed.stderr


# --- status -------------------------------------------------------------------------------------------
def test_status_reports_secret_states_without_values(client):
    os.environ["GITHUB_WEBHOOK_SECRET"] = SECRET
    os.environ["STRIPE_WEBHOOK_SECRET"] = "whsec_XXXXXXXXXXXXXXXX"
    status = client.get("/api/status").json()
    assert status["providers"]["github"] == {"state": "set", "env_var": "GITHUB_WEBHOOK_SECRET"}
    assert status["providers"]["stripe"]["state"] == "placeholder"
    assert status["providers"]["slack"]["state"] == "unset"
    assert SECRET not in json.dumps(status)
    assert status["forward_targets"] == [] and status["generic"] is None


def test_inspector_page_is_self_contained(client):
    page = client.get("/").text
    assert "<script src" not in page and "<link rel=\"stylesheet\"" not in page
    assert "/api/events" in page and "prefers-reduced-motion" in page
    assert "innerHTML" not in page  # captured data never becomes markup
