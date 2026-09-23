"""Receiver behaviour through FastAPI's TestClient (no sockets)."""

import os

import pytest
from fastapi.testclient import TestClient

from src.webhooks import verify
from src.webhooks.server import create_app
from src.webhooks.storage import Storage

DEMO_SECRET = "server" + "-" + "test" + "-" + "secret"
BODY = b'{"action": "opened", "number": 1}'


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "server.db")


@pytest.fixture()
def client(db_path):
    with TestClient(create_app(db_path)) as test_client:
        yield test_client


def _github_headers(secret=DEMO_SECRET, body=BODY):
    return {
        "Content-Type": "application/json",
        "X-GitHub-Event": "pull_request",
        verify.GITHUB_HEADER: verify.sign_github(secret, body),
    }


# --- capture surface ----------------------------------------------------------
def test_favicon_is_served_and_not_captured(client, db_path):
    response = client.get("/favicon.ico")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert Storage(db_path).count() == 0


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS"])
def test_head_and_options_are_captured(client, db_path, method):
    response = client.request(method, "/webhooks/health")
    assert response.status_code == 200
    stored = Storage(db_path).list()
    assert [(e.method, e.path) for e in stored] == [(method, "/webhooks/health")]


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_framework_doc_paths_are_captured_like_any_other(client, db_path, path):
    assert client.post(path, content=b"x").json()["status"] == "received"
    assert client.get(path).json()["status"] == "received"
    assert Storage(db_path).count() == 2


def test_inspector_page_and_catch_all_post_on_root(client, db_path):
    page = client.get("/")
    assert page.status_code == 200 and "<title>" in page.text
    assert client.post("/", content=b"{}").json()["id"] == 1
    assert Storage(db_path).count() == 1


def test_api_events_reports_true_total(client):
    for i in range(7):
        client.post(f"/hook/{i}", content=b"{}")
    data = client.get("/api/events", params={"limit": 3}).json()
    assert data["count"] == 7
    assert len(data["events"]) == 3
    assert data["events"][0]["path"] == "/hook/6"


# --- inbound verification -----------------------------------------------------
def test_inbound_verified_with_real_secret(client, db_path):
    os.environ["GITHUB_WEBHOOK_SECRET"] = DEMO_SECRET
    data = client.post("/webhooks/github", content=BODY, headers=_github_headers()).json()
    assert data["provider"] == "github"
    assert data["verified"] == 1


def test_inbound_invalid_with_real_secret(client):
    os.environ["GITHUB_WEBHOOK_SECRET"] = DEMO_SECRET
    headers = _github_headers(secret="some-other-secret")
    assert client.post("/webhooks/github", content=BODY, headers=headers).json()["verified"] == 0


def test_inbound_without_secret_is_unchecked(client):
    assert client.post("/webhooks/github", content=BODY, headers=_github_headers()).json()["verified"] is None


def test_inbound_placeholder_secret_never_reports_invalid(client):
    placeholder = "use-a-long-random-string-here"
    os.environ["GITHUB_WEBHOOK_SECRET"] = placeholder
    # A real provider delivery (signed with some real secret) -> unchecked, not "invalid".
    real = client.post("/webhooks/github", content=BODY, headers=_github_headers()).json()
    assert real["verified"] is None
    # A local demo signed with the very same placeholder -> verified.
    demo = client.post(
        "/webhooks/github", content=BODY, headers=_github_headers(secret=placeholder)
    ).json()
    assert demo["verified"] == 1


def test_capture_preserves_raw_body_bytes(client, db_path):
    raw = b"\x00\xffnot-utf8\r\n"
    client.post("/bin", content=raw, headers={"Content-Type": "application/octet-stream"})
    assert Storage(db_path).get(1).body == raw


# --- reasons ------------------------------------------------------------------------
def test_unsigned_request_is_labelled_unsigned(client, db_path):
    data = client.post("/anything", content=b"{}").json()
    assert data["verified"] is None
    assert data["reason"] == "unsigned: no known signature header"
    assert Storage(db_path).get(1).verify_reason == "unsigned: no known signature header"


def test_invalid_capture_stores_the_diagnosis(client, db_path):
    os.environ["GITHUB_WEBHOOK_SECRET"] = DEMO_SECRET
    headers = _github_headers()
    client.post("/webhooks/github", content=BODY + b"\n", headers=headers)
    stored = Storage(db_path).get(1)
    assert stored.verified == 0
    assert stored.verify_reason == "signature matches the payload with the trailing newline removed"


def test_missing_secret_reason_names_the_variable(client):
    data = client.post("/webhooks/github", content=BODY, headers=_github_headers()).json()
    assert data["reason"] == "not checked: GITHUB_WEBHOOK_SECRET is not set"


def test_placeholder_reason(client):
    os.environ["GITHUB_WEBHOOK_SECRET"] = "use-a-long-random-string-here"
    data = client.post("/webhooks/github", content=BODY, headers=_github_headers()).json()
    assert data["reason"] == "not checked: GITHUB_WEBHOOK_SECRET is still a placeholder value"


def test_generic_provider_detected_and_verified(db_path):
    os.environ["GENERIC_WEBHOOK_HEADER"] = "X-Acme-Signature"
    os.environ["GENERIC_WEBHOOK_ENCODING"] = "base64"
    os.environ["GENERIC_WEBHOOK_PREFIX"] = "sha256="
    os.environ["GENERIC_WEBHOOK_SECRET"] = DEMO_SECRET
    scheme = verify.GenericScheme("X-Acme-Signature", "sha256", "base64", "sha256=")
    with TestClient(create_app(db_path)) as client:
        ok = client.post("/acme", content=BODY, headers={"X-Acme-Signature": verify.sign_generic(DEMO_SECRET, BODY, scheme)}).json()
        bad = client.post("/acme", content=BODY, headers={"X-Acme-Signature": "sha256=AAAA"}).json()
    assert ok["provider"] == "generic" and ok["verified"] == 1
    assert bad["verified"] == 0


def test_invalid_generic_configuration_fails_at_startup(db_path):
    os.environ["GENERIC_WEBHOOK_HEADER"] = "X-Acme-Signature"
    os.environ["GENERIC_WEBHOOK_ALGORITHM"] = "crc32"
    with pytest.raises(ValueError, match="GENERIC_WEBHOOK"):
        create_app(db_path)
