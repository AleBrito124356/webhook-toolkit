"""Fan-out forwarding: retries, the 4xx rule, concurrency, routing and stats."""

import threading
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from webhooks import verify
from webhooks.forward import ForwardResult, ForwardTarget, TargetStats, forward_event
from webhooks.server import create_app
from webhooks.storage import StoredEvent

SECRET = "forward" + "-" + "secret"


def _event(provider="github", body=b'{"n": 1}', headers=None):
    return StoredEvent(
        method="POST",
        path="/webhooks/github",
        headers=headers if headers is not None else {"content-type": "application/json", "transfer-encoding": "chunked"},
        body=body,
        provider=provider,
        id=7,
    )


class Recorder:
    """An httpx.MockTransport handler scripted per URL."""

    def __init__(self, script):
        self.script = script  # url -> list of (status | Exception | callable)
        self.calls: dict[str, int] = {}
        self.requests: list[httpx.Request] = []
        self.lock = threading.Lock()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        with self.lock:
            n = self.calls.get(url, 0)
            self.calls[url] = n + 1
            self.requests.append(request)
        steps = self.script[url]
        step = steps[min(n, len(steps) - 1)]
        if callable(step) and not isinstance(step, type):
            step = step()
        if isinstance(step, Exception):
            raise step
        return httpx.Response(step, text=f"status {step}")


def _transport(script):
    recorder = Recorder(script)
    return recorder, httpx.MockTransport(recorder)


def test_5xx_is_retried_until_success():
    recorder, transport = _transport({"http://a/h": [503, 502, 200]})
    [result] = forward_event(_event(), ["http://a/h"], retries=2, backoff=0, transport=transport)
    assert result.ok and result.status_code == 200 and result.attempts == 3
    assert recorder.calls["http://a/h"] == 3


def test_4xx_is_not_retried():
    recorder, transport = _transport({"http://a/h": [401, 200]})
    [result] = forward_event(_event(), ["http://a/h"], retries=5, backoff=0, transport=transport)
    assert not result.ok and result.status_code == 401 and result.attempts == 1
    assert result.error == "HTTP 401"


def test_connection_errors_use_the_whole_retry_budget():
    error = httpx.ConnectError("connection refused")
    recorder, transport = _transport({"http://dead/h": [error]})
    [result] = forward_event(_event(), ["http://dead/h"], retries=2, backoff=0, transport=transport)
    assert not result.ok and result.status_code is None and result.attempts == 3
    assert "connection refused" in result.error


def test_forwarded_requests_carry_no_hop_by_hop_headers():
    recorder, transport = _transport({"http://a/h": [200]})
    forward_event(_event(), ["http://a/h"], transport=transport)
    sent = recorder.requests[0]
    assert "transfer-encoding" not in sent.headers
    assert sent.headers["content-length"] == str(len(b'{"n": 1}'))


def test_secret_map_re_signs_the_forwarded_copy():
    recorder, transport = _transport({"http://a/h": [200]})
    event = _event(headers={verify.GITHUB_HEADER: "sha256=stale"})
    forward_event(event, ["http://a/h"], secret_map={"github": SECRET}, transport=transport)
    sent = recorder.requests[0]
    assert verify.verify_github(SECRET, event.body, sent.headers[verify.GITHUB_HEADER])


def test_targets_are_delivered_concurrently():
    finished_at: dict[str, float] = {}
    start = time.perf_counter()

    def slow():
        time.sleep(1.0)
        return 200

    recorder, transport = _transport({"http://slow/h": [slow], "http://fast/h": [200]})

    def on_result(target, result):
        finished_at[target.url] = time.perf_counter() - start

    results = forward_event(
        _event(), ["http://slow/h", "http://fast/h"], transport=transport, on_result=on_result
    )
    # Results keep target order, but the fast target finished long before the slow one.
    assert [r.target for r in results] == ["http://slow/h", "http://fast/h"]
    assert finished_at["http://fast/h"] < 0.5
    assert finished_at["http://slow/h"] >= 1.0


# --- routing ---------------------------------------------------------------------------------
def test_forward_target_parsing():
    assert ForwardTarget.parse("http://a/h") == ForwardTarget("http://a/h")
    assert ForwardTarget.parse("github=http://a/h") == ForwardTarget("http://a/h", "github")
    assert ForwardTarget.parse("Unsigned=http://a/h").provider == "unsigned"
    # A query string with '=' is still a plain URL.
    assert ForwardTarget.parse("http://a/h?x=1").url == "http://a/h?x=1"
    assert ForwardTarget.parse("github=http://a/h").label == "github=http://a/h"
    with pytest.raises(ValueError, match="provider=URL"):
        ForwardTarget.parse("paypal=http://a/h")
    with pytest.raises(ValueError):
        ForwardTarget.parse("not-a-url")


def test_provider_routing_skips_other_providers():
    recorder, transport = _transport({"http://gh/h": [200], "http://st/h": [200], "http://any/h": [200], "http://none/h": [200]})
    targets = ["github=http://gh/h", "stripe=http://st/h", "http://any/h", "unsigned=http://none/h"]
    results = forward_event(_event("github"), targets, transport=transport)
    assert [r.target for r in results] == ["github=http://gh/h", "http://any/h"]
    results = forward_event(_event(None), targets, transport=transport)
    assert [r.target for r in results] == ["http://any/h", "unsigned=http://none/h"]
    assert forward_event(_event("slack"), ["github=http://gh/h"], transport=transport) == []


# --- stats ---------------------------------------------------------------------------------------
def test_target_stats_counts_and_serializes():
    stats = TargetStats("http://a/h")
    assert stats.avg_ms is None
    stats.record(ForwardResult("http://a/h", True, 200, 1, 10.0), event_id=1)
    stats.record(ForwardResult("http://a/h", False, 500, 3, 30.0, error="HTTP 500"), event_id=2)
    data = stats.to_dict()
    assert data["delivered"] == 1 and data["failed"] == 1
    assert data["last_status"] == 500 and data["last_error"] == "HTTP 500" and data["last_event_id"] == 2
    assert data["avg_ms"] == 20.0 and data["last_at"].endswith("Z")
    stats.record(ForwardResult("http://a/h", True, 200, 1, 5.0), event_id=3)
    assert stats.to_dict()["last_error"] is None


def test_receiver_forwards_in_the_background_and_exposes_stats(tmp_path):
    recorder, transport = _transport({"http://gh/h": [200], "http://down/h": [httpx.ConnectError("refused")]})
    app = create_app(
        str(tmp_path / "fwd.db"),
        forward_targets=["github=http://gh/h", "http://down/h"],
        forward_retries=1,
        forward_backoff=0,
        forward_transport=transport,
    )
    with TestClient(app) as client:
        client.post("/webhooks/github", content=b"{}", headers={verify.GITHUB_HEADER: "sha256=00"})
        client.post("/other", content=b"{}")
        stats = {t["target"]: t for t in client.get("/api/forward").json()["targets"]}
        status = client.get("/api/status").json()
    assert stats["github=http://gh/h"]["delivered"] == 1  # the unsigned request was not routed there
    assert stats["http://down/h"]["failed"] == 2
    assert stats["http://down/h"]["last_error"] == "refused"
    assert status["forward_targets"] == ["github=http://gh/h", "http://down/h"]


def test_invalid_forward_target_fails_fast(tmp_path):
    with pytest.raises(ValueError):
        create_app(str(tmp_path / "x.db"), forward_targets=["nope"])
