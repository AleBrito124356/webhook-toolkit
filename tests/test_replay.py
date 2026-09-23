"""Replay re-signing tests.

We exercise the pure ``build_replay_request`` builder (no network) and confirm
that the freshly attached signatures verify against the same fake secret.
"""

import time

from webhooks import verify
from webhooks.replay import build_replay_request
from webhooks.storage import StoredEvent

FAKE_SECRET = ("replay" + "-" + "secret").encode("utf-8")
BODY = b'{"event": "test", "id": 7}'


def _event(provider, headers):
    return StoredEvent(
        method="POST",
        path="/webhooks/in",
        headers=headers,
        body=BODY,
        provider=provider,
    )


def test_replay_strips_hop_by_hop_headers():
    event = _event("github", {"Host": "old-host", "Content-Length": "5", "X-Keep": "yes"})
    request = build_replay_request(event, "http://localhost:9/hook")
    assert request.header("host") is None
    assert request.header("content-length") is None
    assert request.header("X-Keep") == "yes"


def test_replay_resigns_github():
    event = _event("github", {verify.GITHUB_HEADER: "sha256=stale"})
    request = build_replay_request(event, "http://localhost:9/hook", secret=FAKE_SECRET)
    signature = request.header(verify.GITHUB_HEADER)
    assert signature != "sha256=stale"
    assert verify.verify_github(FAKE_SECRET, BODY, signature)


def test_replay_resigns_stripe_with_fresh_timestamp():
    event = _event("stripe", {verify.STRIPE_HEADER: "t=1,v1=stale"})
    now = int(time.time())
    request = build_replay_request(event, "http://localhost:9/hook", secret=FAKE_SECRET, now=now)
    header = request.header(verify.STRIPE_HEADER)
    # The re-signed header verifies at the current time (stale one would not).
    assert verify.verify_stripe(FAKE_SECRET, BODY, header, now=now)


def test_replay_resigns_slack_sets_timestamp_header():
    event = _event("slack", {verify.SLACK_SIGNATURE_HEADER: "v0=stale"})
    now = int(time.time())
    request = build_replay_request(event, "http://localhost:9/hook", secret=FAKE_SECRET, now=now)
    signature = request.header(verify.SLACK_SIGNATURE_HEADER)
    timestamp = request.header(verify.SLACK_TIMESTAMP_HEADER)
    assert timestamp == str(now)
    assert verify.verify_slack(FAKE_SECRET, BODY, signature, timestamp, now=now)


def test_replay_modify_then_resign_matches_new_body():
    event = _event("github", {verify.GITHUB_HEADER: "sha256=stale"})
    new_body = b'{"event": "modified"}'
    request = build_replay_request(
        event, "http://localhost:9/hook", secret=FAKE_SECRET, override_body=new_body
    )
    assert request.body == new_body
    signature = request.header(verify.GITHUB_HEADER)
    assert verify.verify_github(FAKE_SECRET, new_body, signature)
    # And it must NOT verify against the original body.
    assert not verify.verify_github(FAKE_SECRET, BODY, signature)


def test_replay_without_secret_keeps_original_signature():
    event = _event("github", {verify.GITHUB_HEADER: "sha256=original"})
    request = build_replay_request(event, "http://localhost:9/hook")
    assert request.header(verify.GITHUB_HEADER) == "sha256=original"


def test_replay_extra_headers_override():
    event = _event("github", {"content-type": "application/json"})
    request = build_replay_request(
        event, "http://localhost:9/hook", extra_headers={"Content-Type": "text/plain"}
    )
    # Case-insensitive override should not leave a duplicate key behind.
    keys = [k.lower() for k in request.headers]
    assert keys.count("content-type") == 1
    assert request.header("content-type") == "text/plain"


# --- hop-by-hop headers -------------------------------------------------------
def test_replay_strips_every_hop_by_hop_header():
    event = _event(
        "github",
        {
            "Transfer-Encoding": "chunked",
            "TE": "trailers",
            "Trailer": "X-Checksum",
            "Keep-Alive": "timeout=5",
            "Proxy-Connection": "keep-alive",
            "Upgrade": "h2c",
            "Expect": "100-continue",
            "Connection": "keep-alive, X-Private-Hop",
            "X-Private-Hop": "only for the first hop",
            "X-Keep": "yes",
        },
    )
    request = build_replay_request(event, "http://localhost:9/hook")
    assert {k.lower() for k in request.headers} == {"x-keep"}


def test_replay_ignores_manual_framing_overrides():
    event = _event("github", {})
    request = build_replay_request(
        event,
        "http://localhost:9/hook",
        extra_headers={"Content-Length": "999", "Transfer-Encoding": "chunked", "X-Debug": "1"},
    )
    assert request.header("content-length") is None
    assert request.header("transfer-encoding") is None
    assert request.header("x-debug") == "1"


def _capture_one_request(responses=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"):
    """Start a raw TCP server that records exactly the bytes of one request."""
    import socket
    import threading

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    captured = {}

    def run():
        conn, _ = server.accept()
        with conn:
            data = b""
            while b"\r\n\r\n" not in data:
                data += conn.recv(65536)
            head, _, rest = data.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                if name.strip().lower() == b"content-length":
                    length = int(value.strip())
            while len(rest) < length:
                rest += conn.recv(65536)
            captured["head"] = head.decode("latin-1")
            captured["body"] = rest
            conn.sendall(responses)
        server.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return server.getsockname()[1], captured, thread


def test_chunked_capture_replays_as_valid_http_on_the_wire():
    # Regression: a capture received with chunked framing used to be replayed
    # with BOTH Transfer-Encoding and Content-Length, which strict servers
    # (Node's llhttp) reject as a request-smuggling vector.
    from webhooks.replay import send_replay

    port, captured, thread = _capture_one_request()
    event = _event("github", {"transfer-encoding": "chunked", "content-type": "application/json"})
    request = build_replay_request(event, f"http://127.0.0.1:{port}/hook", secret=FAKE_SECRET)
    result = send_replay(request, timeout=5)
    thread.join(5)

    assert result.ok and result.status_code == 200
    header_lines = [line.lower() for line in captured["head"].split("\r\n")[1:]]
    assert not any(line.startswith("transfer-encoding") for line in header_lines)
    assert f"content-length: {len(BODY)}" in header_lines
    assert captured["body"] == BODY


# --- generic provider and GitHub's legacy header ------------------------------------
def test_replay_resigns_generic_provider_with_its_scheme():
    scheme = verify.GenericScheme("X-Acme-Signature", "sha512", "base64", "v1=")
    event = _event("generic", {"X-Acme-Signature": "v1=stale"})
    request = build_replay_request(event, "http://localhost:9/hook", secret=FAKE_SECRET, scheme=scheme)
    assert request.resigned
    assert verify.verify_generic(FAKE_SECRET, BODY, request.header("X-Acme-Signature"), scheme)


def test_replay_updates_legacy_github_header_when_present():
    event = _event("github", {verify.GITHUB_HEADER: "sha256=stale", verify.GITHUB_LEGACY_HEADER: "sha1=stale"})
    new_body = b'{"edited": true}'
    request = build_replay_request(event, "http://localhost:9/hook", secret=FAKE_SECRET, override_body=new_body)
    assert request.header(verify.GITHUB_LEGACY_HEADER) == verify.sign_github_legacy(FAKE_SECRET, new_body)


def test_replay_without_legacy_header_does_not_add_one():
    event = _event("github", {verify.GITHUB_HEADER: "sha256=stale"})
    request = build_replay_request(event, "http://localhost:9/hook", secret=FAKE_SECRET)
    assert request.header(verify.GITHUB_LEGACY_HEADER) is None


def test_replay_of_unsigned_event_is_not_marked_resigned():
    event = _event(None, {})
    assert build_replay_request(event, "http://localhost:9/hook", secret=FAKE_SECRET).resigned is False
