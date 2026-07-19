"""Replay re-signing tests.

We exercise the pure ``build_replay_request`` builder (no network) and confirm
that the freshly attached signatures verify against the same fake secret.
"""

import time

from src.webhooks import verify
from src.webhooks.replay import build_replay_request
from src.webhooks.storage import StoredEvent

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
