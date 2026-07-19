"""Signature verification tests.

Every expected signature is computed *inside the test* from a fake secret that
is assembled at runtime — there is never a real-looking provider token on disk.
The fake secrets below are plainly not credentials.
"""

import time

import pytest

from src.webhooks import verify

# Built from parts so nothing on disk resembles a real signing secret.
FAKE_SECRET = ("test" + "-" + "secret" + "-" + "not-real").encode("utf-8")
BODY = b'{"hello": "world", "n": 42}'


# --- GitHub ----------------------------------------------------------------
def test_github_roundtrip():
    signature = verify.sign_github(FAKE_SECRET, BODY)
    assert signature.startswith("sha256=")
    assert verify.verify_github(FAKE_SECRET, BODY, signature)


def test_github_rejects_tampered_body():
    signature = verify.sign_github(FAKE_SECRET, BODY)
    assert not verify.verify_github(FAKE_SECRET, BODY + b" ", signature)


def test_github_rejects_wrong_secret():
    signature = verify.sign_github(FAKE_SECRET, BODY)
    assert not verify.verify_github(b"other-secret", BODY, signature)


def test_github_rejects_missing_signature():
    assert not verify.verify_github(FAKE_SECRET, BODY, None)


# --- Stripe ----------------------------------------------------------------
def test_stripe_roundtrip_current_timestamp():
    now = int(time.time())
    header = verify.sign_stripe(FAKE_SECRET, BODY, now)
    assert header.startswith("t=") and ",v1=" in header
    assert verify.verify_stripe(FAKE_SECRET, BODY, header, now=now)


def test_stripe_rejects_stale_timestamp():
    old = int(time.time()) - 10_000
    header = verify.sign_stripe(FAKE_SECRET, BODY, old)
    # Signature is correct but the timestamp is outside the tolerance window.
    assert not verify.verify_stripe(FAKE_SECRET, BODY, header, tolerance=300)


def test_stripe_tolerance_zero_skips_time_check():
    old = int(time.time()) - 10_000
    header = verify.sign_stripe(FAKE_SECRET, BODY, old)
    assert verify.verify_stripe(FAKE_SECRET, BODY, header, tolerance=0)


def test_stripe_rejects_tampered_body():
    now = int(time.time())
    header = verify.sign_stripe(FAKE_SECRET, BODY, now)
    assert not verify.verify_stripe(FAKE_SECRET, b'{"hello":"mars"}', header, now=now)


def test_stripe_parse_signature():
    header = "t=1700000000,v1=abc123,v0=ignored"
    timestamp, signatures = verify.parse_stripe_signature(header)
    assert timestamp == 1700000000
    assert signatures == ["abc123"]


# --- Slack -----------------------------------------------------------------
def test_slack_roundtrip():
    now = int(time.time())
    signature = verify.sign_slack(FAKE_SECRET, BODY, now)
    assert signature.startswith("v0=")
    assert verify.verify_slack(FAKE_SECRET, BODY, signature, now, now=now)


def test_slack_rejects_stale_timestamp():
    old = int(time.time()) - 10_000
    signature = verify.sign_slack(FAKE_SECRET, BODY, old)
    assert not verify.verify_slack(FAKE_SECRET, BODY, signature, old, tolerance=300)


def test_slack_rejects_tampered_body():
    now = int(time.time())
    signature = verify.sign_slack(FAKE_SECRET, BODY, now)
    assert not verify.verify_slack(FAKE_SECRET, b"changed", signature, now, now=now)


# --- Shopify ---------------------------------------------------------------
def test_shopify_roundtrip():
    signature = verify.sign_shopify(FAKE_SECRET, BODY)
    assert verify.verify_shopify(FAKE_SECRET, BODY, signature)


def test_shopify_rejects_tampered_body():
    signature = verify.sign_shopify(FAKE_SECRET, BODY)
    assert not verify.verify_shopify(FAKE_SECRET, BODY + b"x", signature)


# --- Generic + dispatch ----------------------------------------------------
def test_generic_hmac_base64():
    signature = verify.sign_hmac(FAKE_SECRET, BODY, encoding="base64")
    assert verify.verify_hmac(FAKE_SECRET, BODY, signature, encoding="base64")


@pytest.mark.parametrize(
    "provider,headers_factory",
    [
        ("github", lambda ts: {verify.GITHUB_HEADER: verify.sign_github(FAKE_SECRET, BODY)}),
        ("stripe", lambda ts: {verify.STRIPE_HEADER: verify.sign_stripe(FAKE_SECRET, BODY, ts)}),
        (
            "slack",
            lambda ts: {
                verify.SLACK_SIGNATURE_HEADER: verify.sign_slack(FAKE_SECRET, BODY, ts),
                verify.SLACK_TIMESTAMP_HEADER: str(ts),
            },
        ),
        ("shopify", lambda ts: {verify.SHOPIFY_HEADER: verify.sign_shopify(FAKE_SECRET, BODY)}),
    ],
)
def test_verify_request_dispatch(provider, headers_factory):
    now = int(time.time())
    headers = headers_factory(now)
    result = verify.verify_request(provider, FAKE_SECRET, BODY, headers, now=now)
    assert result.ok
    assert result.provider == provider


def test_verify_request_is_case_insensitive():
    signature = verify.sign_github(FAKE_SECRET, BODY)
    headers = {"x-hub-signature-256": signature}  # lowercase like Starlette
    result = verify.verify_request("github", FAKE_SECRET, BODY, headers)
    assert result.ok


def test_detect_provider():
    assert verify.detect_provider({verify.GITHUB_HEADER: "sha256=x"}) == "github"
    assert verify.detect_provider({verify.STRIPE_HEADER: "t=1,v1=x"}) == "stripe"
    assert verify.detect_provider({verify.SHOPIFY_HEADER: "x"}) == "shopify"
    assert verify.detect_provider({"content-type": "application/json"}) is None
