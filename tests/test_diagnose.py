"""The diagnosis engine: one test per code and per explained mistake.

Every signature is computed in the test from a fake secret assembled at
runtime, then broken in exactly one known way.
"""

import json

import pytest

from webhooks import verify
from webhooks.verify import diagnose

SECRET = ("diag" + "-" + "secret" + "-" + "value").encode("utf-8")
NOW = 1_750_000_000
BODY = b'{"id":"evt_1","object":"event","data":{"amount":2000,"note":"caf\xc3\xa9"}}'


def _gh(body=BODY, secret=SECRET):
    return {verify.GITHUB_HEADER: verify.sign_github(secret, body)}


def _stripe(body=BODY, secret=SECRET, ts=NOW):
    return {verify.STRIPE_HEADER: verify.sign_stripe(secret, body, ts)}


def _slack(body=BODY, secret=SECRET, ts=NOW):
    return {
        verify.SLACK_SIGNATURE_HEADER: verify.sign_slack(secret, body, ts),
        verify.SLACK_TIMESTAMP_HEADER: str(ts),
    }


# --- codes ------------------------------------------------------------------------
@pytest.mark.parametrize(
    "provider,headers",
    [
        ("github", _gh()),
        ("stripe", _stripe()),
        ("slack", _slack()),
        ("shopify", {verify.SHOPIFY_HEADER: verify.sign_shopify(SECRET, BODY)}),
        ("generic", {"X-Signature": verify.sign_generic(SECRET, BODY)}),
    ],
)
def test_valid(provider, headers):
    diagnosis = diagnose(provider, SECRET, BODY, headers, now=NOW)
    assert diagnosis.ok and diagnosis.code == "valid"
    assert diagnosis.reason == "signature valid"


def test_valid_reports_skew_for_timestamped_providers():
    diagnosis = diagnose("stripe", SECRET, BODY, _stripe(ts=NOW - 12), now=NOW)
    assert diagnosis.ok and diagnosis.skew_seconds == 12


def test_unknown_provider():
    assert diagnose("paypal", SECRET, BODY, {}).code == "unknown_provider"


def test_missing_signature_header():
    diagnosis = diagnose("github", SECRET, BODY, {"content-type": "application/json"})
    assert diagnosis.code == "missing_signature_header"
    assert diagnosis.reason == "no X-Hub-Signature-256 header"


def test_missing_header_but_another_provider_signed_it():
    diagnosis = diagnose("github", SECRET, BODY, _stripe())
    assert diagnosis.code == "missing_signature_header"
    assert any("Stripe signature (Stripe-Signature)" in hint for hint in diagnosis.hints)


def test_missing_header_mentions_lookalike_headers():
    diagnosis = diagnose("github", SECRET, BODY, {"X-Acme-Signature": "abc"})
    assert any("x-acme-signature" in hint for hint in diagnosis.hints)


def test_only_legacy_sha1_github_header_that_matches():
    headers = {verify.GITHUB_LEGACY_HEADER: verify.sign_github_legacy(SECRET, BODY)}
    diagnosis = diagnose("github", SECRET, BODY, headers)
    assert diagnosis.code == "missing_signature_header"
    assert "matches your secret" in diagnosis.hints[0]


def test_only_legacy_sha1_github_header_that_does_not_match():
    headers = {verify.GITHUB_LEGACY_HEADER: verify.sign_github_legacy(b"other", BODY)}
    assert "does not match" in diagnose("github", SECRET, BODY, headers).hints[0]


def test_malformed_missing_prefix_with_correct_digest():
    bare = verify.sign_github(SECRET, BODY).removeprefix("sha256=")
    diagnosis = diagnose("github", SECRET, BODY, {verify.GITHUB_HEADER: bare})
    assert diagnosis.code == "malformed_header"
    assert diagnosis.reason == "X-Hub-Signature-256 is missing the 'sha256=' prefix"
    assert any("digest itself is correct" in hint for hint in diagnosis.hints)


def test_malformed_sha1_prefix_on_the_sha256_header():
    legacy = verify.sign_github_legacy(SECRET, BODY)
    diagnosis = diagnose("github", SECRET, BODY, {verify.GITHUB_HEADER: legacy})
    assert diagnosis.code == "malformed_header"
    assert "prefix 'sha1=' instead of 'sha256='" in diagnosis.reason
    assert any("20 bytes (SHA1)" in hint for hint in diagnosis.hints)
    assert any("digest itself is correct" in hint for hint in diagnosis.hints)


def test_malformed_base64_digest_where_github_expects_hex():
    header = "sha256=" + verify.sign_shopify(SECRET, BODY)
    diagnosis = diagnose("github", SECRET, BODY, {verify.GITHUB_HEADER: header})
    assert diagnosis.code == "malformed_header"
    assert diagnosis.reason == "the digest is base64-encoded but GitHub uses hex"


def test_malformed_hex_digest_where_shopify_expects_base64():
    hex_digest = verify.sign_hmac(SECRET, BODY)
    diagnosis = diagnose("shopify", SECRET, BODY, {verify.SHOPIFY_HEADER: hex_digest})
    assert diagnosis.code == "malformed_header"
    assert diagnosis.reason == "the digest is hex-encoded but Shopify sends base64"
    assert any("digest itself is correct" in hint for hint in diagnosis.hints)


def test_malformed_not_even_an_encoding():
    diagnosis = diagnose("github", SECRET, BODY, {verify.GITHUB_HEADER: "sha256=not-a-digest!"})
    assert diagnosis.code == "malformed_header"
    assert "not valid hex" in diagnosis.reason


def test_malformed_uppercase_hex_is_explained():
    header = "sha256=" + verify.sign_hmac(SECRET, BODY).upper()
    diagnosis = diagnose("github", SECRET, BODY, {verify.GITHUB_HEADER: header})
    assert diagnosis.code == "malformed_header"
    assert "non-canonical" in diagnosis.reason


def test_malformed_stripe_header_without_v1():
    diagnosis = diagnose("stripe", SECRET, BODY, {verify.STRIPE_HEADER: f"t={NOW},v0=abc"}, now=NOW)
    assert diagnosis.code == "malformed_header"
    assert "no v1=" in diagnosis.reason
    assert "v0" in diagnosis.hints[0]


def test_malformed_stripe_timestamp():
    diagnosis = diagnose("stripe", SECRET, BODY, {verify.STRIPE_HEADER: "t=yesterday,v1=ab"})
    assert diagnosis.code == "malformed_header"


def test_missing_timestamp_stripe():
    diagnosis = diagnose("stripe", SECRET, BODY, {verify.STRIPE_HEADER: "v1=abc"})
    assert diagnosis.code == "missing_timestamp"


def test_missing_timestamp_slack():
    headers = {verify.SLACK_SIGNATURE_HEADER: verify.sign_slack(SECRET, BODY, NOW)}
    diagnosis = diagnose("slack", SECRET, BODY, headers, now=NOW)
    assert diagnosis.code == "missing_timestamp"
    assert diagnosis.reason == "no X-Slack-Request-Timestamp header"
    assert "--timestamp" in diagnosis.hints[0]


def test_non_integer_slack_timestamp():
    headers = {verify.SLACK_SIGNATURE_HEADER: "v0=ab", verify.SLACK_TIMESTAMP_HEADER: "soon"}
    assert diagnose("slack", SECRET, BODY, headers).code == "missing_timestamp"


def test_stale_timestamp_with_otherwise_valid_signature():
    diagnosis = diagnose("stripe", SECRET, BODY, _stripe(ts=NOW - 3600), now=NOW, tolerance=300)
    assert diagnosis.code == "timestamp_out_of_tolerance"
    assert diagnosis.reason == "timestamp is 3600 s old, tolerance 300 s"
    assert diagnosis.skew_seconds == 3600
    assert "valid for that timestamp" in diagnosis.hints[0]
    assert "--sign" in diagnosis.hints[0]


def test_future_timestamp_blames_the_clock():
    diagnosis = diagnose("slack", SECRET, BODY, _slack(ts=NOW + 900), now=NOW, tolerance=300)
    assert diagnosis.reason == "timestamp is 900 s in the future, tolerance 300 s"
    assert diagnosis.skew_seconds == -900
    assert "clock" in diagnosis.hints[0]


def test_stale_and_wrong():
    diagnosis = diagnose("stripe", b"other", BODY, _stripe(ts=NOW - 3600), now=NOW)
    assert diagnosis.code == "timestamp_out_of_tolerance"
    assert "does not match either" in diagnosis.hints[0]


def test_millisecond_timestamp_is_called_out():
    diagnosis = diagnose("stripe", SECRET, BODY, _stripe(ts=NOW * 1000), now=NOW)
    assert any("milliseconds" in hint for hint in diagnosis.hints)


def test_tolerance_zero_accepts_old_signatures():
    assert diagnose("stripe", SECRET, BODY, _stripe(ts=NOW - 10**6), now=NOW, tolerance=0).ok


def test_plain_mismatch_has_honest_fallback_hint():
    diagnosis = diagnose("github", b"completely-different", BODY, _gh())
    assert diagnosis.code == "mismatch"
    assert diagnosis.reason == "signature does not match this body and secret"
    assert "No common mistake" in diagnosis.hints[0]


# --- explained mismatches ---------------------------------------------------------------
@pytest.mark.parametrize(
    "received,signed,expected",
    [
        (BODY + b"\n", BODY, "the trailing newline removed"),
        (BODY + b"\r\n", BODY, "the trailing CRLF removed"),
        (BODY, BODY + b"\n", "a trailing newline added"),
        (b'{\r\n "a": 1\r\n}', b'{\n "a": 1\n}', "CRLF line endings converted to LF"),
        (b'{\n "a": 1\n}', b'{\r\n "a": 1\r\n}', "LF line endings converted to CRLF"),
    ],
)
def test_mismatch_explained_by_line_endings(received, signed, expected):
    diagnosis = diagnose("github", SECRET, received, _gh(body=signed))
    assert diagnosis.code == "mismatch"
    assert diagnosis.reason == f"signature matches the payload with {expected}"


def test_mismatch_explained_by_pretty_printed_json():
    pretty = json.dumps(json.loads(BODY), indent=2, ensure_ascii=False).encode("utf-8")
    diagnosis = diagnose("github", SECRET, pretty, _gh())
    assert diagnosis.reason == "signature matches the payload re-serialized as compact JSON (no spaces)"
    assert "raw request bytes" in diagnosis.hints[0]


def test_mismatch_explained_by_python_json_defaults():
    signed = json.dumps(json.loads(BODY)).encode("utf-8")  # ", " / ": " and \\u escapes
    diagnosis = diagnose("github", SECRET, BODY, _gh(body=signed))
    assert "json.dumps defaults" in diagnosis.reason


def test_mismatch_explained_by_secret_whitespace():
    diagnosis = diagnose("github", SECRET + b"\n", BODY, _gh())
    assert diagnosis.reason == "signature matches the secret with surrounding whitespace removed"


def test_mismatch_explained_by_missing_whsec_prefix_on_configured_secret():
    diagnosis = diagnose("stripe", "abc123", BODY, _stripe(secret="whsec_abc123"), now=NOW)
    assert diagnosis.reason == "signature matches the secret with a 'whsec_' prefix added"


def test_mismatch_explained_by_sender_dropping_whsec_prefix():
    diagnosis = diagnose("stripe", "whsec_abc123", BODY, _stripe(secret="abc123"), now=NOW)
    assert diagnosis.reason == "signature matches the secret without its 'whsec_' prefix"


def test_mismatch_explained_by_duplicated_whsec_prefix():
    diagnosis = diagnose("stripe", "whsec_whsec_abc123", BODY, _stripe(secret="whsec_abc123"), now=NOW)
    assert "duplicated 'whsec_' prefix" in diagnosis.reason


def test_mismatch_explained_by_svix_style_secret():
    import base64

    raw_key = b"svix-style-key-bytes"
    secret = "whsec_" + base64.b64encode(raw_key).decode()
    diagnosis = diagnose("stripe", secret, BODY, _stripe(secret=raw_key), now=NOW)
    assert "Svix" in diagnosis.reason


def test_mismatch_explained_by_hex_decoded_secret():
    hex_secret = "ab" * 20
    diagnosis = diagnose("github", hex_secret, BODY, _gh(secret=bytes.fromhex(hex_secret)))
    assert diagnosis.reason == "signature matches the hex-decoded secret"


def test_mismatch_explained_by_swapped_provider_secrets():
    diagnosis = diagnose(
        "github", b"github-one", BODY, _gh(secret=b"shopify-one"),
        other_secrets={"shopify": "shopify-one", "stripe": None},
    )
    assert diagnosis.reason == (
        "signature matches the secret configured for Shopify (SHOPIFY_WEBHOOK_SECRET)"
    )


def test_mismatch_explained_by_stripe_signature_without_timestamp():
    header = f"t={NOW},v1=" + verify.sign_hmac(SECRET, BODY)
    diagnosis = diagnose("stripe", SECRET, BODY, {verify.STRIPE_HEADER: header}, now=NOW)
    assert diagnosis.reason == "signature is an HMAC of the body alone, without the timestamp"
    assert "'<timestamp>.<body>'" in diagnosis.hints[0]


def test_mismatch_explained_by_two_mistakes_at_once():
    diagnosis = diagnose("github", SECRET + b" ", BODY + b"\n", _gh())
    assert diagnosis.reason == (
        "signature matches the payload with the trailing newline removed, "
        "using the secret with surrounding whitespace removed"
    )
    assert len(diagnosis.hints) == 2


def test_generic_scheme_diagnosis_uses_its_own_format():
    scheme = verify.GenericScheme("X-Acme-Sig", "sha512", "base64", "v1=")
    good = verify.sign_generic(SECRET, BODY, scheme)
    assert diagnose("generic", SECRET, BODY, {"X-Acme-Sig": good}, scheme=scheme).ok
    missing = diagnose("generic", SECRET, BODY, {"X-Acme-Sig": good[3:]}, scheme=scheme)
    assert missing.reason == "X-Acme-Sig is missing the 'v1=' prefix"
    sha256 = verify.sign_hmac(SECRET, BODY, encoding="base64", prefix="v1=")
    wrong_alg = diagnose("generic", SECRET, BODY, {"X-Acme-Sig": sha256}, scheme=scheme)
    assert wrong_alg.code == "malformed_header"
    assert "32 bytes (SHA256)" in wrong_alg.reason


def test_generic_scheme_rejects_unsupported_settings():
    with pytest.raises(ValueError):
        verify.GenericScheme(algorithm="crc32")
    with pytest.raises(ValueError):
        verify.GenericScheme(encoding="base32")
    with pytest.raises(ValueError):
        verify.GenericScheme(signature_header=" ")


def test_diagnosis_ok_always_agrees_with_strict_verifiers():
    cases = [
        ("github", _gh(), verify.verify_github(SECRET, BODY, _gh()[verify.GITHUB_HEADER])),
        ("github", _gh(secret=b"x"), False),
        ("stripe", _stripe(ts=NOW - 400), False),
        ("stripe", _stripe(), True),
    ]
    for provider, headers, expected in cases:
        assert diagnose(provider, SECRET, BODY, headers, now=NOW).ok is expected


def test_verify_request_keeps_its_api_and_gains_a_reason():
    result = verify.verify_request("github", SECRET, BODY + b"\n", _gh())
    assert result.ok is False and result.provider == "github"
    assert result.code == "mismatch"
    assert result.reason == "signature matches the payload with the trailing newline removed"
    assert verify.verify_request("nope", SECRET, BODY, {}).reason == "unknown provider: 'nope'"


def test_to_dict_is_json_serializable():
    document = diagnose("stripe", SECRET, BODY, _stripe(ts=NOW - 3600), now=NOW).to_dict()
    assert json.loads(json.dumps(document))["code"] == "timestamp_out_of_tolerance"


def test_detect_provider_generic_only_when_configured():
    scheme = verify.GenericScheme("X-Acme-Sig")
    assert verify.detect_provider({"X-Acme-Sig": "x"}) is None
    assert verify.detect_provider({"X-Acme-Sig": "x"}, generic=scheme) == "generic"
    # Built-in providers win over the generic header.
    assert verify.detect_provider({"X-Acme-Sig": "x", **_gh()}, generic=scheme) == "github"
