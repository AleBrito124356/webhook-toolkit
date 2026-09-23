# Changelog

## 0.2.0

### Added

- **Signature diagnostics.** `webhooks.verify.diagnose()` classifies a failure
  (`missing_signature_header`, `malformed_header`, `missing_timestamp`,
  `timestamp_out_of_tolerance` with skew and direction, `mismatch`) and
  explains mismatches by re-trying the HMAC under common mistakes: trailing
  newline/CRLF, LF↔CRLF conversion, re-serialized JSON, whitespace in the
  secret, missing/dropped/duplicated `whsec_` prefix, Svix-style and
  hex-decoded secrets, hex vs base64, missing `sha256=`/`v0=` prefixes, SHA-1
  instead of SHA-256, only the legacy `X-Hub-Signature`, Stripe/Slack
  signatures without the timestamp, and secrets swapped between providers.
  Used by `verify` (new `--json`, `--header`), the new `show <id>` command, the
  receiver (one-line reason stored with every capture) and the inspector.
- **Generic HMAC provider** configured with `GENERIC_WEBHOOK_*`: detected and
  verified by the receiver, re-signed by replay, and available as
  `verify --provider generic` with `--signature-header/--algorithm/--encoding/--prefix`.
- **Offline event simulator.** 14 realistic sample events (GitHub, Stripe,
  Slack, Shopify) with the providers' companion headers; `samples` lists them,
  `send` signs and delivers (`--to`) or stores (`--store`) them, with
  `--set dotted.path=value`, `--count`, `--dry-run` and `--now`.
- `examples/offline_demo.py`: receiver + both example handlers on loopback,
  36 end-to-end checks in a few seconds.
- **Inspector workbench**: filters, paging with the true total, diagnosis with
  hints, replay with edited body / extra headers / re-signing, copy as curl,
  raw download, delete, clear all, forward-target counters.
- **JSON API**: filtered `GET /api/events`, `GET /api/events/{id}` (live
  diagnosis), `/raw`, `POST /replay`, `POST /curl`, `DELETE` one/all,
  `GET /api/forward`, `GET /api/status`. Mutating routes refuse cross-site
  browser requests.
- **Forwarding**: targets are delivered concurrently, `provider=URL` routes a
  target to one provider's events, per-target counters are printed live and
  served at `/api/forward`.
- `.env` support (no new dependency) with a global `--env-file`; real shell
  variables win.
- Installable package: `pip install git+https://github.com/AleBrito124356/webhook-toolkit`
  gives the `webhook-toolkit` command and the importable `webhooks` package;
  `webhook-toolkit --version`.
- `webhooks.testing.BackgroundServer` to run an ASGI app on a free loopback
  port in tests.

### Fixed

- `.env` was never read, so secrets configured as the README said were ignored.
- `replay --sign` refused the `.env.example` placeholders that the example
  handlers accept, so the documented walkthrough failed with 400/401.
- Replay and forward copied `Transfer-Encoding: chunked` next to the computed
  `Content-Length`; strict servers (Node's llhttp) rejected the request. All
  hop-by-hop headers are now dropped.
- SQLite connections were never closed (the context manager only commits),
  leaking one per operation and possibly locking the file on Windows.
- The browser's `/favicon.ico` request was stored as a webhook; `HEAD` and
  `OPTIONS` returned 405; `/docs`, `/redoc`, `/openapi.json` were not captured.
- The inspector header showed at most 100 events and older events were
  unreachable.
- `serve` crashed with `UnicodeEncodeError` when its output was redirected on
  Windows (cp1252).
- Every replay built a new TLS context (~160 ms on Windows); it is now built
  once.

### Changed (behaviour)

- `replay --sign` with no secret configured now exits with code 2 and says
  which variable is missing, instead of silently sending the event unsigned.
- A **placeholder** secret is used by `verify`, `replay --sign` and
  `send --sign` with a warning (previously treated as "no secret"). The
  receiver marks a capture `verified` when it was signed with that
  placeholder and `not checked` otherwise — never `invalid`.
- Warnings and errors are printed to stderr; results stay on stdout.
- `verify --signature` is optional (omitting it diagnoses the missing header).
- `VerifyResult.reason` is now the specific diagnosis; `VerifyResult` gained
  `code` and `hints` fields (existing fields unchanged).
- Captures without a known signature header are labelled `unsigned` and
  captures that could not be checked `not checked` (previously both
  `no secret`). The receiver's JSON reply includes `reason`.
- `GET /api/events` adds `total`, `offset` and `limit`; `count` is the number
  of events matching the filters (equal to the total when there are none).
- `ForwardResult.target` is the target label (`provider=URL` for routed
  targets).
- The CLI moved to `src/webhooks/cli.py`; `python cli.py ...` still works
  through a thin shim, and `import src.webhooks...` still works from a
  checkout, but `import webhooks...` is the supported path.
- `pydantic>=2` is now a declared dependency (it was already required through
  FastAPI).
- Databases created by 0.1.0 are migrated in place (new `verify_reason`
  column) the first time they are opened.

## 0.1.0

- Initial release: FastAPI catch-all receiver with SQLite storage, signature
  verification for GitHub, Stripe, Slack and Shopify, inspector page, replay
  with re-signing, fan-out forwarding, JSON fixtures.
