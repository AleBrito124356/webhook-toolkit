"""A verified GitHub *push* webhook handler.

Run it, then deliver (or replay) a push event to it. The handler and the
toolkit must share the same secret; the simplest way is a ``.env`` file in the
repository root, which both of them read (shell variables win over the file):

    cp .env.example .env            # then set GITHUB_WEBHOOK_SECRET to anything
    uvicorn examples.handlers.github_push_handler:app --port 3001

    # From another shell, load the bundled push and replay it, re-signed with
    # the secret from .env so the handler accepts it:
    python cli.py import examples/fixtures/github_push.json
    python cli.py replay 1 --to http://127.0.0.1:3001/webhooks/github --sign

If you leave the ``.env.example`` placeholder in place, ``--sign`` still signs
with it (and prints a warning), so the walkthrough works end to end; a real
GitHub delivery will of course only verify with your real secret.

GitHub signs the raw request body with HMAC-SHA256 and sends it in the
``X-Hub-Signature-256`` header as ``sha256=<hex>``. We must read the *raw* body
(not a parsed model) because any re-serialization would change the bytes and
break the signature.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request

# Use the checkout's package when run from the repository (``pip install`` of
# webhook-toolkit makes ``webhooks`` importable anywhere).
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from webhooks.config import load_env_file  # noqa: E402
from webhooks.verify import verify_github  # noqa: E402

# Share the toolkit's .env (no-op when there is none; real env vars win).
load_env_file()

app = FastAPI(title="github-push-handler")

# Never hardcode this — read it from the environment. The placeholder here is an
# obvious dummy; replace it with the secret you set in the GitHub webhook UI.
SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "use-a-long-random-string-here")


@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
):
    raw = await request.body()

    # SECURITY: verify before doing anything with the payload.
    if not verify_github(SECRET, raw, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="invalid signature")

    if x_github_event != "push":
        return {"status": "ignored", "event": x_github_event}

    payload = json.loads(raw)
    repo = payload.get("repository", {}).get("full_name", "unknown/repo")
    ref = payload.get("ref", "")
    commits = payload.get("commits", [])

    print(f"[github] push to {repo} ({ref}) with {len(commits)} commit(s)")
    for commit in commits:
        message = commit.get("message", "").splitlines()[0] if commit.get("message") else ""
        author = commit.get("author", {}).get("name", "?")
        print(f"  - {commit.get('id', '')[:7]} {message}  ({author})")

    return {"status": "ok", "repo": repo, "commits": len(commits)}
