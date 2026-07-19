"""A verified GitHub *push* webhook handler.

Run it, then deliver (or replay) a push event to it:

    export GITHUB_WEBHOOK_SECRET="use-a-long-random-string-here"
    uvicorn examples.handlers.github_push_handler:app --port 3001

    # From another shell, replay a captured push and re-sign it:
    python cli.py replay 1 --to http://127.0.0.1:3001/webhooks/github --sign

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

# Make ``src`` importable when run from the repository root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.webhooks.verify import verify_github  # noqa: E402

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
