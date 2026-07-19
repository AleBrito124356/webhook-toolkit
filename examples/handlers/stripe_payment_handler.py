"""A verified Stripe *payment* webhook handler.

Run it, then deliver (or replay) an event to it:

    export STRIPE_WEBHOOK_SECRET="whsec_XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    uvicorn examples.handlers.stripe_payment_handler:app --port 3002

    # Replay a captured event, re-signing with a fresh timestamp so it passes
    # Stripe's 5-minute tolerance window:
    python cli.py replay 2 --to http://127.0.0.1:3002/webhooks/stripe --sign

Stripe sends the signature in the ``Stripe-Signature`` header as
``t=<timestamp>,v1=<hex>`` where the HMAC-SHA256 is computed over
``"<timestamp>.<raw-body>"``. The timestamp is checked against a tolerance to
blunt replay attacks — which is exactly why replaying an old capture requires
re-signing.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request

# Make ``src`` importable when run from the repository root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.webhooks.verify import verify_stripe  # noqa: E402

app = FastAPI(title="stripe-payment-handler")

# Placeholder only. Your real value comes from the Stripe dashboard and starts
# with ``whsec_``; the literal X's below fail Stripe's checksum by design.
SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "whsec_XXXXXXXXXXXXXXXXXXXXXXXXXXXX")

# Tolerance in seconds for the signature timestamp (Stripe's default is 300).
TOLERANCE = int(os.environ.get("STRIPE_TIMESTAMP_TOLERANCE", "300"))


@app.post("/webhooks/stripe")
async def stripe_webhook(
    request: Request,
    stripe_signature: str | None = Header(default=None),
):
    raw = await request.body()

    # SECURITY: verify signature and timestamp before trusting the event.
    if not verify_stripe(SECRET, raw, stripe_signature, tolerance=TOLERANCE):
        raise HTTPException(status_code=400, detail="invalid signature")

    event = json.loads(raw)
    event_type = event.get("type", "unknown")
    obj = event.get("data", {}).get("object", {})

    if event_type == "payment_intent.succeeded":
        amount = obj.get("amount", 0) / 100
        currency = str(obj.get("currency", "")).upper()
        print(f"[stripe] payment succeeded: {amount:.2f} {currency} ({obj.get('id', '')})")
    elif event_type == "payment_intent.payment_failed":
        reason = obj.get("last_payment_error", {}).get("message", "unknown reason")
        print(f"[stripe] payment failed: {obj.get('id', '')} — {reason}")
    else:
        print(f"[stripe] received event: {event_type}")

    return {"status": "ok", "type": event_type}
