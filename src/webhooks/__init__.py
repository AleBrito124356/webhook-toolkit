"""webhook-toolkit: receive, verify, inspect and replay webhooks locally.

A small FastAPI-based toolkit for developing webhook handlers without a public
tunnel. It captures every inbound request to SQLite, verifies provider
signatures and explains why they fail, generates realistic signed sample
events offline, and lets you replay (edited, re-signed) or fan-out stored
events to your local handlers from the CLI or the browser inspector.
"""

__version__ = "0.2.0"

__all__ = ["__version__"]
