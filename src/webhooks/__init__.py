"""webhook-toolkit: receive, verify, inspect and replay webhooks locally.

A small FastAPI-based toolkit for developing webhook handlers without a public
tunnel. It captures every inbound request to SQLite, verifies provider
signatures, and lets you replay or fan-out stored events to your local handler.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
