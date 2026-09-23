"""SQLite storage for captured webhook events.

Bodies are stored as raw bytes (BLOB) so a replay reproduces the exact payload
the provider sent — this matters because signatures are computed over the byte
stream, and re-encoding through ``str`` would silently break verification.

One connection is opened per operation and *closed* when it finishes (the
``sqlite3`` context manager only commits; it does not close). That is more than
fast enough for a local dev tool, sidesteps SQLite's cross-thread connection
rules under the uvicorn worker threadpool, and never leaves the database file
locked on Windows.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT    NOT NULL,
    method      TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    query       TEXT    NOT NULL,
    headers     TEXT    NOT NULL,
    body        BLOB    NOT NULL,
    source_ip   TEXT,
    provider    TEXT,
    verified    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_received_at ON events(received_at);
"""


def utcnow_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with a ``Z`` suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class StoredEvent:
    """A single captured request.

    ``verified`` is ``None`` when no secret was configured, ``1`` when the
    signature checked out, and ``0`` when it failed.
    """

    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    query: dict[str, str] = field(default_factory=dict)
    received_at: str = field(default_factory=utcnow_iso)
    source_ip: str | None = None
    provider: str | None = None
    verified: int | None = None
    id: int | None = None

    # -- header access -----------------------------------------------------
    def header(self, name: str) -> str | None:
        target = name.lower()
        for key, value in self.headers.items():
            if key.lower() == target:
                return value
        return None

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";")[0].strip()

    def body_text(self, errors: str = "replace") -> str:
        return self.body.decode("utf-8", errors=errors)

    # -- serialization -----------------------------------------------------
    def to_public_dict(self) -> dict:
        """JSON-safe representation for the inspector API."""
        is_json = "json" in self.content_type
        return {
            "id": self.id,
            "received_at": self.received_at,
            "method": self.method,
            "path": self.path,
            "query": self.query,
            "headers": self.headers,
            "source_ip": self.source_ip,
            "provider": self.provider,
            "verified": self.verified,
            "content_type": self.content_type,
            "size": len(self.body),
            "is_json": is_json,
            "body_text": self.body_text(),
        }

    def to_fixture_dict(self) -> dict:
        """Portable representation for export/import (body base64-encoded)."""
        return {
            "received_at": self.received_at,
            "method": self.method,
            "path": self.path,
            "query": self.query,
            "headers": self.headers,
            "source_ip": self.source_ip,
            "provider": self.provider,
            "verified": self.verified,
            "body_base64": base64.b64encode(self.body).decode("ascii"),
        }

    @classmethod
    def from_fixture_dict(cls, data: dict) -> "StoredEvent":
        return cls(
            method=data["method"],
            path=data.get("path", "/"),
            headers=data.get("headers", {}),
            body=base64.b64decode(data.get("body_base64", "")),
            query=data.get("query", {}),
            received_at=data.get("received_at", utcnow_iso()),
            source_ip=data.get("source_ip"),
            provider=data.get("provider"),
            verified=data.get("verified"),
        )


class Storage:
    """Thin persistence layer over a SQLite database file."""

    def __init__(self, path: str):
        self.path = path
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        """Open a connection, commit (or roll back) the block, always close."""
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._session() as conn:
            conn.executescript(SCHEMA)

    # -- writes ------------------------------------------------------------
    def insert(self, event: StoredEvent) -> int:
        with self._session() as conn:
            cursor = conn.execute(
                """
                INSERT INTO events
                    (received_at, method, path, query, headers, body,
                     source_ip, provider, verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.received_at,
                    event.method,
                    event.path,
                    json.dumps(event.query),
                    json.dumps(event.headers),
                    sqlite3.Binary(event.body),
                    event.source_ip,
                    event.provider,
                    event.verified,
                ),
            )
            event.id = int(cursor.lastrowid)
            return event.id

    def delete(self, event_id: int) -> bool:
        with self._session() as conn:
            cursor = conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
            return cursor.rowcount > 0

    def clear(self) -> int:
        with self._session() as conn:
            cursor = conn.execute("DELETE FROM events")
            return cursor.rowcount

    # -- reads -------------------------------------------------------------
    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> StoredEvent:
        return StoredEvent(
            id=row["id"],
            received_at=row["received_at"],
            method=row["method"],
            path=row["path"],
            query=json.loads(row["query"]),
            headers=json.loads(row["headers"]),
            body=bytes(row["body"]),
            source_ip=row["source_ip"],
            provider=row["provider"],
            verified=row["verified"],
        )

    def get(self, event_id: int) -> StoredEvent | None:
        with self._session() as conn:
            row = conn.execute(
                "SELECT * FROM events WHERE id = ?", (event_id,)
            ).fetchone()
        return self._row_to_event(row) if row else None

    def list(self, limit: int = 100, offset: int = 0) -> list[StoredEvent]:
        with self._session() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def all(self) -> list[StoredEvent]:
        with self._session() as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
        return [self._row_to_event(row) for row in rows]

    def count(self) -> int:
        with self._session() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"])
