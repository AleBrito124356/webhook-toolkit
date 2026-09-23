"""Storage and fixture round-trip tests."""

import json

import pytest

from src.webhooks import fixtures
from src.webhooks.storage import StoredEvent, Storage


@pytest.fixture()
def storage(tmp_path):
    return Storage(str(tmp_path / "events.db"))


def _sample(body=b'{"a": 1}', provider="github", verified=1):
    return StoredEvent(
        method="POST",
        path="/webhooks/github",
        headers={"content-type": "application/json", "x-hub-signature-256": "sha256=abc"},
        body=body,
        query={"debug": "1"},
        source_ip="127.0.0.1",
        provider=provider,
        verified=verified,
    )


def test_insert_assigns_id_and_counts(storage):
    event = _sample()
    event_id = storage.insert(event)
    assert event_id == event.id == 1
    assert storage.count() == 1


def test_get_returns_exact_bytes(storage):
    raw = b"\x00\x01binary\xff payload"
    storage.insert(_sample(body=raw))
    fetched = storage.get(1)
    assert fetched is not None
    assert fetched.body == raw  # bytes survive the BLOB round-trip exactly


def test_get_preserves_fields(storage):
    storage.insert(_sample())
    fetched = storage.get(1)
    assert fetched.method == "POST"
    assert fetched.path == "/webhooks/github"
    assert fetched.query == {"debug": "1"}
    assert fetched.provider == "github"
    assert fetched.verified == 1
    assert fetched.header("Content-Type") == "application/json"


def test_list_is_newest_first(storage):
    storage.insert(_sample(body=b"one"))
    storage.insert(_sample(body=b"two"))
    events = storage.list()
    assert [e.body for e in events] == [b"two", b"one"]


def test_delete_and_clear(storage):
    storage.insert(_sample())
    storage.insert(_sample())
    assert storage.delete(1) is True
    assert storage.delete(999) is False
    assert storage.count() == 1
    assert storage.clear() == 1
    assert storage.count() == 0


def test_content_type_and_is_json(storage):
    event = _sample()
    public = event.to_public_dict()
    assert public["content_type"] == "application/json"
    assert public["is_json"] is True
    assert public["size"] == len(event.body)


def test_fixture_roundtrip(tmp_path):
    src = Storage(str(tmp_path / "src.db"))
    src.insert(_sample(body=b'{"first": true}'))
    src.insert(_sample(body=b"\x00binary", provider="stripe", verified=0))

    path = tmp_path / "fixtures.json"
    exported = fixtures.export_to_file(src, path)
    assert exported == 2

    # The file is valid JSON with a version marker.
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["version"] == fixtures.FIXTURE_VERSION
    assert document["count"] == 2

    dst = Storage(str(tmp_path / "dst.db"))
    imported = fixtures.import_from_file(dst, path)
    assert imported == 2

    original = src.all()
    restored = dst.all()
    assert [e.body for e in original] == [e.body for e in restored]
    assert [e.provider for e in original] == [e.provider for e in restored]
    assert [e.verified for e in original] == [e.verified for e in restored]


def test_fixture_rejects_unknown_version(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"version": 999, "events": []}), encoding="utf-8")
    with pytest.raises(ValueError):
        fixtures.import_from_file(Storage(str(tmp_path / "x.db")), path)


# --- schema migration --------------------------------------------------------------
OLD_SCHEMA = """
CREATE TABLE events (
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
INSERT INTO events (received_at, method, path, query, headers, body, provider, verified)
VALUES ('2026-01-01T00:00:00Z', 'POST', '/old', '{}', '{}', X'7B7D', 'github', 1);
"""


def test_database_from_the_first_release_is_migrated_in_place(tmp_path):
    import sqlite3
    from contextlib import closing

    path = str(tmp_path / "old.db")
    with closing(sqlite3.connect(path)) as conn:
        conn.executescript(OLD_SCHEMA)

    storage = Storage(path)  # runs the migration
    old = storage.get(1)
    assert old.path == "/old" and old.verify_reason is None and old.body == b"{}"

    new_id = storage.insert(_sample())
    storage.get(new_id)
    event = _sample()
    event.verify_reason = "signature valid"
    storage.insert(event)
    assert storage.list()[0].verify_reason == "signature valid"

    Storage(path)  # idempotent: a second open must not try to add the column again
    with closing(sqlite3.connect(path)) as conn:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(events)")]
    assert columns.count("verify_reason") == 1


def test_verify_reason_survives_fixture_roundtrip(tmp_path):
    src = Storage(str(tmp_path / "a.db"))
    event = _sample(verified=0)
    event.verify_reason = "timestamp is 3600 s old, tolerance 300 s"
    src.insert(event)
    path = tmp_path / "f.json"
    fixtures.export_to_file(src, path)
    dst = Storage(str(tmp_path / "b.db"))
    fixtures.import_from_file(dst, path)
    assert dst.get(1).verify_reason == "timestamp is 3600 s old, tolerance 300 s"
