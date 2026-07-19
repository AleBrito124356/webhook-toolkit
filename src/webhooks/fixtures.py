"""Export and import stored events as JSON fixtures.

Fixtures let you capture a real (or replayed) delivery once and reuse it as a
deterministic test input, or share a reproduction with a teammate. Bodies are
base64-encoded so binary payloads survive the round-trip exactly.
"""

from __future__ import annotations

import json
from pathlib import Path

from .storage import StoredEvent, Storage

FIXTURE_VERSION = 1


def dump_events(events: list[StoredEvent]) -> dict:
    """Build the JSON-serializable fixture document for ``events``."""
    return {
        "version": FIXTURE_VERSION,
        "count": len(events),
        "events": [event.to_fixture_dict() for event in events],
    }


def load_events(document: dict) -> list[StoredEvent]:
    """Parse a fixture document back into :class:`StoredEvent` objects."""
    version = document.get("version")
    if version != FIXTURE_VERSION:
        raise ValueError(
            f"unsupported fixture version {version!r}; expected {FIXTURE_VERSION}"
        )
    return [StoredEvent.from_fixture_dict(item) for item in document.get("events", [])]


def export_to_file(storage: Storage, path: str | Path) -> int:
    """Write every stored event to ``path`` as a JSON fixture. Returns the count."""
    events = storage.all()
    document = dump_events(events)
    Path(path).write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    return len(events)


def import_from_file(storage: Storage, path: str | Path) -> int:
    """Insert every event from a JSON fixture file. Returns the count inserted."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    events = load_events(document)
    for event in events:
        event.id = None
        storage.insert(event)
    return len(events)
