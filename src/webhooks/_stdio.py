"""Terminal output helpers."""

from __future__ import annotations

import sys


def ensure_utf8_stdio() -> None:
    """Let stdout/stderr print rich's box-drawing characters wherever they go.

    On Windows, output redirected to a file or pipe uses the ANSI code page
    (cp1252), which cannot encode the rules and table borders rich draws: the
    first ``console.rule()`` of ``serve`` then crashed with UnicodeEncodeError
    as soon as its output was redirected. Streams that cannot encode them are
    switched to UTF-8 (undecodable characters replaced, never raised).
    """
    for stream in (sys.stdout, sys.stderr):
        encoding = getattr(stream, "encoding", None) or "ascii"
        try:
            "\u2500\u2026".encode(encoding)
        except (UnicodeEncodeError, LookupError):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError, OSError):
                pass
