"""Offline event simulator: realistic, signed sample webhooks for every provider.

Each sample is a JSON template under ``templates/<provider>/`` describing the
request a provider would send: method, path, the companion headers real
deliveries carry (``X-GitHub-Event``, ``X-Shopify-Topic``, Slack's timestamp,
content types...) and a body. Rendering fills in fresh ids and timestamps, so
every send looks like a new delivery, and signing uses the same ``sign_*``
functions as replay.

Template placeholders (inside any string of the template)::

    {{uuid}}          random UUID4
    {{hex:N}}         N random lowercase hex characters
    {{int:N}}         N random digits (an int when it is the whole value)
    {{alnum:N}}       N random letters and digits
    {{upper:N}}       N random uppercase letters and digits
    {{now}}           current Unix time in seconds (an int when whole value)
    {{now_iso}}       current UTC time, ISO 8601 with a Z suffix

Adding ``@name`` (``{{int:9@repo_id}}``) reuses one value everywhere that name
appears in the same render, e.g. a repository id in the body and a header.
"""

from __future__ import annotations

import json
import random
import re
import string
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import resources
from urllib.parse import urlencode, urlsplit, urlunsplit

from .replay import ReplayRequest, build_replay_request, set_header
from .storage import StoredEvent, utcnow_iso
from .verify import GITHUB_LEGACY_HEADER, GenericScheme, sign_github_legacy

BODY_FORMATS = ("json-compact", "json-pretty", "form")
_PLACEHOLDER = re.compile(r"\{\{\s*([a-z_]+)(?::(\d+))?(?:@([A-Za-z0-9_]+))?\s*\}\}")
_TYPED_KINDS = {"int", "now"}


@dataclass(frozen=True)
class SampleTemplate:
    provider: str
    event: str
    description: str
    method: str
    path: str
    headers: dict
    body: object
    body_format: str = "json-compact"

    @property
    def content_type(self) -> str:
        for key, value in self.headers.items():
            if key.lower() == "content-type":
                return str(value)
        return "application/x-www-form-urlencoded" if self.body_format == "form" else "application/json"


@dataclass
class RenderedSample:
    provider: str
    event: str
    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    document: object = field(repr=False, default=None)

    def to_stored_event(self, headers: dict[str, str] | None = None) -> StoredEvent:
        """A :class:`StoredEvent` as the receiver would have captured it."""
        final = dict(headers if headers is not None else self.headers)
        lowered = {k.lower(): v for k, v in final.items()}
        lowered["content-length"] = str(len(self.body))
        return StoredEvent(
            method=self.method,
            path=self.path,
            headers=lowered,
            body=self.body,
            received_at=utcnow_iso(),
            source_ip="127.0.0.1",
            provider=self.provider,
        )


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------
_CACHE: list[SampleTemplate] | None = None


def _load_all() -> list[SampleTemplate]:
    global _CACHE
    if _CACHE is None:
        templates: list[SampleTemplate] = []
        root = resources.files(__package__).joinpath("templates")
        for provider_dir in sorted(root.iterdir(), key=lambda p: p.name):
            if not provider_dir.is_dir():
                continue
            for item in sorted(provider_dir.iterdir(), key=lambda p: p.name):
                if not item.name.endswith(".json"):
                    continue
                data = json.loads(item.read_text(encoding="utf-8"))
                body_format = data.get("body_format", "json-compact")
                if body_format not in BODY_FORMATS:
                    raise ValueError(f"{item.name}: unknown body_format {body_format!r}")
                templates.append(
                    SampleTemplate(
                        provider=data["provider"],
                        event=data["event"],
                        description=data.get("description", ""),
                        method=data.get("method", "POST"),
                        path=data.get("path", "/"),
                        headers=data.get("headers", {}),
                        body=data.get("body", {}),
                        body_format=body_format,
                    )
                )
        _CACHE = templates
    return list(_CACHE)


def list_samples(provider: str | None = None) -> list[SampleTemplate]:
    """Every bundled sample, optionally for one provider."""
    return [t for t in _load_all() if provider is None or t.provider == provider]


def providers() -> list[str]:
    return sorted({t.provider for t in _load_all()})


def get_sample(provider: str, event: str) -> SampleTemplate:
    """Look up one sample; ``KeyError`` lists what exists when it does not."""
    for template in _load_all():
        if template.provider == provider and template.event == event:
            return template
    known = [t.event for t in list_samples(provider)]
    if not known:
        raise KeyError(f"no samples for provider {provider!r}; choose one of {', '.join(providers())}")
    raise KeyError(f"no {provider} sample {event!r}; available: {', '.join(known)}")


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
class _Renderer:
    def __init__(self, now: int, rng: random.Random):
        self.now = now
        self.rng = rng
        self.named: dict[str, object] = {}

    def _generate(self, kind: str, arg: str | None) -> object:
        size = int(arg) if arg else 0
        rng = self.rng
        if kind == "uuid":
            return str(uuid.UUID(int=rng.getrandbits(128), version=4))
        if kind == "hex":
            return "".join(rng.choice("0123456789abcdef") for _ in range(size or 40))
        if kind == "int":
            size = size or 9
            return int(str(rng.randint(1, 9)) + "".join(rng.choice(string.digits) for _ in range(size - 1)))
        if kind == "alnum":
            return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(size or 24))
        if kind == "upper":
            return "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(size or 10))
        if kind == "now":
            return self.now
        if kind == "now_iso":
            return datetime.fromtimestamp(self.now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        raise ValueError(f"unknown template placeholder {{{{{kind}}}}}")

    def value(self, kind: str, arg: str | None, name: str | None) -> object:
        if name:
            if name not in self.named:
                self.named[name] = self._generate(kind, arg)
            return self.named[name]
        return self._generate(kind, arg)

    def render(self, node: object) -> object:
        if isinstance(node, dict):
            return {key: self.render(value) for key, value in node.items()}
        if isinstance(node, list):
            return [self.render(item) for item in node]
        if isinstance(node, str):
            whole = _PLACEHOLDER.fullmatch(node.strip())
            if whole and whole.group(1) in _TYPED_KINDS:
                return self.value(*whole.groups())
            return _PLACEHOLDER.sub(lambda m: str(self.value(*m.groups())), node)
        return node


def parse_value(text: str) -> object:
    """Interpret an override value as JSON when possible, else as a string.

    ``5000`` -> int, ``true`` -> bool, ``null`` -> None, ``"5000"`` -> str,
    ``{"a": 1}`` -> dict, ``hello`` -> "hello".
    """
    try:
        return json.loads(text)
    except ValueError:
        return text


def parse_override(text: str) -> tuple[str, object]:
    """Split ``dotted.path=value`` into ``(path, parsed value)``."""
    if "=" not in text:
        raise ValueError(f"invalid override {text!r}; expected dotted.path=value")
    path, _, raw = text.partition("=")
    path = path.strip()
    if not path:
        raise ValueError(f"invalid override {text!r}; the path is empty")
    return path, parse_value(raw)


def apply_override(document: object, dotted_path: str, value: object) -> None:
    """Set ``dotted_path`` (``data.object.amount``, ``commits.0.message``) in place.

    Missing (or null) object keys are created; list indices must exist, and a
    scalar in the way is an error rather than being silently replaced.
    """
    parts = dotted_path.split(".")
    node = document
    for position, part in enumerate(parts):
        last = position == len(parts) - 1
        if isinstance(node, list):
            try:
                index = int(part)
                node[index]  # noqa: B018 - bounds check
            except (ValueError, IndexError):
                raise ValueError(
                    f"{dotted_path!r}: {part!r} is not a valid index for a list of {len(node)}"
                ) from None
            if last:
                node[index] = value
            else:
                node = node[index]
        elif isinstance(node, dict):
            if last:
                node[part] = value
            else:
                if node.get(part) is None:
                    node[part] = {}
                elif not isinstance(node[part], (dict, list)):
                    raise ValueError(
                        f"{dotted_path!r}: cannot descend into {type(node[part]).__name__} at {part!r}"
                    )
                node = node[part]
        else:
            raise ValueError(f"{dotted_path!r}: cannot descend into {type(node).__name__} at {part!r}")


def _serialize(document: object, body_format: str) -> bytes:
    if body_format == "form":
        if not isinstance(document, dict):
            raise ValueError("form bodies must be a flat object")
        flat = {
            key: value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
            for key, value in document.items()
        }
        return urlencode(flat).encode("ascii")
    if body_format == "json-pretty":
        return json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8")
    return json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def render_sample(
    template: SampleTemplate,
    *,
    overrides: list[str] | dict[str, object] | None = None,
    now: int | None = None,
    seed: int | None = None,
) -> RenderedSample:
    """Fill a template with fresh ids/timestamps and apply ``--set`` overrides."""
    renderer = _Renderer(int(time.time()) if now is None else now, random.Random(seed))
    document = renderer.render(json.loads(json.dumps(template.body)))
    headers = {str(k): str(v) for k, v in renderer.render(dict(template.headers)).items()}
    items = overrides.items() if isinstance(overrides, dict) else (
        parse_override(text) for text in (overrides or [])
    )
    for path, value in items:
        apply_override(document, path, value)
    if not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = template.content_type
    return RenderedSample(
        provider=template.provider,
        event=template.event,
        method=template.method,
        path=template.path,
        headers=headers,
        body=_serialize(document, template.body_format),
        document=document,
    )


def resolve_url(url: str, sample_path: str) -> str:
    """Use the sample's own path when ``url`` has none (``http://host:port``)."""
    parts = urlsplit(url)
    if parts.path in ("", "/"):
        return urlunsplit((parts.scheme, parts.netloc, sample_path, parts.query, parts.fragment))
    return url


def build_sample_request(
    rendered: RenderedSample,
    url: str,
    *,
    secret: str | bytes | None = None,
    scheme: GenericScheme | None = None,
    now: int | None = None,
    extra_headers: dict[str, str] | None = None,
) -> ReplayRequest:
    """The HTTP request for ``rendered``, signed when ``secret`` is given.

    GitHub samples also get the legacy ``X-Hub-Signature`` (SHA-1) header,
    like real deliveries.
    """
    event = StoredEvent(
        method=rendered.method,
        path=rendered.path,
        headers=dict(rendered.headers),
        body=rendered.body,
        provider=rendered.provider,
    )
    request = build_replay_request(
        event,
        resolve_url(url, rendered.path),
        secret=secret,
        scheme=scheme,
        now=now,
        extra_headers=extra_headers,
    )
    if secret is not None and rendered.provider == "github":
        set_header(request.headers, GITHUB_LEGACY_HEADER, sign_github_legacy(secret, request.body))
    return request
