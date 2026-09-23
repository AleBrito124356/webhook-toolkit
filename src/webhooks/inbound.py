"""Assess a captured request: which provider, verified or not, and why.

Shared by the receiver (at capture time), the inspector API (live, with full
hints) and the CLI (``send --store``, ``show``), so every surface gives the
same answer for the same event.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import config
from .storage import StoredEvent
from .verify import Diagnosis, GenericScheme, PROVIDERS, diagnose

UNSIGNED_REASON = "unsigned: no known signature header"


@dataclass
class Assessment:
    """Outcome of checking one capture against the configured secrets.

    ``verified`` follows :class:`StoredEvent`: ``1`` / ``0`` / ``None``.
    ``secret_state`` is ``set`` / ``placeholder`` / ``unset`` / ``unsigned``.
    ``diagnosis`` is ``None`` when nothing could be checked.
    """

    verified: int | None
    reason: str
    secret_state: str
    diagnosis: Diagnosis | None = None

    def to_dict(self) -> dict:
        return {
            "verified": self.verified,
            "reason": self.reason,
            "secret_state": self.secret_state,
            "diagnosis": self.diagnosis.to_dict() if self.diagnosis else None,
        }


def _other_secrets(provider: str) -> dict[str, str | None]:
    """Real (non-placeholder) secrets of the other providers, for swap hints."""
    return {
        name: secret
        for name, secret in config.all_secrets().items()
        if name != provider and secret
    }


def assess(
    event: StoredEvent,
    *,
    generic: GenericScheme | None = None,
    tolerance: int | None = None,
    now: int | None = None,
) -> Assessment:
    """Check ``event`` with the secret configured for its provider.

    * no provider -> ``None`` / "unsigned"
    * no secret -> ``None`` / "not checked: X is not set"
    * a real secret -> ``1`` / ``0`` with the diagnosis reason
    * a placeholder -> ``1`` when the capture was signed with that very
      placeholder (a local demo), otherwise ``None``: a real provider never
      signs with a placeholder, so "invalid" would be misleading.
    """
    provider = event.provider
    if not provider or provider not in PROVIDERS:
        return Assessment(None, UNSIGNED_REASON, "unsigned")
    status = config.secret_status(provider)
    if not status.usable:
        return Assessment(None, f"not checked: {status.describe()}", status.state)
    if provider == "generic" and generic is None:
        generic = config.generic_scheme(required=True)
    diagnosis = diagnose(
        provider,
        status.value.encode("utf-8"),
        event.body,
        event.headers,
        tolerance=config.DEFAULT_TOLERANCE if tolerance is None else tolerance,
        now=now,
        scheme=generic,
        other_secrets=_other_secrets(provider),
    )
    if status.state == "placeholder":
        if diagnosis.ok:
            return Assessment(
                1,
                f"signature valid (with the placeholder in {status.env_var}: local testing only)",
                status.state,
                diagnosis,
            )
        return Assessment(
            None,
            f"not checked: {status.env_var} is still a placeholder value",
            status.state,
            diagnosis,
        )
    return Assessment(1 if diagnosis.ok else 0, diagnosis.reason, status.state, diagnosis)
