"""Single-use, expiring change previews kept in server memory.

A preview belongs to the session that created it (username + CSRF token) and to the switch
address/type/credential revision at preview time. Plans with secrets never leave the
server; only the redacted lines are stored and compared.
"""

import hashlib
import hmac
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .. import database as db
from ..auth import Principal
from ..i18n import t
from .errors import ChangeConflict

_PREVIEW_SECONDS = 300
_MAX_PREVIEWS = 256
_GUARD = threading.Lock()
_PREVIEWS: "OrderedDict[str, Preview]" = OrderedDict()

INVALID_MESSAGE = "Die Vorschau ist abgelaufen oder gehört zu einer anderen Sitzung. Bitte neu erstellen."


@dataclass
class Preview:
    switch_id: int | None
    owner: str
    fingerprint: str
    kind: str
    params: dict
    lines: tuple[str, ...]
    basis: dict
    risk: str | None
    persistent: bool
    reloads: bool
    rollback_minutes: int | None
    rollback_available: bool
    expires: float
    expires_at: str
    used: bool = False


def owner(principal: Principal) -> str:
    return hashlib.sha256(f"{principal.username}\0{principal.csrf_token}".encode()).hexdigest()


def fingerprint(switch_id: int | None) -> str:
    """Revision token of the switch row; empty for switches without a database row."""
    return (db.switch_revision_token(switch_id) or "") if switch_id is not None else ""


def _purge() -> None:
    now = time.monotonic()
    for token in [token for token, entry in _PREVIEWS.items() if entry.expires <= now]:
        del _PREVIEWS[token]


def store(*, switch_id: int | None, principal: Principal, **values) -> tuple[str, Preview]:
    """Keep a new preview; returns (token, preview). The oldest previews are dropped beyond the limit."""
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=_PREVIEW_SECONDS)
    entry = Preview(
        switch_id=switch_id, owner=owner(principal), fingerprint=fingerprint(switch_id),
        expires=time.monotonic() + _PREVIEW_SECONDS, expires_at=expires_at.isoformat(timespec="seconds"),
        **values,
    )
    token = secrets.token_urlsafe(32)
    with _GUARD:
        _purge()
        while len(_PREVIEWS) >= _MAX_PREVIEWS:
            _PREVIEWS.popitem(last=False)
        _PREVIEWS[token] = entry
    return token, entry


def claim(token: str, switch_id: int, principal: Principal) -> Preview:
    """The unused, unexpired preview of this session and switch revision; ``preview_invalid`` otherwise."""
    with _GUARD:
        _purge()
        entry = _PREVIEWS.get(token)
    if (
        entry is None or entry.used or entry.switch_id != switch_id
        or not hmac.compare_digest(entry.owner, owner(principal))
        or not hmac.compare_digest(entry.fingerprint, fingerprint(switch_id))
    ):
        raise ChangeConflict("preview_invalid", t(INVALID_MESSAGE))
    return entry


def consume(token: str, entry: Preview) -> None:
    """Mark the preview used (single use); a concurrent consumer gets ``preview_invalid``."""
    with _GUARD:
        if entry.used or _PREVIEWS.get(token) is not entry:
            raise ChangeConflict("preview_invalid", t(INVALID_MESSAGE))
        entry.used = True
