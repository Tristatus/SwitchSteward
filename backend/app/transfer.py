"""One-time download tickets through which switches fetch files from SwitchSteward.

A ticket (row in ``transfer_tokens``) grants ``max_uses`` downloads of one backup or firmware
image until ``expires_at``. Only ``sha256(secret)`` is stored. Switches use it over HTTP
(``GET /transfer/{token_id}.{secret}/{filename}``, ``transfer_routes``) or over the built-in
read-only SFTP server (user ``t{token_id}``, password ``secret``, ``sftp_server``).
Plan lines never show the token: ``location_for`` returns a ``TransferLocation`` whose
``display_url`` carries ``REDACTED``; previews use placeholders and store nothing.
"""

import hashlib
import hmac
import logging
import re
import secrets
import string
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from . import audit, backups, system_settings
from . import database as db
from .auth.sessions import now, timestamp
from .i18n import t
from .switches.drivers.plans import REDACTED, TransferLocation
from .switches.errors import InvalidInputError

logger = logging.getLogger("switchsteward.transfer")

KINDS = ("backup", "firmware")
BACKUP_MINUTES = 15
BACKUP_MAX_USES = 3
FIRMWARE_MAX_USES = 5
NETGEAR_MAX_FILENAME = 31
TOKEN_ID_RE = re.compile(r"^[0-9a-f]{12}$")
SECRET_RE = re.compile(r"^[A-Za-z0-9]{24}$")
SFTP_USER_RE = re.compile(r"^t([0-9a-f]{12})$")
_SECRET_ALPHABET = string.ascii_letters + string.digits
# Preview tickets: never stored, never redeemable; the displayed URL is identical anyway.
_PLACEHOLDER_ID = "0" * 12
_PLACEHOLDER_SECRET = "0" * 24

NO_BASE_URL = "In Administration → Betrieb ist keine Transfer-Adresse hinterlegt."
SFTP_DISABLED = "Der SFTP-Transfer ist in Administration → Betrieb nicht aktiviert."
SFTP_PORT_22 = (
    "Diese Plattform lädt per SFTP nur von Port 22. Bitte den SFTP-Port in Administration → Betrieb auf 22 setzen."
)


@dataclass(frozen=True)
class Ticket:
    token_id: str
    secret: str
    filename: str


@dataclass(frozen=True)
class Grant:
    """A valid ticket: what it grants."""

    kind: str
    ref_id: int
    switch_id: int
    filename: str


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("ascii")).hexdigest()


def issue(kind: str, ref_id: int, switch_id: int, filename: str, minutes: int, max_uses: int) -> Ticket:
    if kind not in KINDS:
        raise ValueError(f"unknown transfer kind {kind}")
    token_id = secrets.token_hex(6)
    secret = "".join(secrets.choice(_SECRET_ALPHABET) for _ in range(24))
    expires = timestamp(now() + timedelta(minutes=minutes))
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO transfer_tokens (token_id, secret_hash, kind, ref_id, switch_id, filename, expires_at, "
            "uses, max_uses) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
            (token_id, _hash(secret), kind, ref_id, switch_id, filename, expires, max_uses),
        )
    logger.info("Transfer ticket %s issued (%s %s, switch %s, %d min)", token_id, kind, ref_id, switch_id, minutes)
    return Ticket(token_id, secret, filename)


def http_url(ticket: Ticket, settings: system_settings.TransferSettings | None = None) -> str:
    base_url = (settings or system_settings.load_transfer()).base_url
    if not base_url:
        raise InvalidInputError(t(NO_BASE_URL))
    return f"{base_url}/transfer/{ticket.token_id}.{ticket.secret}/{ticket.filename}"


def _sftp_host(settings: system_settings.TransferSettings) -> str:
    if settings.sftp_host:
        return settings.sftp_host
    if settings.base_url:
        return urlsplit(settings.base_url).hostname
    raise InvalidInputError(t(NO_BASE_URL))


def sftp_target(ticket: Ticket, settings: system_settings.TransferSettings | None = None) -> dict:
    """``{host, port, user, password, path}`` of the running SFTP server for ``ticket``."""
    from . import sftp_server

    settings = settings or system_settings.load_transfer()
    status = sftp_server.status()
    if not settings.sftp_enabled or not status["running"]:
        raise InvalidInputError(t(SFTP_DISABLED))
    return {
        "host": _sftp_host(settings),
        "port": status.get("port") or settings.sftp_port,
        "user": f"t{ticket.token_id}",
        "password": ticket.secret,
        "path": f"/{ticket.filename}",
    }


def _sftp_url(user: str, host: str, port: int, path: str) -> str:
    return f"sftp://{user}@{host}{'' if port == 22 else f':{port}'}{path}"


def location_for(
    driver, kind: str, ref_id: int, switch_id: int, filename: str, *, applying: bool,
    minutes: int | None = None, max_uses: int | None = None,
) -> TransferLocation:
    """Download location for ``driver`` (its ``transfer_method``).

    ``applying=False`` (preview): placeholder credentials, nothing stored; the displayed URL
    is identical to the real one. Raises ``InvalidInputError`` when the transfer is not set up.
    """
    if kind == "firmware" and driver.id == "netgear_prosafe" and len(filename) > NETGEAR_MAX_FILENAME:
        raise InvalidInputError(t(
            "Der Dateiname ist für diese Plattform zu lang (höchstens {limit} Zeichen).", limit=NETGEAR_MAX_FILENAME,
        ))
    settings = system_settings.load_transfer()
    if minutes is None:
        minutes = BACKUP_MINUTES if kind == "backup" else settings.token_minutes
    if max_uses is None:
        max_uses = BACKUP_MAX_USES if kind == "backup" else FIRMWARE_MAX_USES
    method = driver.transfer_method
    # Check the setup before a ticket is issued.
    if method == "http":
        placeholder = Ticket(_PLACEHOLDER_ID, _PLACEHOLDER_SECRET, filename)
        http_url(placeholder, settings)
    else:
        placeholder_target = sftp_target(Ticket(_PLACEHOLDER_ID, _PLACEHOLDER_SECRET, filename), settings)
        if driver.sftp_port_22_only and placeholder_target["port"] != 22:
            raise InvalidInputError(t(SFTP_PORT_22))
    ticket = (
        issue(kind, ref_id, switch_id, filename, minutes, max_uses) if applying
        else Ticket(_PLACEHOLDER_ID, _PLACEHOLDER_SECRET, filename)
    )
    if method == "http":
        return TransferLocation(
            method="http",
            url=http_url(ticket, settings),
            display_url=f"{settings.base_url}/transfer/{REDACTED}/{filename}",
            host=urlsplit(settings.base_url).hostname,
            port=urlsplit(settings.base_url).port or (443 if settings.base_url.startswith("https") else 80),
            username="",
            password="",
            filename=filename,
        )
    target = sftp_target(ticket, settings)
    return TransferLocation(
        method="sftp",
        url=_sftp_url(target["user"], target["host"], target["port"], target["path"]),
        display_url=_sftp_url(REDACTED, target["host"], target["port"], target["path"]),
        host=target["host"],
        port=target["port"],
        username=target["user"],
        password=target["password"],
        filename=filename,
    )


def location_secrets(location: TransferLocation) -> tuple[str, ...]:
    """Values of ``location`` that plan lines, logs and results must never show (``ChangePlan.secrets``)."""
    if location.method == "sftp":
        return tuple(value for value in (location.password, location.username) if value)
    token = location.url.rsplit("/", 2)[-2]
    return (token, token.split(".", 1)[-1])


def redeem(token_id: str, secret: str, filename: str, *, consume: bool = True) -> Grant | None:
    """The ticket's grant if it is valid for ``filename``; ``consume`` counts one use.

    Without ``consume`` (SFTP login) the ticket is only checked.
    """
    if not TOKEN_ID_RE.fullmatch(token_id or "") or not SECRET_RE.fullmatch(secret or ""):
        return None
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM transfer_tokens WHERE token_id = ?", (token_id,)).fetchone()
        if row is None or not hmac.compare_digest(row["secret_hash"], _hash(secret)):
            return None
        if row["expires_at"] < timestamp() or row["uses"] >= row["max_uses"] or row["filename"] != filename:
            return None
        if consume:
            conn.execute("UPDATE transfer_tokens SET uses = uses + 1 WHERE token_id = ?", (token_id,))
    return Grant(row["kind"], row["ref_id"], row["switch_id"], row["filename"])


def ticket_filename(token_id: str, secret: str) -> str | None:
    """File name of a valid, unused-up ticket (SFTP login checks without knowing the file)."""
    if not TOKEN_ID_RE.fullmatch(token_id or "") or not SECRET_RE.fullmatch(secret or ""):
        return None
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM transfer_tokens WHERE token_id = ?", (token_id,)).fetchone()
    if row is None or not hmac.compare_digest(row["secret_hash"], _hash(secret)):
        return None
    if row["expires_at"] < timestamp() or row["uses"] >= row["max_uses"]:
        return None
    return row["filename"]


def open_payload(kind: str, ref_id: int) -> bytes | Path:
    """Backup: decrypted text as bytes; firmware: path of the image file."""
    if kind == "backup":
        return backups.read_text(ref_id).encode("utf-8")
    from . import firmware

    return firmware.image_path(ref_id)


def audit_download(grant: Grant, protocol: str, client_ip: str | None, status: str = "ok") -> None:
    switch = db.get_switch(grant.switch_id)
    audit.record(
        "transfer-download", username="system", target=switch["name"] if switch else str(grant.switch_id),
        detail=f"kind={grant.kind} ref={grant.ref_id} protocol={protocol} client_ip={client_ip or '-'}",
        status=status,
    )
