"""Operations settings (administration → "Betrieb") stored in ``app_settings``.

``operations.backups``: storage directory, retention and encryption of configuration backups.
``operations.transfer``: address and SFTP server through which switches download files.
``operations.firmware``: storage directory of uploaded firmware images.
"""

import ipaddress
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import config, crypto, settings_store
from .i18n import t

BACKUPS_KEY = "operations.backups"
TRANSFER_KEY = "operations.transfer"
FIRMWARE_KEY = "operations.firmware"

_HOSTNAME = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def _reject_control_characters(value: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(t("Steuerzeichen und Zeilenumbrüche sind nicht erlaubt."))
    return value


def _directory(value: str) -> str:
    value = _reject_control_characters(value.strip())
    if not value:
        raise ValueError(t("Bitte ein Verzeichnis angeben."))
    return value


def validate_transfer_base_url(value: str) -> str:
    """``http://`` or ``https://`` with host and optional port; no path, query, fragment or user info."""
    _reject_control_characters(value)
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError:
        url, port = None, None
    valid = (
        url is not None
        and url.scheme in ("http", "https")
        and url.hostname
        and url.username is None
        and url.password is None
        and url.path == ""
        and not url.query
        and not url.fragment
        and "?" not in value
        and "#" not in value
        and (port is None or 1 <= port <= 65_535)
    )
    if not valid:
        raise ValueError(t(
            "Die Transfer-Adresse muss eine http://- oder https://-URL ohne Pfad, Query oder abschließenden "
            "Schrägstrich sein."
        ))
    return value


def validate_host(value: str) -> str:
    """IPv4 address or DNS name."""
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        pass
    if not _HOSTNAME.fullmatch(value) or value.startswith(("-", ".")) or value.endswith("-"):
        raise ValueError(t("Ungültiger Hostname oder ungültige IPv4-Adresse: {value}", value=value))
    return value


class BackupSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    directory: str = Field(default="data/config-backups", max_length=1024)
    retention: int = Field(default=30, ge=1, le=1000)
    encryption: Literal["none", "password"] = "none"
    # crypto.encrypt(password) as ASCII; never returned by the API.
    password_enc: str | None = None

    @field_validator("directory")
    @classmethod
    def validate_directory(cls, value: str) -> str:
        return _directory(value)


class TransferSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Address under which *switches* reach SwitchSteward (HTTP/HTTPS downloads).
    base_url: str | None = Field(default=None, max_length=2048)
    token_minutes: int = Field(default=120, ge=5, le=1440)
    sftp_enabled: bool = False
    # Switches download from it; the read-only server only runs when sftp_enabled is set.
    sftp_bind: str = "0.0.0.0"  # noqa: S104
    sftp_port: int = Field(default=2222, ge=1, le=65_535)
    # Address switches use for SFTP; empty = host of base_url.
    sftp_host: str | None = Field(default=None, max_length=253)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return validate_transfer_base_url(value) if value else None

    @field_validator("sftp_bind")
    @classmethod
    def validate_bind(cls, value: str) -> str:
        try:
            return str(ipaddress.IPv4Address(value.strip()))
        except ValueError:
            raise ValueError(t("Die SFTP-Bind-Adresse muss eine IPv4-Adresse sein.")) from None

    @field_validator("sftp_host")
    @classmethod
    def validate_sftp_host(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return validate_host(value) if value else None


class FirmwareSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    directory: str = Field(default="data/firmware", max_length=1024)

    @field_validator("directory")
    @classmethod
    def validate_directory(cls, value: str) -> str:
        return _directory(value)


_KEYS: dict[type[BaseModel], str] = {
    BackupSettings: BACKUPS_KEY, TransferSettings: TRANSFER_KEY, FirmwareSettings: FIRMWARE_KEY,
}


def load_backups(conn: sqlite3.Connection | None = None) -> BackupSettings:
    return settings_store.load(BACKUPS_KEY, BackupSettings, conn)


def load_transfer(conn: sqlite3.Connection | None = None) -> TransferSettings:
    return settings_store.load(TRANSFER_KEY, TransferSettings, conn)


def load_firmware(conn: sqlite3.Connection | None = None) -> FirmwareSettings:
    return settings_store.load(FIRMWARE_KEY, FirmwareSettings, conn)


def save(value: BaseModel, *, conn: sqlite3.Connection | None = None) -> None:
    settings_store.store(_KEYS[type(value)], value, conn=conn)


def encrypt_password(password: str) -> str:
    return crypto.encrypt(password).decode("ascii")


def backup_password(settings: BackupSettings) -> str | None:
    """Plain backup password, or None when none is stored."""
    return crypto.decrypt(settings.password_enc.encode("ascii")) if settings.password_enc else None


def _forbidden_roots() -> tuple[Path, ...]:
    root = config.BACKEND_DIR.parent
    return tuple((root / name).resolve() for name in ("backend/app", "frontend", ".updates"))


def storage_dir(value: str) -> Path:
    """Resolve, check and create a storage directory; raise ``ValueError`` with a German message.

    Called when the setting is saved and before every use. Directories inside the application
    code, the frontend or the update staging area are refused.
    """
    path = config.resolve_runtime_path(value)
    for forbidden in _forbidden_roots():
        if path == forbidden or path.is_relative_to(forbidden):
            raise ValueError(t("Dieses Verzeichnis ist nicht erlaubt: {path}", path=str(path)))
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path):
            pass
    except OSError:
        raise ValueError(t("Verzeichnis ist nicht beschreibbar: {path}", path=str(path))) from None
    return path
