"""Authentication settings and group-to-role mappings stored in the database.

Settings live in ``app_settings`` as JSON under ``auth.general``, ``auth.ad`` and ``auth.entra``
and are edited in the administration workspace.
"""

import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .. import config, settings_store
from ..i18n import t

GENERAL_KEY = "auth.general"
AD_KEY = "auth.ad"
ENTRA_KEY = "auth.entra"
ENTRA_CALLBACK_PATH = "/api/auth/entra/callback"
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _reject_control_characters(value: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(t("Steuerzeichen und Zeilenumbrüche sind nicht erlaubt."))
    return value


def is_guid(value: str) -> bool:
    return bool(_GUID.fullmatch(value))


def validate_public_base_url(value: str) -> str:
    """``https://…`` or ``http://localhost|127.0.0.1|[::1]…`` without path, query or trailing slash."""
    _reject_control_characters(value)
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError:
        url, port = None, None
    valid = (
        url is not None
        and url.hostname
        and url.username is None
        and url.password is None
        and url.path == ""
        and not url.query
        and not url.fragment
        and "?" not in value
        and "#" not in value
        and (port is None or 1 <= port <= 65_535)
        and (url.scheme == "https" or (url.scheme == "http" and url.hostname in _LOCAL_HOSTS))
    )
    if not valid:
        raise ValueError(t(
            "Die öffentliche Adresse muss eine https://-URL (http:// nur für localhost) ohne Pfad, "
            "Query oder abschließenden Schrägstrich sein."
        ))
    return value


def parse_server_url(value: str) -> tuple[str, int, bool]:
    """Return ``(host, port, use_ssl)`` of an ``ldap://`` or ``ldaps://`` URL; raise ``ValueError``."""
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ValueError(t("Ungültige AD-Server-URL.")) from exc
    if parsed.scheme.lower() not in {"ldap", "ldaps"} or not parsed.hostname:
        raise ValueError(t("AD-Server müssen als ldap://host[:port] oder ldaps://host[:port] angegeben werden."))
    if (
        parsed.username is not None or parsed.password is not None or parsed.path not in {"", "/"}
        or parsed.query or parsed.fragment
    ):
        raise ValueError(t("AD-Server-URLs dürfen keine Zugangsdaten, Pfade, Querys oder Fragmente enthalten."))
    try:
        port = parsed.port if parsed.port is not None else (636 if parsed.scheme.lower() == "ldaps" else 389)
    except ValueError as exc:
        raise ValueError(t("Ungültiger Port in der AD-Server-URL.")) from exc
    if not 1 <= port <= 65535:
        raise ValueError(t("Ungültiger Port in der AD-Server-URL."))
    return parsed.hostname, port, parsed.scheme.lower() == "ldaps"


class GeneralAuthSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    public_base_url: str | None = Field(default=None, max_length=2048)

    @field_validator("public_base_url")
    @classmethod
    def validate_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return validate_public_base_url(value) if value else None


class AdSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    servers: list[str] = Field(default_factory=list, max_length=10)
    domain: str = Field(default="", max_length=253)
    base_dn: str = Field(default="", max_length=1024)
    tls_validate: bool = True
    ca_cert_file: str | None = Field(default=None, max_length=4096)
    connect_timeout_seconds: int = Field(default=5, ge=1, le=120)
    receive_timeout_seconds: int = Field(default=10, ge=1, le=300)
    allow_insecure_ldap: bool = False
    allow_unverified_ldaps: bool = False
    default_role: Literal["none", "viewer"] = "none"

    @field_validator("servers")
    @classmethod
    def normalize_servers(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            value = _reject_control_characters(value.strip())
            if len(value) > 1024:
                raise ValueError(t("AD-Server-URLs dürfen höchstens 1024 Zeichen lang sein."))
            if value:
                normalized.append(value)
        return normalized

    @field_validator("domain", "base_dn")
    @classmethod
    def normalize_text(cls, value: str) -> str:
        return _reject_control_characters(value.strip())

    @field_validator("ca_cert_file")
    @classmethod
    def normalize_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _reject_control_characters(value.strip()) or None

    @model_validator(mode="after")
    def validate_enabled(self):
        if not self.enabled:
            return self
        if not self.servers or not self.domain or not self.base_dn:
            raise ValueError(t("AD-Server, Domain und Base-DN müssen gesetzt sein."))
        parsed = [parse_server_url(value) for value in self.servers]
        if any(not use_ssl for _, _, use_ssl in parsed) and not self.allow_insecure_ldap:
            raise ValueError(t(
                "Unverschlüsseltes LDAP ist deaktiviert. LDAPS verwenden oder die unsichere Ausnahme explizit "
                "aktivieren."
            ))
        if any(use_ssl for _, _, use_ssl in parsed) and not self.tls_validate and not self.allow_unverified_ldaps:
            raise ValueError(t(
                "LDAPS-Zertifikatsprüfung darf nur mit expliziter unsicherer Ausnahme deaktiviert werden."
            ))
        return self


def ad_ca_cert_path(ad: AdSettings) -> Path | None:
    """Absolute CA file path; relative paths are resolved against the configuration directory."""
    if not ad.ca_cert_file:
        return None
    path = Path(ad.ca_cert_file).expanduser()
    if not path.is_absolute():
        path = config.settings.config_file.parent / path
    return path.resolve()


def check_ad_files(ad: AdSettings) -> None:
    """Raise ``ValueError`` when the configured CA file does not exist."""
    path = ad_ca_cert_path(ad)
    if path is not None and not path.is_file():
        raise ValueError(t("Die angegebene AD-CA-Datei existiert nicht."))


class EntraSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    tenant_id: str = Field(default="", max_length=64)
    client_id: str = Field(default="", max_length=64)
    client_secret_enc: str | None = None
    cloud: Literal["global", "usgov", "china"] = "global"
    default_role: Literal["none", "viewer"] = "none"

    @field_validator("tenant_id", "client_id")
    @classmethod
    def normalize_id(cls, value: str) -> str:
        return _reject_control_characters(value.strip().lower())

    @model_validator(mode="after")
    def validate_enabled(self):
        if not self.enabled:
            return self
        if not is_guid(self.tenant_id) or not is_guid(self.client_id):
            raise ValueError(t("Tenant-ID und Client-ID müssen GUIDs sein."))
        if not self.client_secret_enc:
            raise ValueError(t("Für Entra ID muss ein Client-Secret hinterlegt sein."))
        return self


def check_entra_ready(entra: EntraSettings, general: GeneralAuthSettings) -> None:
    """An enabled Entra sign-in also needs the public base URL for its redirect URI."""
    if entra.enabled and not general.public_base_url:
        raise ValueError(t("Für Entra ID muss die öffentliche Adresse (public_base_url) gesetzt sein."))


def entra_redirect_uri(general: GeneralAuthSettings) -> str | None:
    """Redirect URI registered in Entra; never derived from the request's Host header."""
    return f"{general.public_base_url}{ENTRA_CALLBACK_PATH}" if general.public_base_url else None


@dataclass(frozen=True)
class GroupMapping:
    id: int
    provider: str
    group_id: str
    label: str | None
    role: str


# An unreadable stored provider configuration falls back to the defaults (disabled): fail closed.
def load_general(conn: sqlite3.Connection | None = None) -> GeneralAuthSettings:
    return settings_store.load(GENERAL_KEY, GeneralAuthSettings, conn)


def load_ad(conn: sqlite3.Connection | None = None) -> AdSettings:
    return settings_store.load(AD_KEY, AdSettings, conn)


def load_entra(conn: sqlite3.Connection | None = None) -> EntraSettings:
    return settings_store.load(ENTRA_KEY, EntraSettings, conn)


_KEYS: dict[type[BaseModel], str] = {GeneralAuthSettings: GENERAL_KEY, AdSettings: AD_KEY, EntraSettings: ENTRA_KEY}


def save(value: BaseModel, *, conn: sqlite3.Connection | None = None) -> None:
    settings_store.store(_KEYS[type(value)], value, conn=conn)


def _mapping(row) -> GroupMapping:
    return GroupMapping(id=row["id"], provider=row["provider"], group_id=row["group_id"], label=row["label"],
                        role=row["role"])


def list_mappings(provider: str | None = None, *, conn: sqlite3.Connection | None = None) -> list[GroupMapping]:
    with settings_store.connection(conn) as connection:
        if provider is None:
            rows = connection.execute(
                "SELECT * FROM group_role_mappings ORDER BY provider, role, label COLLATE NOCASE, group_id"
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM group_role_mappings WHERE provider = ? ORDER BY role, label COLLATE NOCASE, group_id",
                (provider,),
            ).fetchall()
    return [_mapping(row) for row in rows]


def get_mapping(mapping_id: int, *, conn: sqlite3.Connection | None = None) -> GroupMapping | None:
    with settings_store.connection(conn) as connection:
        row = connection.execute("SELECT * FROM group_role_mappings WHERE id = ?", (mapping_id,)).fetchone()
    return _mapping(row) if row else None
