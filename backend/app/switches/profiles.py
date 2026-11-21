"""Global port profiles (table ``port_profiles``): stored port and security settings applied by admins."""

import json
import re

from pydantic import Field, field_validator, model_validator

from .. import database as db
from ..auth import sessions
from ..i18n import t
from .operations import ApiModel

NAME_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,64}$")
NAME_INVALID = "Der Profilname darf 1–64 Zeichen aus Buchstaben, Ziffern, Leerzeichen, Punkt, Unterstrich und Bindestrich enthalten."
SETTINGS_EMPTY = "Ein Port-Profil benötigt Port- oder Sicherheitseinstellungen."
PORT_FIELD_FORBIDDEN = "Ein Port-Profil darf das Feld {field} nicht enthalten."


def _settings_dump(model, values: dict, forbidden: tuple[str, ...]) -> dict:
    for name in forbidden:
        if name in values:
            raise ValueError(t(PORT_FIELD_FORBIDDEN, field=name))
    dumped = model.model_validate({**values, "interface": "profile"}).model_dump(exclude_none=True)
    dumped.pop("interface", None)
    return dumped


class PortProfileSettings(ApiModel):
    """``port`` = port-configure body without interface/shutdown; ``security`` = port-security-configure without
    interface. Stored normalised (unset fields dropped)."""

    port: dict | None = None
    security: dict | None = None

    @field_validator("port")
    @classmethod
    def validate_port(cls, value: dict | None) -> dict | None:
        if value is None:
            return None
        from .ops.ports import PortConfigureIn

        return _settings_dump(PortConfigureIn, value, ("interface", "shutdown")) or None

    @field_validator("security")
    @classmethod
    def validate_security(cls, value: dict | None) -> dict | None:
        if value is None:
            return None
        from .ops.security import PortSecurityIn

        return _settings_dump(PortSecurityIn, value, ("interface",)) or None

    @model_validator(mode="after")
    def require_settings(self):
        if not self.port and not self.security:
            raise ValueError(t(SETTINGS_EMPTY))
        return self


class PortProfileIn(ApiModel):
    name: str = Field(min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=200)
    settings: PortProfileSettings

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()
        if not NAME_RE.fullmatch(value):
            raise ValueError(t(NAME_INVALID))
        return value

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError(t("Die Beschreibung enthält ungültige Zeichen."))
        return value or None


def _row(row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "settings": json.loads(row["settings"]),
        "updated_by": row["updated_by"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_profiles() -> list[dict]:
    with db.get_conn() as conn:
        rows = conn.execute("SELECT * FROM port_profiles ORDER BY name COLLATE NOCASE").fetchall()
    return [_row(row) for row in rows]


def get(profile_id: int) -> dict | None:
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM port_profiles WHERE id = ?", (profile_id,)).fetchone()
    return _row(row) if row else None


def create(body: PortProfileIn, username: str) -> dict:
    """Raises ``sqlite3.IntegrityError`` for a duplicate name."""
    now = sessions.timestamp()
    with db.get_conn() as conn:
        cursor = conn.execute(
            "INSERT INTO port_profiles (name, description, settings, updated_by, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (body.name, body.description, _settings_json(body), username, now, now),
        )
        profile_id = cursor.lastrowid
    return get(profile_id)


def update(profile_id: int, body: PortProfileIn, username: str) -> dict | None:
    """None when the profile does not exist; raises ``sqlite3.IntegrityError`` for a duplicate name."""
    with db.get_conn() as conn:
        cursor = conn.execute(
            "UPDATE port_profiles SET name = ?, description = ?, settings = ?, updated_by = ?, updated_at = ?"
            " WHERE id = ?",
            (body.name, body.description, _settings_json(body), username, sessions.timestamp(), profile_id),
        )
        if cursor.rowcount == 0:
            return None
    return get(profile_id)


def delete(profile_id: int) -> dict | None:
    profile = get(profile_id)
    if profile is None:
        return None
    with db.get_conn() as conn:
        conn.execute("DELETE FROM port_profiles WHERE id = ?", (profile_id,))
    return profile


def _settings_json(body: PortProfileIn) -> str:
    return json.dumps(body.settings.model_dump(exclude_none=True), sort_keys=True)
