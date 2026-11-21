"""Lockout protection: at least one way to sign in as administrator must remain."""

import sqlite3

from fastapi import HTTPException, status

from ..i18n import t
from . import settings


class AdminLockoutError(HTTPException):
    def __init__(self, detail: str | None = None):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail or t("Die Änderung würde den letzten Administratorzugang entfernen."),
        )


def has_admin_path(conn: sqlite3.Connection) -> bool:
    if conn.execute(
        "SELECT 1 FROM users WHERE provider = 'local' AND enabled = 1 AND assigned_role = 'admin' LIMIT 1"
    ).fetchone():
        return True
    enabled_providers = [
        provider
        for provider, provider_settings in (("ad", settings.load_ad(conn)), ("entra", settings.load_entra(conn)))
        if provider_settings.enabled
    ]
    for provider in enabled_providers:
        if conn.execute(
            "SELECT 1 FROM group_role_mappings WHERE provider = ? AND role = 'admin' LIMIT 1", (provider,),
        ).fetchone():
            return True
        if conn.execute(
            "SELECT 1 FROM users WHERE provider = ? AND enabled = 1 AND assigned_role = 'admin' LIMIT 1", (provider,),
        ).fetchone():
            return True
    return False


def ensure_admin_path(conn: sqlite3.Connection) -> None:
    """Call after applying a change inside the same transaction; raises ``AdminLockoutError`` (409)."""
    if not has_admin_path(conn):
        raise AdminLockoutError()
