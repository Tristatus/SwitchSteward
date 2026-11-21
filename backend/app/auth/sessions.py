"""Server-side sessions in SQLite; the cookie only carries a random token.

The table stores the SHA-256 of the token, so a database leak does not expose usable cookies.
Sessions expire absolutely (no sliding renewal) and are revoked immediately when an account is
disabled, its role changes or its sign-in provider is switched off.
"""

import hashlib
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from fastapi import Response

from .. import config
from .. import database as db

COOKIE_NAME = config.settings.cookie_name
_LAST_SEEN_INTERVAL = timedelta(seconds=60)
_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
_MAX_TOKEN_LENGTH = 256


class Role(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


@dataclass(frozen=True)
class Principal:
    user_id: int
    session_id: str
    username: str
    display_name: str | None
    provider: str
    role: Role
    csrf_token: str

    @property
    def can_edit(self) -> bool:
        return self.role is Role.ADMIN

    @property
    def can_operate(self) -> bool:
        return self.role in (Role.ADMIN, Role.OPERATOR)


def now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime | None = None) -> str:
    """UTC timestamp in the format of SQLite's ``datetime('now')``."""
    return (value or now()).strftime(_TIMESTAMP_FORMAT)


def _parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, _TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def session_id_for(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@contextmanager
def _connection(conn: sqlite3.Connection | None):
    if conn is not None:
        yield conn
        return
    with db.get_conn() as own:
        yield own


def create_session(user_id: int, role: Role | str, *, conn: sqlite3.Connection | None = None) -> tuple[str, str]:
    """Store a new session and return ``(cookie_token, csrf_token)``."""
    normalized = Role(role)
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    created = now()
    expires = created + timedelta(seconds=config.settings.session_max_age)
    with _connection(conn) as connection:
        connection.execute(
            "INSERT INTO sessions (id, user_id, role, csrf_token, created_at, expires_at, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session_id_for(token), user_id, normalized.value, csrf_token, timestamp(created), timestamp(expires),
             timestamp(created)),
        )
    return token, csrf_token


def read_session(token: str | None) -> Principal | None:
    """Return the principal of a valid, unexpired session of an enabled account."""
    if not token or len(token) > _MAX_TOKEN_LENGTH:
        return None
    session_id = session_id_for(token)
    current = now()
    with db.get_conn() as conn:
        row = conn.execute(
            """
            SELECT s.id, s.role, s.csrf_token, s.last_seen_at, u.id AS user_id, u.username, u.display_name,
                   u.provider
            FROM sessions AS s JOIN users AS u ON u.id = s.user_id
            WHERE s.id = ? AND u.enabled = 1 AND s.expires_at > ?
            """,
            (session_id, timestamp(current)),
        ).fetchone()
        if row is None:
            return None
        try:
            role = Role(row["role"])
        except ValueError:
            return None
        last_seen = _parse_timestamp(row["last_seen_at"])
        if last_seen is None or current - last_seen >= _LAST_SEEN_INTERVAL:
            conn.execute("UPDATE sessions SET last_seen_at = ? WHERE id = ?", (timestamp(current), session_id))
    return Principal(
        user_id=row["user_id"],
        session_id=row["id"],
        username=row["username"],
        display_name=row["display_name"],
        provider=row["provider"],
        role=role,
        csrf_token=row["csrf_token"],
    )


def delete_session(session_id: str, *, conn: sqlite3.Connection | None = None) -> None:
    with _connection(conn) as connection:
        connection.execute("DELETE FROM sessions WHERE id = ?", (session_id,))


def revoke_user_sessions(
    user_id: int, *, keep_session_id: str | None = None, conn: sqlite3.Connection | None = None,
) -> int:
    with _connection(conn) as connection:
        cursor = connection.execute(
            "DELETE FROM sessions WHERE user_id = ? AND id IS NOT ?", (user_id, keep_session_id),
        )
        return cursor.rowcount


def revoke_provider_sessions(provider: str, *, conn: sqlite3.Connection | None = None) -> int:
    with _connection(conn) as connection:
        cursor = connection.execute(
            "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE provider = ?)", (provider,),
        )
        return cursor.rowcount


def purge_expired(*, conn: sqlite3.Connection | None = None) -> int:
    with _connection(conn) as connection:
        return connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (timestamp(),)).rowcount


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        samesite="strict",
        secure=config.settings.cookie_secure,
        max_age=config.settings.session_max_age,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        COOKIE_NAME, path="/", secure=config.settings.cookie_secure, httponly=True, samesite="strict",
    )
