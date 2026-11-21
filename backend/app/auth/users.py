"""Persistence of local and external (AD/Entra) user accounts."""

import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field

from .. import database as db
from .sessions import timestamp

LOCAL = "local"
AD = "ad"
ENTRA = "entra"
PROVIDERS = (LOCAL, AD, ENTRA)
# Local account names: letters, digits and . _ @ - (1–64 characters).
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


@dataclass(frozen=True)
class User:
    id: int
    provider: str
    subject: str
    username: str
    display_name: str | None
    email: str | None
    assigned_role: str | None
    enabled: bool
    last_role: str | None
    last_login_at: str | None
    created_at: str
    password_hash: str | None = field(default=None, repr=False)


def local_subject(username: str) -> str:
    return username.strip().casefold()


@contextmanager
def _connection(conn: sqlite3.Connection | None):
    if conn is not None:
        yield conn
        return
    with db.get_conn() as own:
        yield own


def _user(row) -> User | None:
    if row is None:
        return None
    return User(
        id=row["id"],
        provider=row["provider"],
        subject=row["subject"],
        username=row["username"],
        display_name=row["display_name"],
        email=row["email"],
        assigned_role=row["assigned_role"],
        enabled=bool(row["enabled"]),
        last_role=row["last_role"],
        last_login_at=row["last_login_at"],
        created_at=row["created_at"],
        password_hash=row["password_hash"],
    )


def get_user(user_id: int, *, conn: sqlite3.Connection | None = None) -> User | None:
    with _connection(conn) as connection:
        return _user(connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())


def find_user(provider: str, subject: str, *, conn: sqlite3.Connection | None = None) -> User | None:
    with _connection(conn) as connection:
        return _user(connection.execute(
            "SELECT * FROM users WHERE provider = ? AND subject = ?", (provider, subject),
        ).fetchone())


def find_local_user(username: str, *, conn: sqlite3.Connection | None = None) -> User | None:
    return find_user(LOCAL, local_subject(username), conn=conn)


def list_users(*, user_id: int | None = None, conn: sqlite3.Connection | None = None) -> list[dict]:
    """Accounts (all, or the one with ``user_id``) with their active session count; never password hashes."""
    with _connection(conn) as connection:
        rows = connection.execute(
            """
            SELECT u.id, u.provider, u.username, u.display_name, u.email, u.assigned_role, u.enabled,
                   u.last_role, u.last_login_at, u.created_at,
                   (SELECT COUNT(*) FROM sessions AS s WHERE s.user_id = u.id AND s.expires_at > ?)
                       AS active_sessions
            FROM users AS u
            WHERE ? IS NULL OR u.id = ?
            ORDER BY u.provider, u.username COLLATE NOCASE, u.id
            """,
            (timestamp(), user_id, user_id),
        ).fetchall()
    return [{**dict(row), "enabled": bool(row["enabled"])} for row in rows]


def create_local_user(
    conn: sqlite3.Connection, username: str, password_hash: str, role: str, display_name: str | None = None,
) -> int:
    """Insert a local account; raises ``sqlite3.IntegrityError`` for a duplicate (case-insensitive) name."""
    cursor = conn.execute(
        "INSERT INTO users (provider, subject, username, display_name, password_hash, assigned_role, enabled) "
        "VALUES ('local', ?, ?, ?, ?, ?, 1)",
        (local_subject(username), username.strip(), display_name, password_hash, role),
    )
    return cursor.lastrowid


def upsert_external_user(
    conn: sqlite3.Connection, provider: str, subject: str, username: str, display_name: str | None,
    email: str | None,
) -> User:
    """Create or refresh an AD/Entra account record from the directory's current attributes."""
    conn.execute(
        """
        INSERT INTO users (provider, subject, username, display_name, email)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(provider, subject) DO UPDATE SET
            username = excluded.username, display_name = excluded.display_name, email = excluded.email,
            updated_at = ?
        """,
        (provider, subject, username, display_name, email, timestamp()),
    )
    return find_user(provider, subject, conn=conn)


def record_login(conn: sqlite3.Connection, user_id: int, role: str | None) -> None:
    current = timestamp()
    conn.execute(
        "UPDATE users SET last_role = ?, last_login_at = ?, updated_at = ? WHERE id = ?",
        (role, current, current, user_id),
    )
