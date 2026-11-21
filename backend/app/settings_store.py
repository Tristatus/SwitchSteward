"""Typed settings stored as JSON in ``app_settings`` (key → Pydantic model).

An unreadable stored value falls back to the model defaults (fail closed) and is reported in
the system log; values are never logged because they may contain secrets.
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from . import database as db
from .auth.sessions import timestamp

logger = logging.getLogger("switchsteward.settings")

M = TypeVar("M", bound=BaseModel)


@contextmanager
def connection(conn: sqlite3.Connection | None):
    """Use ``conn`` or open (and commit) an own connection."""
    if conn is not None:
        yield conn
        return
    with db.get_conn() as own:
        yield own


def load(key: str, model: type[M], conn: sqlite3.Connection | None = None) -> M:
    with connection(conn) as current:
        row = current.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    if row is None:
        return model()
    try:
        return model.model_validate(json.loads(row[0]))
    except (ValueError, ValidationError) as exc:
        logger.error("Stored setting %s is invalid and is ignored (%s)", key, type(exc).__name__)
        return model()


def store(key: str, value: BaseModel, conn: sqlite3.Connection | None = None) -> None:
    with connection(conn) as current:
        current.execute(
            "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, value.model_dump_json(), timestamp()),
        )
