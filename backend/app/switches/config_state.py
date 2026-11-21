"""Save state of the changes made through SwitchSteward and the armed rollback timer per switch.

``switch_config_state.status``: ``untracked`` (no change recorded yet), ``dirty`` (changes
not saved on the device), ``saved`` (saved through SwitchSteward), ``unknown`` (reload,
restore or expired rollback: the device state must be re-checked). Times are UTC in the
format of ``auth.sessions.timestamp`` ("YYYY-MM-DD HH:MM:SS").
"""

from datetime import timedelta

from .. import database as db
from ..auth import sessions

_UNTRACKED = {"status": "untracked", "last_change_at": None, "last_change_by": None, "last_saved_at": None}


def state(switch_id: int) -> dict:
    """{status, last_change_at, last_change_by, last_saved_at}."""
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT status, last_change_at, last_change_by, last_saved_at FROM switch_config_state WHERE switch_id = ?",
            (switch_id,),
        ).fetchone()
    return dict(row) if row else dict(_UNTRACKED)


def _store(switch_id: int, status: str, *, changed_by: str | None = None, saved: bool = False) -> None:
    now = sessions.timestamp()
    change_at = now if changed_by is not None else None
    saved_at = now if saved else None
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO switch_config_state "
            "(switch_id, status, last_change_at, last_change_by, last_saved_at, updated_at) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(switch_id) DO UPDATE SET status = excluded.status, "
            "last_change_at = COALESCE(excluded.last_change_at, last_change_at), "
            "last_change_by = COALESCE(excluded.last_change_by, last_change_by), "
            "last_saved_at = COALESCE(excluded.last_saved_at, last_saved_at), "
            "updated_at = excluded.updated_at",
            (switch_id, status, change_at, changed_by, saved_at, now),
        )


def mark_dirty(switch_id: int, username: str) -> None:
    _store(switch_id, "dirty", changed_by=username)


def mark_saved(switch_id: int) -> None:
    _store(switch_id, "saved", saved=True)


def mark_unknown(switch_id: int) -> None:
    _store(switch_id, "unknown")


# --- Rollback timer ----------------------------------------------------------------------


def arm(switch_id: int, mechanism: str, minutes: int, username: str) -> dict:
    """Record an armed rollback timer; returns {mechanism, armed_at, expires_at, armed_by}."""
    now = sessions.now()
    entry = {
        "mechanism": mechanism,
        "armed_at": sessions.timestamp(now),
        "expires_at": sessions.timestamp(now + timedelta(minutes=minutes)),
        "armed_by": username,
    }
    with db.get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO switch_rollbacks (switch_id, mechanism, armed_at, expires_at, armed_by) "
            "VALUES (?,?,?,?,?)",
            (switch_id, entry["mechanism"], entry["armed_at"], entry["expires_at"], entry["armed_by"]),
        )
    return entry


def clear(switch_id: int) -> None:
    with db.get_conn() as conn:
        conn.execute("DELETE FROM switch_rollbacks WHERE switch_id = ?", (switch_id,))


def pending(switch_id: int) -> dict | None:
    """Armed rollback ({..., "expired": False}); an expired one is removed, marks the state
    ``unknown`` (the device rolled back by itself) and is returned once with ``"expired": True``."""
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT mechanism, armed_at, expires_at, armed_by FROM switch_rollbacks WHERE switch_id = ?",
            (switch_id,),
        ).fetchone()
        if row is None:
            return None
        entry = dict(row)
        if entry["expires_at"] > sessions.timestamp():
            return {**entry, "expired": False}
        conn.execute("DELETE FROM switch_rollbacks WHERE switch_id = ?", (switch_id,))
    mark_unknown(switch_id)
    return {**entry, "expired": True}
