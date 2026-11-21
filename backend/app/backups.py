"""Configuration backups of switches: files in the configured directory plus rows in ``config_backups``.

Files are named ``<directory>/<switch_id>/<UTC %Y%m%dT%H%M%SZ>-<trigger>.cfg`` (``.cfg.smbk`` when
password-encrypted, see ``backup_crypto``), written via a temporary file and ``os.replace`` with
mode 0600 in 0700 directories. Rows store absolute paths, so changing the directory setting
moves nothing. ``sha256`` is the hash of the normalized text (volatile lines removed); a backup
identical to the switch's latest one is not stored again. Only the newest ``retention`` backups
per switch are kept.
"""

import hashlib
import logging
import os
import re
import secrets
import sqlite3
import threading
from collections.abc import Callable, Iterable
from pathlib import Path

from . import backup_crypto, system_settings
from . import database as db
from .auth.sessions import now, timestamp
from .i18n import t

logger = logging.getLogger("switchsteward.backups")

TRIGGERS = ("before-save", "after-save", "before-restore", "before-change", "after-change")
SOURCES = ("startup", "running")
PLAIN_SUFFIX = ".cfg"
ENCRYPTED_SUFFIX = ".cfg.smbk"

# Serializes creation, retention and re-encryption within this server process.
_lock = threading.Lock()


def normalize(text: str, patterns: Iterable[str] = ()) -> str:
    """Text used for hashing and diffs: unified line ends, no trailing blanks, volatile lines removed."""
    compiled = [re.compile(pattern) for pattern in patterns]
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    kept = [line.rstrip() for line in lines if not any(pattern.search(line) for pattern in compiled)]
    return "\n".join(kept).strip("\n") + "\n"


def content_hash(text: str, patterns: Iterable[str] = ()) -> str:
    return hashlib.sha256(normalize(text, patterns).encode("utf-8")).hexdigest()


def _public(row) -> dict:
    return {
        "id": row["id"],
        "switch_id": row["switch_id"],
        "created_at": row["created_at"],
        "trigger": row["trigger"],
        "source": row["source"],
        "encrypted": bool(row["encrypted"]),
        "sha256": row["sha256"],
        "size": row["size"],
        "created_by": row["created_by"],
    }


def list_backups(switch_id: int) -> list[dict]:
    """Backups of a switch, newest first (without content and file path)."""
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM config_backups WHERE switch_id = ? ORDER BY created_at DESC, id DESC", (switch_id,),
        ).fetchall()
    return [_public(row) for row in rows]


def get_backup(switch_id: int, backup_id: int) -> dict | None:
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM config_backups WHERE id = ? AND switch_id = ?", (backup_id, switch_id),
        ).fetchone()
    return _public(row) if row else None


def _write_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _temp_path(target: Path) -> Path:
    return target.with_name(f".{target.name}.{secrets.token_hex(4)}.tmp")


def _atomic_write(path: Path, payload: bytes) -> None:
    temp = _temp_path(path)
    _write_file(temp, payload)
    try:
        os.replace(temp, path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def _new_file(directory: Path, stem: str, suffix: str, payload: bytes) -> Path:
    for attempt in range(1, 1000):
        name = stem if attempt == 1 else f"{stem}-{attempt}"
        # A name is taken in either form: re-encryption switches the suffix of existing files.
        if any((directory / f"{name}{candidate}").exists() for candidate in (PLAIN_SUFFIX, ENCRYPTED_SUFFIX)):
            continue
        path = directory / f"{name}{suffix}"
        _atomic_write(path, payload)
        return path
    raise OSError(f"no free backup file name for {stem} in {directory}")


def _unlink(path: str) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except OSError as exc:
        logger.warning("Expired backup file %s could not be deleted: %s", path, exc)


def create(
    switch: dict, text: str, trigger: str, source: str, username: str, *, volatile_patterns: Iterable[str] = (),
) -> dict | None:
    """Store a backup of ``text``; returns the new backup (``id`` …) or None when unchanged.

    ``volatile_patterns`` are the driver's ``volatile_config_patterns``. Raises ``ValueError``
    (German message) when the directory is unusable or no password is stored, ``OSError`` on
    write errors.
    """
    if trigger not in TRIGGERS or source not in SOURCES:
        raise ValueError(f"invalid backup trigger/source {trigger}/{source}")
    patterns = tuple(volatile_patterns)
    digest = content_hash(text, patterns)
    with _lock:
        settings = system_settings.load_backups()
        directory = system_settings.storage_dir(settings.directory)
        password = None
        if settings.encryption == "password":
            password = system_settings.backup_password(settings)
            if not password:
                raise ValueError(t("Für die Backup-Verschlüsselung ist kein Passwort hinterlegt."))
        with db.get_conn() as conn:
            last = conn.execute(
                "SELECT sha256 FROM config_backups WHERE switch_id = ? ORDER BY created_at DESC, id DESC LIMIT 1",
                (switch["id"],),
            ).fetchone()
        if last is not None and last["sha256"] == digest:
            logger.info("Backup of switch %s (%s) unchanged; not stored again", switch["id"], trigger)
            return None

        created = now()
        payload = backup_crypto.encrypt(text, password) if password else text.encode("utf-8")
        switch_dir = directory / str(int(switch["id"]))
        switch_dir.mkdir(mode=0o700, exist_ok=True)
        path = _new_file(
            switch_dir, f"{created:%Y%m%dT%H%M%SZ}-{trigger}", ENCRYPTED_SUFFIX if password else PLAIN_SUFFIX, payload,
        )
        try:
            with db.get_conn() as conn:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.execute(
                    "INSERT INTO config_backups (switch_id, created_at, trigger, source, path, encrypted, sha256, "
                    "size, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (switch["id"], timestamp(created), trigger, source, str(path), int(bool(password)), digest,
                     len(text.encode("utf-8")), username),
                )
                backup_id = cursor.lastrowid
                expired = conn.execute(
                    "SELECT id, path FROM config_backups WHERE switch_id = ? "
                    "ORDER BY created_at DESC, id DESC LIMIT -1 OFFSET ?",
                    (switch["id"], settings.retention),
                ).fetchall()
                conn.executemany("DELETE FROM config_backups WHERE id = ?", [(row["id"],) for row in expired])
                row = conn.execute("SELECT * FROM config_backups WHERE id = ?", (backup_id,)).fetchone()
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    for old in expired:
        _unlink(old["path"])
    logger.info("Backup %s of switch %s stored (%s, %s)", backup_id, switch["id"], trigger, source)
    return _public(row)


def _decode(row, data: bytes, password: str | None) -> str:
    if row["encrypted"]:
        return backup_crypto.decrypt(data, password or "")
    return data.decode("utf-8")


def read_text(backup_id: int) -> str:
    """Plain text of a backup; ``LookupError`` if unknown, ``ValueError`` if unreadable."""
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM config_backups WHERE id = ?", (backup_id,)).fetchone()
    if row is None:
        raise LookupError(t("Backup nicht gefunden."))
    path = Path(row["path"])
    try:
        data = path.read_bytes()
    except OSError:
        raise ValueError(t("Backup-Datei fehlt oder ist nicht lesbar: {file}", file=str(path))) from None
    try:
        return _decode(row, data, system_settings.backup_password(system_settings.load_backups()))
    except UnicodeDecodeError:
        raise ValueError(t("Backup-Datei fehlt oder ist nicht lesbar: {file}", file=str(path))) from None


def _target_path(path: Path, encrypted: bool) -> Path:
    name = path.name
    for suffix in (ENCRYPTED_SUFFIX, PLAIN_SUFFIX):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return path.with_name(name + (ENCRYPTED_SUFFIX if encrypted else PLAIN_SUFFIX))


def _conversion_error(path: Path, error: Exception) -> ValueError:
    detail = getattr(error, "strerror", None) or str(error)
    return ValueError(t("Backup {file} konnte nicht umgewandelt werden: {error}", file=path.name, error=detail))


def _undo(moved: list[tuple[Path, Path, Path | None]]) -> None:
    for old, new, displaced in reversed(moved):
        try:
            if displaced is not None:
                os.replace(displaced, old)
            else:
                new.unlink(missing_ok=True)
        except OSError as exc:
            logger.error("Re-encryption of %s could not be rolled back: %s", old, exc)


def reencrypt_all(
    old_settings: system_settings.BackupSettings,
    new_mode: str,
    new_password: str | None,
    *,
    commit_with: Callable[[sqlite3.Connection], None] | None = None,
) -> int:
    """Convert every backup file to ``new_mode`` (``none``/``password``); returns the number converted.

    All new contents are written to temporary files first; only when that succeeded for every
    file are they moved into place and the rows updated in one transaction (``commit_with`` runs
    in the same transaction, e.g. to store the new settings). On any error nothing changes and a
    ``ValueError`` names the affected file. Rows whose file no longer exists are removed.
    """
    if new_mode not in ("none", "password"):
        raise ValueError(f"invalid backup encryption mode {new_mode}")
    if new_mode == "password" and not new_password:
        raise ValueError(t("Für die Backup-Verschlüsselung ist ein Passwort erforderlich."))
    old_password = system_settings.backup_password(old_settings)
    encrypt = new_mode == "password"
    staged: list[tuple[int, Path, Path, Path]] = []
    moved: list[tuple[Path, Path, Path | None]] = []
    missing: list[int] = []
    with _lock:
        try:
            with db.get_conn() as conn:
                rows = conn.execute("SELECT id, path, encrypted FROM config_backups ORDER BY id").fetchall()
            for row in rows:
                old_path = Path(row["path"])
                if not old_path.exists():
                    missing.append(row["id"])
                    continue
                try:
                    text = _decode(row, old_path.read_bytes(), old_password)
                    payload = backup_crypto.encrypt(text, new_password) if encrypt else text.encode("utf-8")
                    new_path = _target_path(old_path, encrypt)
                    temp = _temp_path(new_path)
                    _write_file(temp, payload)
                except (OSError, ValueError) as exc:
                    raise _conversion_error(old_path, exc) from None
                staged.append((row["id"], old_path, new_path, temp))

            with db.get_conn() as conn:
                conn.execute("BEGIN IMMEDIATE")
                for _, old_path, new_path, temp in staged:
                    displaced = None
                    try:
                        if new_path == old_path:
                            displaced = _temp_path(old_path)
                            os.replace(old_path, displaced)
                        os.replace(temp, new_path)
                    except OSError as exc:
                        if displaced is not None and displaced.exists():
                            os.replace(displaced, old_path)
                        raise _conversion_error(old_path, exc) from None
                    moved.append((old_path, new_path, displaced))
                conn.executemany(
                    "UPDATE config_backups SET path = ?, encrypted = ? WHERE id = ?",
                    [(str(new_path), int(encrypt), row_id) for row_id, _, new_path, _ in staged],
                )
                conn.executemany("DELETE FROM config_backups WHERE id = ?", [(row_id,) for row_id in missing])
                if commit_with is not None:
                    commit_with(conn)
        except BaseException:
            _undo(moved)
            for *_, temp in staged:
                temp.unlink(missing_ok=True)
            raise
    for old_path, _new_path, displaced in moved:
        try:
            (displaced or old_path).unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Old backup file %s could not be deleted: %s", displaced or old_path, exc)
    if missing:
        logger.warning("Removed %d backup rows whose files no longer exist", len(missing))
    logger.info("Re-encrypted %d backups (mode=%s)", len(staged), new_mode)
    return len(staged)
