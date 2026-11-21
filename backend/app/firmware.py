"""Firmware image store (administration → "Betrieb"): uploaded images and their metadata.

Images live as ``<firmware directory>/<filename>`` (directory from ``system_settings``), their
metadata in the table ``firmware_images`` (``platforms`` = JSON list of driver IDs chosen by
the administrator). Uploads arrive through ``SecurityMiddleware`` as a temporary file in
``<firmware directory>/.incoming`` (same file system, moved with ``os.replace``).
"""

import hashlib
import json
import logging
import os
import re
import sqlite3
from pathlib import Path

from . import database as db
from . import system_settings
from .i18n import t

logger = logging.getLogger("switchsteward.firmware")

MAX_UPLOAD_BYTES = 4 * 1024**3
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
INCOMING = ".incoming"
# Jobs whose ``params.image_id`` keeps an image in use while pending or running.
_IMAGE_JOB_KINDS = ("firmware-stage", "reload")
_CHUNK = 1024 * 1024


class FirmwareError(Exception):
    """Rejected firmware request; ``status_code`` is the HTTP status, the message is German (translated)."""

    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code


def directory() -> Path:
    """Checked, existing firmware directory; ``FirmwareError(400)`` when it is not usable."""
    try:
        return system_settings.storage_dir(system_settings.load_firmware().directory)
    except ValueError as exc:
        raise FirmwareError(400, str(exc)) from None


def incoming_dir() -> Path:
    """Temporary upload directory inside the firmware directory (created on demand, mode 0700)."""
    path = directory() / INCOMING
    path.mkdir(mode=0o700, exist_ok=True)
    return path


def _view(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "filename": row["filename"],
        "size": row["size"],
        "sha256": row["sha256"],
        "md5": row["md5"],
        "platforms": json.loads(row["platforms"]),
        "uploaded_by": row["uploaded_by"],
        "uploaded_at": row["uploaded_at"],
    }


def list_images() -> list[dict]:
    with db.get_conn() as conn:
        rows = conn.execute("SELECT * FROM firmware_images ORDER BY filename COLLATE NOCASE").fetchall()
    return [_view(row) for row in rows]


def get_image(image_id: int) -> dict | None:
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM firmware_images WHERE id = ?", (image_id,)).fetchone()
    return _view(row) if row else None


def images_for(driver_id: str) -> list[dict]:
    """Images the administrator marked as compatible with ``driver_id``."""
    return [image for image in list_images() if driver_id in image["platforms"]]


def image_path(image_id: int) -> Path:
    """File of an image; ``LookupError`` when the image or its file does not exist."""
    image = get_image(image_id)
    if image is None:
        raise LookupError(f"firmware image {image_id} not found")
    path = directory() / image["filename"]
    if not path.is_file():
        raise LookupError(f"firmware file {image['filename']} is missing")
    return path


def validate_filename(filename: str) -> str:
    if not FILENAME_RE.fullmatch(filename or ""):
        raise FirmwareError(400, t(
            "Ungültiger Dateiname: erlaubt sind 1–128 Zeichen A–Z, a–z, 0–9, Punkt, Unterstrich und Bindestrich "
            "(erstes Zeichen Buchstabe oder Ziffer).",
        ))
    return filename


def validate_platforms(value: str, known: set[str]) -> list[str]:
    """Comma-separated driver IDs → list without duplicates; at least one, all known."""
    platforms = list(dict.fromkeys(part.strip() for part in (value or "").split(",") if part.strip()))
    unknown = [platform for platform in platforms if platform not in known]
    if not platforms or unknown:
        raise FirmwareError(400, t(
            "Bitte mindestens eine gültige Plattform wählen (unbekannt: {platforms}).",
            platforms=", ".join(unknown) or "-",
        ))
    return platforms


def _hashes(path: Path) -> tuple[int, str, str]:
    sha256, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            size += len(chunk)
            sha256.update(chunk)
            md5.update(chunk)
    return size, sha256.hexdigest(), md5.hexdigest()


def store_upload(upload_path: Path, filename: str, platforms: list[str], username: str) -> dict:
    """Hash the uploaded file, move it to ``<directory>/<filename>`` and record it.

    Duplicate file names → ``FirmwareError(409)``. A file of that name without a database row
    (left over from an interrupted deletion) is replaced.
    """
    filename = validate_filename(filename)
    size, sha256, md5 = _hashes(upload_path)
    if size == 0:
        raise FirmwareError(400, t("Das Firmware-Image ist leer."))
    target = directory() / filename
    try:
        with db.get_conn() as conn:
            image_id = conn.execute(
                "INSERT INTO firmware_images (filename, size, sha256, md5, platforms, uploaded_by) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (filename, size, sha256, md5, json.dumps(platforms), username),
            ).lastrowid
            # Inside the transaction: a failed move leaves no row behind.
            os.replace(upload_path, target)
            os.chmod(target, 0o600)
    except sqlite3.IntegrityError:
        raise FirmwareError(409, t("Ein Firmware-Image mit diesem Dateinamen existiert bereits.")) from None
    logger.info("Firmware image %s stored (%s bytes, sha256 %s)", filename, size, sha256)
    return get_image(image_id)


def _in_use(conn: sqlite3.Connection, image_id: int) -> bool:
    rows = conn.execute(
        "SELECT params FROM jobs WHERE status IN ('pending', 'running') AND kind IN (?, ?)", _IMAGE_JOB_KINDS,
    ).fetchall()
    for row in rows:
        try:
            params = json.loads(row["params"] or "{}")
        except ValueError:
            continue
        if isinstance(params, dict) and params.get("image_id") == image_id:
            return True
    return False


def delete_image(image_id: int) -> dict:
    """Delete row and file; ``FirmwareError(404)`` unknown, ``(409)`` while a pending/running job uses it."""
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM firmware_images WHERE id = ?", (image_id,)).fetchone()
        if row is None:
            raise FirmwareError(404, t("Firmware-Image nicht gefunden."))
        if _in_use(conn, image_id):
            raise FirmwareError(409, t("Das Firmware-Image wird von einer geplanten oder laufenden Aufgabe verwendet."))
        conn.execute("DELETE FROM firmware_images WHERE id = ?", (image_id,))
    image = _view(row)
    try:
        (directory() / image["filename"]).unlink(missing_ok=True)
    except (OSError, FirmwareError) as exc:
        logger.warning("Firmware file %s could not be deleted: %s", image["filename"], exc)
    return image
