"""Administrator access to system.log and audit.log: tail view and ZIP downloads."""

import re
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from . import config
from .audit import record
from .auth import AdminPrincipal
from .i18n import t
from .logging_setup import AUDIT_LOG_FILE, SYSTEM_LOG_FILE

router = APIRouter(prefix="/api/admin/logs", tags=["admin"])
_TAIL_BYTES = 2 * 1024 * 1024
_CHUNK_BYTES = 64 * 1024
# Matches logging_setup._FORMAT: "%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s"
_ENTRY = re.compile(r"^(\S+) ([A-Z]+|Level \d+) (\S+) \[([^\]]*)\] (.*)$")


def read_system_log(path: Path, limit: int) -> list[dict]:
    """Return the newest ``limit`` entries from the last ``_TAIL_BYTES`` of ``path``, newest first."""
    try:
        with path.open("rb") as handle:
            size = handle.seek(0, 2)
            start = max(0, size - _TAIL_BYTES)
            handle.seek(start)
            data = handle.read()
    except FileNotFoundError:
        return []
    lines = data.decode("utf-8", errors="replace").splitlines()
    if start > 0 and lines:
        lines = lines[1:]
    entries: list[dict] = []
    for line in lines:
        match = _ENTRY.match(line)
        if match:
            ts, level, logger_name, request_id, message = match.groups()
            entries.append({
                "ts": ts, "level": level, "logger": logger_name, "request_id": request_id, "message": message,
            })
        elif entries:
            entries[-1]["message"] += "\n" + line
    return entries[-limit:][::-1]


def _log_files(name: str) -> list[Path]:
    directory = Path(config.settings.log_directory)
    pattern = re.compile(rf"^{re.escape(name)}(?:\.(\d+))?$")
    found: list[tuple[int, Path]] = []
    try:
        candidates = list(directory.iterdir())
    except FileNotFoundError:
        return []
    for path in candidates:
        match = pattern.match(path.name)
        if match and path.is_file():
            found.append((int(match.group(1)) if match.group(1) else 0, path))
    return [path for _, path in sorted(found, key=lambda item: item[0])]


def _zip_download(name: str, kind: str, action: str) -> StreamingResponse:
    files = _log_files(name)
    if not files:
        raise HTTPException(404, t("Keine Logdateien vorhanden."))
    tmp = tempfile.TemporaryFile()
    written = 0
    try:
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in files:
                try:
                    archive.write(path, arcname=path.name)
                except FileNotFoundError:
                    continue  # rotated away between listing and reading
                written += 1
    except BaseException:
        tmp.close()
        raise
    if not written:
        tmp.close()
        raise HTTPException(404, t("Keine Logdateien vorhanden."))
    tmp.seek(0)
    record(action, detail=f"files={written}")
    filename = f"switchsteward-{kind}-log-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.zip"
    return StreamingResponse(
        iter(lambda: tmp.read(_CHUNK_BYTES), b""),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        background=BackgroundTask(tmp.close),
    )


@router.get("/system")
def api_system_log(_: AdminPrincipal, limit: int = Query(default=500, ge=1, le=5000)):
    return read_system_log(Path(config.settings.log_directory) / SYSTEM_LOG_FILE, limit)


@router.get("/system/download")
def api_download_system_log(_: AdminPrincipal):
    return _zip_download(SYSTEM_LOG_FILE, "system", "download-system-log")


@router.get("/audit/download")
def api_download_audit_log(_: AdminPrincipal):
    return _zip_download(AUDIT_LOG_FILE, "audit", "download-audit-log")
