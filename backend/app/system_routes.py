"""Authenticated version information and administrator-managed release uploads."""

import logging

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from . import updates
from .audit import audit_action, record
from .auth import AdminPrincipal, CurrentPrincipal
from .i18n import t

logger = logging.getLogger("switchsteward.updates")
router = APIRouter(prefix="/api/system", tags=["system"])


class InstallUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    update_id: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")


@router.get("/version")
def version(_: CurrentPrincipal):
    return updates.update_manager.status()


@router.post("/updates")
@audit_action("upload-update")
def upload_update(request: Request, _: AdminPrincipal):
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in {"application/octet-stream", "application/zip", "application/gzip", "application/x-gzip"}:
        raise HTTPException(415, t("Das Release-Archiv muss als ZIP- oder tar.gz-Datei hochgeladen werden."))
    archive_path = request.scope.get("switchsteward.upload_path")
    if archive_path is None:
        raise HTTPException(400, t("Update-Archiv fehlt."))
    try:
        candidate = updates.update_manager.stage_archive(archive_path)
    except updates.UpdateError as exc:
        logger.error("Update upload rejected: %s", exc)
        record("upload-update", detail=str(exc), status="error")
        raise HTTPException(exc.status_code, str(exc)) from None
    logger.info("Update %s staged (sha256 %s)", candidate["version"], candidate["sha256"])
    record("upload-update", detail=f"version={candidate['version']} sha256={candidate['sha256']}")
    return candidate


@router.post("/updates/install", status_code=202)
@audit_action("install-update")
def install_update(body: InstallUpdateIn, background_tasks: BackgroundTasks, _: AdminPrincipal):
    try:
        candidate = updates.update_manager.request_install(body.update_id)
    except updates.UpdateError as exc:
        raise HTTPException(exc.status_code, str(exc)) from None
    try:
        record(
            "install-update",
            detail=f"Installation angefordert: version={candidate['version']} update_id={body.update_id}",
        )
    except Exception:
        updates.update_manager.cancel_install(body.update_id)
        raise
    logger.info("Installation of update %s requested; restarting", candidate["version"])
    background_tasks.add_task(updates.update_manager.begin_restart)
    return {"status": "restarting", "version": candidate["version"], "restarting": True}
