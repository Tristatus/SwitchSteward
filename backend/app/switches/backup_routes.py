"""Backups of a switch (list, content, download, diff) and the rollback timer (confirm/revert)."""

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from .. import database as db
from ..audit import audit_action, record
from ..auth import AdminPrincipal, CurrentPrincipal
from ..i18n import t
from . import backup_service

router = APIRouter(prefix="/api", tags=["switch-backups"])


def _switch(switch_id: int) -> dict:
    switch = db.get_switch(switch_id)
    if not switch:
        raise HTTPException(404, t("Switch nicht gefunden"))
    return switch


def _connection(switch_id: int) -> tuple[dict, dict]:
    connection = db.get_switch_connection(switch_id)
    if not connection:
        raise HTTPException(404, t("Switch nicht gefunden"))
    if not connection["credentials"]:
        raise HTTPException(400, t("Für diesen Switch fehlen Zugangsdaten für die gewählte Quelle (global/eigen)."))
    return connection["switch"], connection["credentials"]


@router.get("/switches/{switch_id}/backups")
def api_list_backups(switch_id: int, _: CurrentPrincipal):
    return backup_service.list_backups(_switch(switch_id))


@router.get("/switches/{switch_id}/backups/{backup_id}")
def api_backup_text(switch_id: int, backup_id: int, _: AdminPrincipal):
    _backup, text = backup_service.backup_text(_switch(switch_id), backup_id)
    return {"text": text}


@router.get("/switches/{switch_id}/backups/{backup_id}/download")
def api_download_backup(switch_id: int, backup_id: int, _: AdminPrincipal):
    switch = _switch(switch_id)
    backup, text = backup_service.backup_text(switch, backup_id)
    record("download-config-backup", target=switch["name"], detail=f"id={backup_id}")
    filename = backup_service.download_name(switch, backup)
    return Response(
        text.encode("utf-8"), media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/switches/{switch_id}/backups/{backup_id}/diff")
def api_diff_backup(
    switch_id: int, backup_id: int, _: AdminPrincipal,
    against: str = Query(min_length=1, max_length=20, pattern=r"^(running|startup|[0-9]+)$"),
):
    if against in ("running", "startup"):
        switch, credentials = _connection(switch_id)
    else:
        switch, credentials = _switch(switch_id), {}
    return backup_service.diff_backup(switch, credentials, backup_id, against)


@router.post("/switches/{switch_id}/rollback/confirm")
@audit_action("rollback-confirm")
def api_rollback_confirm(switch_id: int, _: AdminPrincipal):
    switch, credentials = _connection(switch_id)
    return backup_service.finish_rollback(switch, credentials, revert=False)


@router.post("/switches/{switch_id}/rollback/revert")
@audit_action("rollback-revert")
def api_rollback_revert(switch_id: int, _: AdminPrincipal):
    switch, credentials = _connection(switch_id)
    return backup_service.finish_rollback(switch, credentials, revert=True)
