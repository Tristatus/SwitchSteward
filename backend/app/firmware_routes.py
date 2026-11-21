"""Firmware image store for administrators: list, streaming upload, delete."""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request

from . import firmware
from .audit import audit_action, record
from .auth import AdminPrincipal
from .i18n import t
from .switches.drivers import DRIVERS

router = APIRouter(prefix="/api/firmware", tags=["firmware"])


def _raise(exc: firmware.FirmwareError, action: str, detail: str):
    record(action, detail=f"{detail} -> {exc}", status="error")
    raise HTTPException(exc.status_code, str(exc)) from None


@router.get("/images")
def list_images(_: AdminPrincipal):
    return {"images": firmware.list_images()}


@router.post("/images")
@audit_action("upload-firmware")
def upload_image(
    request: Request,
    principal: AdminPrincipal,
    filename: Annotated[str, Query(max_length=200)],
    platforms: Annotated[str, Query(max_length=500)],
):
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/octet-stream":
        raise HTTPException(415, t("Das Firmware-Image muss als Binärdatei (application/octet-stream) hochgeladen werden."))
    upload_path = request.scope.get("switchsteward.upload_path")
    if upload_path is None:
        raise HTTPException(400, t("Firmware-Image fehlt."))
    detail = f"filename={filename!r}"
    try:
        selected = firmware.validate_platforms(platforms, set(DRIVERS))
        image = firmware.store_upload(upload_path, filename, selected, principal.username)
    except firmware.FirmwareError as exc:
        _raise(exc, "upload-firmware", detail)
    record("upload-firmware", target=image["filename"], detail=(
        f"size={image['size']} sha256={image['sha256']} platforms={','.join(image['platforms'])}"
    ))
    return image


@router.delete("/images/{image_id}")
@audit_action("delete-firmware")
def delete_image(image_id: int, _: AdminPrincipal):
    try:
        image = firmware.delete_image(image_id)
    except firmware.FirmwareError as exc:
        _raise(exc, "delete-firmware", f"id={image_id}")
    record("delete-firmware", target=image["filename"], detail=f"id={image_id} sha256={image['sha256']}")
    return {"ok": True}
