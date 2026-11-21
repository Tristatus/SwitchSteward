"""Switch inventory, switch groups, credentials and the audit log."""

import logging
import sqlite3
from ipaddress import ip_address
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import crypto
from . import database as db
from .audit import audit_action, record
from .auth import AdminPrincipal, CurrentPrincipal
from .i18n import t
from .switches import service as switch_service
from .switches.drivers import get_driver
from .wlan import service as wlan_service
from .wlan.config_service import clear_previews

logger = logging.getLogger("switchsteward.inventory")
router = APIRouter(prefix="/api", tags=["inventory"])


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SwitchIn(ApiModel):
    name: str = Field(min_length=1, max_length=100)
    ip: str = Field(min_length=1, max_length=45)
    device_type: str = Field(default="cisco_ios", min_length=1, max_length=50)
    model_id: Optional[str] = Field(default=None, max_length=100)
    site: Optional[str] = Field(default=None, max_length=100)
    port: int = Field(default=22, ge=1, le=65535)
    notes: Optional[str] = Field(default=None, max_length=2000)
    group_id: Optional[int] = Field(default=None, ge=1)

    @field_validator("name", "site", "notes")
    @classmethod
    def normalize_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator("name")
    @classmethod
    def require_name(cls, value: Optional[str]) -> str:
        if not value:
            raise ValueError(t("Name darf nicht leer sein."))
        return value

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        try:
            return str(ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError(t("Es muss eine gültige IPv4- oder IPv6-Adresse angegeben werden.")) from exc

    @field_validator("device_type")
    @classmethod
    def validate_device_type(cls, value: str) -> str:
        if get_driver(value) is None:
            raise ValueError(t("Unbekannter Gerätetyp."))
        return value

    @model_validator(mode="after")
    def validate_model(self):
        if self.model_id is not None and get_driver(self.device_type).catalog.get(self.model_id) is None:
            raise ValueError(t("Das Modell gehört nicht zum gewählten Gerätetyp."))
        return self


class SwitchGroupIn(ApiModel):
    name: str = Field(min_length=1, max_length=100)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError(t("Gruppenname darf nicht leer sein."))
        return value


class CredentialsIn(ApiModel):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)
    enable_secret: Optional[str] = Field(default=None, max_length=1024)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError(t("Benutzername darf nicht leer sein."))
        return value


class SwitchCredentialsIn(ApiModel):
    mode: Literal["global", "device"] = "device"
    username: str | None = Field(default=None, max_length=256)
    password: str | None = Field(default=None, max_length=1024)
    enable_secret: str | None = Field(default=None, max_length=1024)
    clear_enable_secret: bool = False
    revision_token: str = Field(min_length=48, max_length=48, pattern=r"^scr1\.[A-Za-z0-9_-]{43}$")

    @model_validator(mode="after")
    def validate_credential_mode(self):
        self.username = self.username.strip() if self.username is not None else None
        if self.mode == "device" and not self.username:
            raise ValueError(t("Für eigene Zugangsdaten ist ein Benutzername erforderlich."))
        if self.mode == "global" and any((self.username, self.password, self.enable_secret, self.clear_enable_secret)):
            raise ValueError(t("Bei globalen Zugangsdaten dürfen keine eigenen Geheimnisse gesetzt werden."))
        if self.clear_enable_secret and self.enable_secret:
            raise ValueError(t("Enable-Secret kann nicht gleichzeitig gesetzt und entfernt werden."))
        return self


@router.get("/switch-groups")
def api_list_switch_groups(_: CurrentPrincipal):
    return db.list_switch_groups()


@router.post("/switch-groups")
@audit_action("create-switch-group")
def api_create_switch_group(body: SwitchGroupIn, _: AdminPrincipal):
    try:
        group_id = db.create_switch_group(body.name)
    except sqlite3.IntegrityError:
        raise HTTPException(409, t("Eine Gruppe mit diesem Namen existiert bereits.")) from None
    record("create-switch-group", target=body.name, detail=f"name={body.name}")
    return db.get_switch_group(group_id)


@router.put("/switch-groups/{group_id}")
@audit_action("update-switch-group")
def api_update_switch_group(group_id: int, body: SwitchGroupIn, _: AdminPrincipal):
    if not db.get_switch_group(group_id):
        raise HTTPException(404, t("Gruppe nicht gefunden"))
    try:
        db.update_switch_group(group_id, body.name)
    except sqlite3.IntegrityError:
        raise HTTPException(409, t("Eine Gruppe mit diesem Namen existiert bereits.")) from None
    record("update-switch-group", target=body.name, detail=f"name={body.name}")
    return db.get_switch_group(group_id)


@router.delete("/switch-groups/{group_id}")
@audit_action("delete-switch-group")
def api_delete_switch_group(group_id: int, _: AdminPrincipal):
    group = db.get_switch_group(group_id)
    if not group:
        raise HTTPException(404, t("Gruppe nicht gefunden"))
    db.delete_switch_group(group_id)
    record("delete-switch-group", target=group["name"], detail=f"name={group['name']}")
    return {"ok": True}


def _validate_group_id(group_id: Optional[int]):
    if group_id is not None and not db.get_switch_group(group_id):
        raise HTTPException(404, t("Gruppe nicht gefunden"))


@router.get("/switches")
def api_list_switches(_: CurrentPrincipal):
    return [switch_service.describe_switch(switch) for switch in db.list_switches()]


@router.get("/switches/{switch_id}")
def api_get_switch(switch_id: int, _: CurrentPrincipal):
    switch = db.get_switch(switch_id)
    if not switch:
        raise HTTPException(404, t("Switch nicht gefunden"))
    return switch_service.describe_switch(switch)


def _switch_values(body: SwitchIn) -> dict:
    return {
        "name": body.name, "ip": body.ip, "device_type": body.device_type, "model_id": body.model_id,
        "site": body.site, "port": body.port, "notes": body.notes, "group_id": body.group_id,
    }


@router.post("/switches")
@audit_action("create-switch")
def api_create_switch(body: SwitchIn, _: AdminPrincipal):
    _validate_group_id(body.group_id)
    try:
        switch_id = db.create_switch(**_switch_values(body))
    except sqlite3.IntegrityError:
        raise HTTPException(409, t("Ein Switch mit diesem Namen existiert bereits.")) from None
    record("create-switch", target=body.name,
           detail=f"ip={body.ip} port={body.port} device_type={body.device_type} model_id={body.model_id}")
    return switch_service.describe_switch(db.get_switch(switch_id))


@router.put("/switches/{switch_id}")
@audit_action("update-switch")
def api_update_switch(switch_id: int, body: SwitchIn, _: AdminPrincipal):
    existing = db.get_switch(switch_id)
    if not existing:
        raise HTTPException(404, t("Switch nicht gefunden"))
    _validate_group_id(body.group_id)
    try:
        result = db.update_switch(switch_id, **_switch_values(body))
    except sqlite3.IntegrityError:
        raise HTTPException(409, t("Ein Switch mit diesem Namen existiert bereits.")) from None
    if result is None:
        raise HTTPException(404, t("Switch nicht gefunden"))
    detail = (
        f"ip={body.ip} port={body.port} device_type={body.device_type} model_id={body.model_id} "
        f"credentials_cleared={str(result['credentials_cleared']).lower()}"
    )
    record("update-switch", target=body.name, detail=detail)
    return switch_service.describe_switch(result["switch"])


@router.delete("/switches/{switch_id}")
@audit_action("delete-switch")
def api_delete_switch(switch_id: int, _: AdminPrincipal):
    switch = db.get_switch(switch_id)
    if not switch:
        raise HTTPException(404, t("Switch nicht gefunden"))
    db.delete_switch(switch_id)
    record("delete-switch", target=switch["name"], detail="Switch aus Inventar entfernt")
    return {"ok": True}


@router.get("/credentials")
def api_get_credentials(_: AdminPrincipal):
    creds = db.get_credentials()
    return {"configured": bool(creds), **({"username": creds["username"]} if creds else {})}


@router.post("/credentials")
@audit_action("update-credentials")
def api_set_credentials(body: CredentialsIn, _: AdminPrincipal):
    db.set_credentials(
        body.username,
        crypto.encrypt(body.password),
        crypto.encrypt(body.enable_secret) if body.enable_secret else None,
    )
    record("update-credentials", detail=f"ssh_username={body.username}")
    for controller in db.list_wlan_controllers():
        if controller.get("credentials_source") == "global":
            wlan_service.clear_cache(controller["id"])
            clear_previews(controller["id"])
    return {"ok": True}


@router.get("/switches/{switch_id}/credentials")
def api_get_switch_credentials(switch_id: int, _: AdminPrincipal):
    metadata = db.get_switch_credentials_metadata(switch_id)
    if metadata is None:
        raise HTTPException(404, t("Switch nicht gefunden"))
    return metadata


@router.put("/switches/{switch_id}/credentials")
@audit_action("update-switch-credentials")
def api_set_switch_credentials(switch_id: int, body: SwitchCredentialsIn, _: AdminPrincipal):
    connection = db.get_switch_connection(switch_id)
    if connection is None:
        raise HTTPException(404, t("Switch nicht gefunden"))
    switch = connection["switch"]
    preserve_password = body.mode == "device" and body.password in {None, ""}
    preserve_enable = body.mode == "device" and not body.clear_enable_secret and body.enable_secret in {None, ""}
    result = db.set_switch_credentials_for_connection(
        switch_id, body.username,
        crypto.encrypt(body.password) if body.mode == "device" and not preserve_password else None,
        crypto.encrypt(body.enable_secret) if body.mode == "device" and body.enable_secret else None,
        mode=body.mode,
        expected_ip=switch["ip"], expected_port=switch["port"], expected_device_type=switch["device_type"],
        expected_revision_token=body.revision_token,
        preserve_password=preserve_password, preserve_enable_secret=preserve_enable,
    )
    state = result["status"]
    if state == "switch_not_found":
        raise HTTPException(404, t("Switch nicht gefunden"))
    if state != "ok":
        record("update-switch-credentials", target=switch["name"], detail=f"mode={body.mode} status={state}",
               status="error")
        if state == "credentials_missing":
            raise HTTPException(400, t("Für neue eigene Zugangsdaten ist ein Passwort erforderlich."))
        raise HTTPException(409, t("Switch oder Zugangsdaten wurden geändert. Bitte den Dialog neu öffnen."))
    record("update-switch-credentials", target=switch["name"], detail=f"mode={body.mode}")
    metadata = db.get_switch_credentials_metadata(switch_id)
    if metadata is None:
        raise HTTPException(404, t("Switch wurde zwischenzeitlich entfernt."))
    return {"ok": True, **metadata}


@router.get("/audit-log")
def api_audit_log(_: AdminPrincipal):
    return db.list_audit()
