"""HTTP-API fuer WLAN-Controller, Access Points und verbundene Clients."""

from __future__ import annotations

import re
import sqlite3
from ipaddress import ip_address
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .. import crypto
from .. import database as db
from ..audit import audit_action, record
from ..auth import AdminPrincipal, CurrentPrincipal
from ..i18n import t
from . import config_service, models, service

router = APIRouter(prefix="/api/wlan", tags=["wlan"])

_DNS_LABEL_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE | re.ASCII,
)
_PLATFORMS = service.platform_catalog()


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ControllerIn(ApiModel):
    name: str = Field(min_length=1, max_length=100)
    host: str = Field(min_length=1, max_length=253)
    platform: Literal["catalyst_9800"] = "catalyst_9800"
    transport: Literal["restconf", "netconf"] = models.TRANSPORT_RESTCONF
    port: int = Field(default=443, ge=1, le=65535)
    site: str | None = Field(default=None, max_length=100)
    notes: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="before")
    @classmethod
    def apply_transport_default_port(cls, value):
        if isinstance(value, dict) and "port" not in value:
            value = dict(value)
            value["port"] = (
                830 if value.get("transport") == models.TRANSPORT_NETCONF else 443
            )
        return value

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError(t("Name darf nicht leer sein."))
        return value

    @field_validator("site", "notes")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError(t("Der Host darf keine Steuerzeichen enthalten."))
        host = value.strip()
        try:
            return str(ip_address(host))
        except ValueError:
            pass

        # Resolver interpretieren einige ungueltige IPv4-Schreibweisen
        # plattformabhaengig. Rein numerische Eingaben duerfen daher nicht als
        # vermeintlicher DNS-Name durchfallen.
        if not host or all(char.isdigit() or char == "." for char in host):
            raise ValueError(
                t("Es muss eine gültige IP-Adresse oder ein gültiger DNS-Name angegeben werden.")
            )
        dns_host = host[:-1] if host.endswith(".") else host
        if (
            not dns_host
            or len(dns_host) > 253
            or any(not _DNS_LABEL_RE.fullmatch(label) for label in dns_host.split("."))
        ):
            raise ValueError(
                t("Es muss eine gültige IP-Adresse oder ein gültiger DNS-Name angegeben werden.")
            )
        return dns_host.lower()


class ControllerUpdateIn(ControllerIn):
    revision_token: str = Field(
        min_length=49,
        max_length=49,
        pattern=r"^wlcr1\.[A-Za-z0-9_-]{43}$",
    )


class WlanCredentialsIn(ApiModel):
    mode: Literal["global", "device"] = "device"
    username: str | None = Field(default=None, max_length=256)
    # Leer/None bedeutet bei einem Update: vorhandenes Passwort beibehalten.
    password: str | None = Field(default=None, max_length=1024)
    revision_token: str = Field(
        min_length=48,
        max_length=48,
        pattern=r"^wcr1\.[A-Za-z0-9_-]{43}$",
    )
    controller_revision_token: str = Field(
        min_length=49,
        max_length=49,
        pattern=r"^wlcr1\.[A-Za-z0-9_-]{43}$",
    )

    @model_validator(mode="after")
    def validate_credential_mode(self):
        self.username = self.username.strip() if self.username is not None else None
        if self.mode == "device" and not self.username:
            raise ValueError(t("Für eigene Zugangsdaten ist ein Benutzername erforderlich."))
        if self.mode == "global" and any((self.username, self.password)):
            raise ValueError(t("Bei globalen Zugangsdaten dürfen keine eigenen Geheimnisse gesetzt werden."))
        return self


def _get_controller(controller_id: int) -> dict:
    controller = db.get_wlan_controller(controller_id)
    if not controller:
        raise HTTPException(404, t("WLAN-Controller nicht gefunden"))
    return controller


def _get_controller_and_credentials(controller_id: int) -> tuple[dict, dict]:
    connection = db.get_wlan_controller_connection(controller_id)
    if not connection:
        raise HTTPException(404, t("WLAN-Controller nicht gefunden"))
    controller = connection["controller"]
    credentials = connection["credentials"]
    if not credentials:
        raise HTTPException(
            400,
            t("Für diesen WLAN-Controller sind noch keine Zugangsdaten hinterlegt."),
        )
    return controller, credentials


def _normalize_filter(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


@router.get("/platforms")
def api_list_wlan_platforms(_: CurrentPrincipal):
    return _PLATFORMS


@router.get("/controllers")
def api_list_wlan_controllers(_: CurrentPrincipal):
    return db.list_wlan_controllers()


@router.post("/controllers")
@audit_action("create-wlan-controller")
def api_create_wlan_controller(body: ControllerIn, _: AdminPrincipal):
    try:
        controller_id = db.create_wlan_controller(
            body.name,
            body.host,
            body.platform,
            body.port,
            body.site,
            body.notes,
            transport=body.transport,
        )
    except sqlite3.IntegrityError:
        raise HTTPException(
            409,
            t("Ein WLAN-Controller mit diesem Namen existiert bereits."),
        ) from None
    record(
        "create-wlan-controller",
        target=body.name,
        detail=(
            f"host={body.host} platform={body.platform} "
            f"transport={body.transport} port={body.port}"
        ),
    )
    return db.get_wlan_controller(controller_id)


@router.put("/controllers/{controller_id}")
@audit_action("update-wlan-controller")
def api_update_wlan_controller(
    controller_id: int,
    body: ControllerUpdateIn,
    _: AdminPrincipal,
):
    try:
        update_result = db.update_wlan_controller(
            controller_id,
            body.name,
            body.host,
            body.platform,
            body.port,
            body.site,
            body.notes,
            transport=body.transport,
            expected_revision_token=body.revision_token,
        )
    except sqlite3.IntegrityError:
        raise HTTPException(
            409,
            t("Ein WLAN-Controller mit diesem Namen existiert bereits."),
        ) from None
    if update_result is None:
        raise HTTPException(404, t("WLAN-Controller nicht gefunden"))
    if update_result["status"] == "revision_changed":
        record(
            "update-wlan-controller",
            target=update_result["controller_name"],
            detail="Controller- oder Zugangsdatenstand veraltet; Controller nicht aktualisiert",
            status="error",
        )
        raise HTTPException(
            409,
            {
                "code": "stale_controller_revision",
                "message": t(
                    "Der Controller wurde zwischenzeitlich geändert. "
                    "Bitte neu laden und erneut öffnen."
                ),
            },
        )
    service.clear_cache(controller_id)
    credentials_cleared = update_result["connection_changed"]
    record(
        "update-wlan-controller",
        target=body.name,
        detail=(
            f"host={body.host} platform={body.platform} "
            f"transport={body.transport} port={body.port} "
            f"credentials_cleared={str(credentials_cleared).lower()}"
        ),
    )
    return update_result["controller"]


@router.delete("/controllers/{controller_id}")
@audit_action("delete-wlan-controller")
def api_delete_wlan_controller(controller_id: int, _: AdminPrincipal):
    controller = _get_controller(controller_id)
    db.delete_wlan_controller(controller_id)
    service.clear_cache(controller_id)
    record("delete-wlan-controller", target=controller["name"], detail="WLAN-Controller aus Inventar entfernt")
    return {"ok": True}


@router.get("/controllers/{controller_id}/credentials")
def api_get_wlan_credentials(controller_id: int, _: AdminPrincipal):
    metadata = db.get_wlan_credentials_metadata(controller_id)
    if not metadata:
        raise HTTPException(404, t("WLAN-Controller nicht gefunden"))
    return metadata


@router.put("/controllers/{controller_id}/credentials")
@audit_action("update-wlan-credentials")
def api_set_wlan_credentials(
    controller_id: int,
    body: WlanCredentialsIn,
    _: AdminPrincipal,
):
    connection = db.get_wlan_controller_connection(controller_id)
    if not connection:
        raise HTTPException(404, t("WLAN-Controller nicht gefunden"))
    controller = connection["controller"]
    preserve_password = body.mode == "device" and body.password in {None, ""}
    own_configured = controller.get("credentials_override_configured", bool(connection["credentials"]))
    if preserve_password and not own_configured:
        raise HTTPException(
            400,
            t("Beim erstmaligen Hinterlegen der Zugangsdaten ist ein Passwort erforderlich."),
        )
    password_enc = crypto.encrypt(body.password) if body.mode == "device" and not preserve_password else None
    credential_result = db.set_wlan_credentials_for_connection(
        controller_id,
        body.username,
        password_enc,
        expected_host=controller["host"],
        expected_port=controller["port"],
        expected_platform=controller["platform"],
        expected_transport=controller["transport"],
        expected_revision_token=body.revision_token,
        expected_controller_revision_token=body.controller_revision_token,
        preserve_password=preserve_password,
        mode=body.mode,
    )
    result_status = credential_result["status"]
    if result_status == "controller_not_found":
        raise HTTPException(404, t("WLAN-Controller nicht gefunden"))
    if result_status == "revision_changed":
        record(
            "update-wlan-credentials",
            target=credential_result["controller_name"],
            detail="Controller- oder Zugangsdatenstand veraltet; Zugangsdaten nicht gespeichert",
            status="error",
        )
        raise HTTPException(
            409,
            t("Controller oder Zugangsdaten wurden zwischenzeitlich geändert. "
              "Bitte den Dialog schließen und neu öffnen."),
        )
    if result_status == "connection_changed":
        record(
            "update-wlan-credentials",
            target=credential_result["controller_name"],
            detail="Verbindungsziel parallel geändert; Zugangsdaten nicht gespeichert",
            status="error",
        )
        raise HTTPException(
            409,
            t("Das Verbindungsziel wurde parallel geändert. Zugangsdaten wurden nicht gespeichert."),
        )
    if result_status == "credentials_missing":
        record(
            "update-wlan-credentials",
            target=credential_result["controller_name"],
            detail="Bestehende Zugangsdaten parallel entfernt; keine Änderung gespeichert",
            status="error",
        )
        raise HTTPException(
            409,
            t("Die bestehenden Zugangsdaten wurden parallel entfernt. Bitte erneut öffnen."),
        )
    service.clear_cache(controller_id)
    config_service.clear_previews(controller_id)
    record(
        "update-wlan-credentials",
        target=credential_result["controller_name"],
        detail=f"transport={controller['transport']} mode={body.mode}",
    )
    metadata = db.get_wlan_credentials_metadata(controller_id)
    if metadata is None:
        raise HTTPException(404, t("WLAN-Controller wurde zwischenzeitlich entfernt."))
    return {"ok": True, **metadata}


@router.post("/controllers/{controller_id}/test-connection")
@audit_action("test-wlan-connection")
def api_test_wlan_connection(controller_id: int, _: AdminPrincipal):
    controller, credentials = _get_controller_and_credentials(controller_id)
    try:
        result = service.check_connection(controller, credentials)
    except models.WlanError as exc:
        record("test-wlan-connection", target=controller["name"], detail=str(exc), status="error")
        raise
    message = str(result.get("message") or "Verbindungstest abgeschlossen")
    record(
        "test-wlan-connection",
        target=controller["name"],
        detail=message,
        status="ok" if result.get("ok") else "error",
    )
    return {key: value for key, value in result.items() if key != "raw"}


@router.get("/controllers/{controller_id}/access-points")
def api_list_access_points(
    controller_id: int,
    _: CurrentPrincipal,
    q: Annotated[str | None, Query(max_length=100)] = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    refresh: bool = False,
    status: Annotated[str | None, Query(max_length=50)] = None,
):
    controller, credentials = _get_controller_and_credentials(controller_id)
    return service.list_access_points(
        controller,
        credentials,
        q=_normalize_filter(q),
        offset=offset,
        limit=limit,
        refresh=refresh,
        **({"status": _normalize_filter(status)} if status is not None else {}),
    )


@router.get("/controllers/{controller_id}/clients")
def api_list_wlan_clients(
    controller_id: int,
    _: CurrentPrincipal,
    q: Annotated[str | None, Query(max_length=100)] = None,
    ap: Annotated[str | None, Query(max_length=100)] = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    refresh: bool = False,
    ssid: Annotated[str | None, Query(max_length=128)] = None,
):
    controller, credentials = _get_controller_and_credentials(controller_id)
    return service.list_clients(
        controller,
        credentials,
        q=_normalize_filter(q),
        ap=_normalize_filter(ap),
        offset=offset,
        limit=limit,
        refresh=refresh,
        **({"ssid": _normalize_filter(ssid)} if ssid is not None else {}),
    )


class ConfigurationChangeIn(ApiModel):
    resource: str = Field(min_length=1, max_length=50, pattern=r"^[a-z_]+$")
    operation: Literal["create", "update", "delete", "clone", "rpc"]
    key: str = Field(min_length=1, max_length=256)
    values: dict[str, Any] = Field(default_factory=dict, max_length=64)
    source_key: str | None = Field(default=None, min_length=1, max_length=256)


class ConfigurationApplyIn(ApiModel):
    preview_token: str = Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]{43}$")


def _configuration_call(callback, *args):
    try:
        return callback(*args)
    except models.WlanError as exc:
        if isinstance(exc, config_service.ConfigurationConflict):
            status_code = 409
        elif isinstance(exc, models.WlanConfigurationError):
            status_code = 422
        elif isinstance(exc, models.WlanCapabilityError):
            status_code = 409
        elif isinstance(exc, models.WlanAuthenticationError):
            status_code = 403
        else:
            status_code = 502
        raise HTTPException(status_code, {"code": exc.code, "message": exc.message}) from None


@router.get("/controllers/{controller_id}/configuration")
def api_get_wlan_configuration(controller_id: int, _: CurrentPrincipal):
    controller, credentials = _get_controller_and_credentials(controller_id)
    return _configuration_call(config_service.get_configuration, controller, credentials)


@router.post("/controllers/{controller_id}/configuration/preview")
@audit_action("wlan-config-preview")
def api_preview_wlan_configuration(
    controller_id: int, body: ConfigurationChangeIn, principal: AdminPrincipal,
):
    controller = _get_controller(controller_id)
    preview = _configuration_call(
        config_service.preview, controller_id, principal, body.model_dump(exclude_none=True),
    )
    # Values can hold secrets (PSKs); only the addressed object is audited.
    record(
        "wlan-config-preview",
        target=controller["name"],
        interface=body.key,
        detail=f"resource={body.resource} operation={body.operation}",
    )
    return preview


@router.post("/controllers/{controller_id}/configuration/apply")
@audit_action("wlan-config-start")
def api_apply_wlan_configuration(
    controller_id: int, body: ConfigurationApplyIn, principal: AdminPrincipal,
):
    _get_controller(controller_id)
    return _configuration_call(config_service.apply, controller_id, principal, body.preview_token)


@router.get("/controllers/{controller_id}/access-points/{ap_key}")
def api_get_access_point(
    controller_id: int, ap_key: str, _: CurrentPrincipal,
):
    if len(ap_key) > 256:
        raise HTTPException(422, t("Ungültige AP-Kennung."))
    controller, credentials = _get_controller_and_credentials(controller_id)
    if controller.get("transport") == models.TRANSPORT_NETCONF:
        snapshot = _configuration_call(config_service.get_configuration, controller, credentials)
        items = snapshot.get("access_points", [])
    else:
        snapshot = {"capabilities": {"supported_resources": []}}
        items = service.adapter_for(controller).list_access_points(controller, credentials).items
    # Names are a read-only fallback for older monitoring adapters; mutations
    # always validate the distinct radio/Ethernet MAC identifiers afresh.
    matches = [ap for ap in items if ap_key.casefold() in {
        str(ap.get(field, "")).casefold() for field in ("id", "radio_mac", "ethernet_mac", "mac", "name")
    }]
    if len(matches) != 1:
        raise HTTPException(404 if not matches else 409, t("Access Point nicht eindeutig gefunden."))
    return {**matches[0], "capabilities": snapshot.get("capabilities", {})}
