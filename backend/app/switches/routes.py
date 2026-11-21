"""Device operations on inventoried switches, driver list and capabilities."""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query

from .. import database as db
from ..audit import audit_action, record
from ..auth import AdminPrincipal, CurrentPrincipal, OperatorPrincipal
from ..i18n import t
from . import backup_service, service
from .operations import OPERATIONS, ApplyIn, ChangeIn

router = APIRouter(prefix="/api", tags=["switches"])


def _public_result(result: dict) -> dict:
    return {key: value for key, value in result.items() if key != "raw"}


def _get_switch_and_creds(switch_id: int, *, audit: str | None = None, interface: str | None = None):
    connection = db.get_switch_connection(switch_id)
    if not connection:
        raise HTTPException(404, t("Switch nicht gefunden"))
    switch, creds = connection["switch"], connection["credentials"]
    if not creds:
        if audit:
            record(audit, target=switch["name"], interface=interface, detail="credentials_missing", status="error")
        raise HTTPException(400, t("Für diesen Switch fehlen Zugangsdaten für die gewählte Quelle (global/eigen)."))
    return switch, creds


@router.get("/switch-drivers")
def api_switch_drivers(_: CurrentPrincipal):
    return service.list_driver_info()


@router.get("/switches/{switch_id}/capabilities")
def api_switch_capabilities(switch_id: int, _: CurrentPrincipal):
    connection = db.get_switch_connection(switch_id)
    if not connection:
        raise HTTPException(404, t("Switch nicht gefunden"))
    return service.get_capabilities(connection["switch"])


@router.post("/switches/{switch_id}/test-connection")
@audit_action("test-connection")
def api_test_connection(switch_id: int, _: AdminPrincipal):
    switch, creds = _get_switch_and_creds(switch_id, audit="test-connection")
    result = service.check_connection(switch, creds)
    record("test-connection", target=switch["name"], detail=result["message"],
           status="ok" if result["ok"] else "error")
    return _public_result(result)


@router.get("/switches/{switch_id}/interface-inventory")
def api_get_interface_inventory(switch_id: int, _: CurrentPrincipal):
    switch, creds = _get_switch_and_creds(switch_id)
    return service.get_interface_inventory(switch, creds)


@router.get("/switches/{switch_id}/interface-detail")
def api_interface_detail(switch_id: int, interface: str, _: CurrentPrincipal):
    switch, creds = _get_switch_and_creds(switch_id)
    return service.get_interface_detail(switch, creds, interface)


@router.post("/switches/{switch_id}/changes/preview")
@audit_action("switch-change-preview")
def api_preview_change(switch_id: int, body: ChangeIn, principal: OperatorPrincipal):
    spec = OPERATIONS[body.kind]
    params = service.parse_params(spec, body.params)  # invalid input fails before any lookup
    switch, creds = _get_switch_and_creds(switch_id, audit="switch-change-preview")
    result = service.preview_change(switch, creds, principal, body)
    record("switch-change-preview", target=switch["name"], interface=spec.interface(params),
           detail=f"kind={body.kind}")
    return result


@router.post("/switches/{switch_id}/changes/apply")
@audit_action("switch-change")
def api_apply_change(switch_id: int, body: ApplyIn, principal: OperatorPrincipal):
    return service.apply_change(switch_id, principal, body)


@router.get("/switches/{switch_id}/config-status")
def api_config_status(switch_id: int, principal: CurrentPrincipal, compare: bool = False):
    if compare:
        # Running vs. startup on the device; updates the app's save state before it is returned.
        switch, creds = _get_switch_and_creds(switch_id)
        device = backup_service.compare_device(switch, creds, principal)
        return {**service.get_config_status(switch_id), "device": device}
    if not db.get_switch(switch_id):
        raise HTTPException(404, t("Switch nicht gefunden"))
    return service.get_config_status(switch_id)


@router.get("/switches/{switch_id}/vlans")
def api_get_vlans(switch_id: int, _: CurrentPrincipal):
    switch, creds = _get_switch_and_creds(switch_id)
    return service.get_vlan_inventory(switch, creds)


@router.get("/switches/{switch_id}/summary")
def api_summary(switch_id: int, _: CurrentPrincipal):
    switch, creds = _get_switch_and_creds(switch_id)
    return service.get_device_summary(switch, creds)


@router.get("/switches/{switch_id}/client-inventory")
def api_client_inventory(switch_id: int, _: CurrentPrincipal):
    switch, creds = _get_switch_and_creds(switch_id)
    return service.get_client_inventory(switch, creds)


@router.get("/clients/search")
def api_search_clients(
    q: Annotated[str, Query(min_length=2, max_length=100)],
    _: CurrentPrincipal,
):
    query = q.strip()
    if len(query) < 2:
        raise HTTPException(400, t("Der Suchbegriff muss mindestens zwei Zeichen enthalten."))
    return service.search_clients(db.list_switches(), query, connection_resolver=db.get_switch_connection)


@router.get("/switches/{switch_id}/neighbors")
def api_neighbors(switch_id: int, _: CurrentPrincipal):
    switch, creds = _get_switch_and_creds(switch_id)
    return service.get_neighbors(switch, creds)
