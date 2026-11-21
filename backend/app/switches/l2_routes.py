"""Layer-2 read routes: link aggregation, spanning tree and VTP (writes go through ``changes/preview|apply``)."""

from fastapi import APIRouter

from ..auth import CurrentPrincipal
from . import service, vlans, vtp_overview
from .coalescing import coalesced_read
from .routes import _get_switch_and_creds

router = APIRouter(prefix="/api", tags=["switches"])


@coalesced_read
def get_lags(switch: dict, credentials: dict) -> dict:
    driver, _capabilities = service._require(switch, "lag")
    with driver.session(switch, credentials) as session:
        lags = driver.read_lags(session)
    return {"lags": lags, "max_lag_id": driver.max_lag_id, "warnings": session.warnings}


@coalesced_read
def get_stp(switch: dict, credentials: dict) -> dict:
    driver, _capabilities = service._require(switch, "stp")
    with driver.session(switch, credentials) as session:
        stp = driver.read_stp(session)
    return {
        "mode": stp.get("mode"),
        "priority": stp.get("priority") or [],
        "mst": stp.get("mst"),
        "roots": stp.get("roots") or [],
        "ports": stp.get("ports") or [],
        "warnings": session.warnings,
    }


@coalesced_read
def get_vtp(switch: dict, credentials: dict) -> dict:
    driver, _capabilities = service._require(switch, "vtp")
    with driver.session(switch, credentials) as session:
        status = driver.read_vtp(session)
    return {**status, "vlan_lock": vlans.vtp_lock(status), "warnings": session.warnings}


@router.get("/switches/{switch_id}/lags")
def api_get_lags(switch_id: int, _: CurrentPrincipal):
    switch, creds = _get_switch_and_creds(switch_id)
    return get_lags(switch, creds)


@router.get("/switches/{switch_id}/stp")
def api_get_stp(switch_id: int, _: CurrentPrincipal):
    switch, creds = _get_switch_and_creds(switch_id)
    return get_stp(switch, creds)


@router.get("/switches/{switch_id}/vtp")
def api_get_vtp(switch_id: int, _: CurrentPrincipal):
    switch, creds = _get_switch_and_creds(switch_id)
    return get_vtp(switch, creds)


@router.get("/vtp/domains")
def api_get_vtp_domains(_: CurrentPrincipal):
    return vtp_overview.overview()
