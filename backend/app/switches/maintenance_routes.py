"""Maintenance read routes: firmware state of a switch and diagnostics (writes go through ``changes/preview|apply``)."""

from typing import Annotated, Literal

from fastapi import APIRouter, Query

from .. import firmware, scheduler
from ..auth import AdminPrincipal, CurrentPrincipal
from . import service
from .coalescing import coalesced_read
from .routes import _get_switch_and_creds

router = APIRouter(prefix="/api", tags=["switches"])

FIRMWARE_JOB_KINDS = ("firmware-stage", "reload")
LOG_LINES = 500


@coalesced_read
def read_firmware(switch: dict, credentials: dict) -> dict:
    driver, _capabilities = service._require(switch, "firmware")
    with driver.session(switch, credentials) as session:
        state = driver.read_firmware(session)
    return {
        "running_version": state.get("running_version"),
        "boot_images": state.get("boot_images") or [],
        "next_boot": state.get("next_boot"),
        "install_mode": state.get("install_mode"),
        "free_bytes": state.get("free_bytes"),
        "files": state.get("files") or [],
        "warnings": session.warnings,
    }


def get_firmware(switch: dict, credentials: dict) -> dict:
    """Device firmware state, the images released for this platform and the switch's firmware/reload jobs."""
    result = read_firmware(switch, credentials)
    jobs = [job for job in scheduler.list_switch_jobs(switch["id"]) if job["kind"] in FIRMWARE_JOB_KINDS]
    return {**result, "images": firmware.images_for(switch["device_type"]), "jobs": jobs}


@coalesced_read
def get_counters(switch: dict, credentials: dict, interface: str | None) -> dict:
    driver, _capabilities = service._require(switch, "diag_counters")
    name = driver.validate_interface(interface) if interface else None
    with driver.session(switch, credentials) as session:
        counters = driver.read_counters(session, name)
    return {"counters": counters, "warnings": session.warnings}


@coalesced_read
def get_transceivers(switch: dict, credentials: dict) -> dict:
    driver, _capabilities = service._require(switch, "diag_transceivers")
    with driver.session(switch, credentials) as session:
        transceivers = driver.read_transceivers(session)
    return {"transceivers": transceivers, "warnings": session.warnings}


@coalesced_read
def get_environment(switch: dict, credentials: dict) -> dict:
    driver, _capabilities = service._require(switch, "environment")
    with driver.session(switch, credentials) as session:
        environment = driver.read_environment(session)
    return {
        "temperatures": environment.get("temperatures") or [],
        "fans": environment.get("fans") or [],
        "power_supplies": environment.get("power_supplies") or [],
        "warnings": session.warnings,
    }


@coalesced_read
def get_log(switch: dict, credentials: dict) -> dict:
    driver, _capabilities = service._require(switch, "device_log")
    with driver.session(switch, credentials) as session:
        lines = driver.read_log(session, LOG_LINES)
    return {"lines": lines, "warnings": session.warnings}


def get_cable_test(switch: dict, credentials: dict, interface: str) -> dict:
    """Result of the last cable test (not coalesced: the frontend polls until ``done``)."""
    driver, _capabilities = service._require(switch, "cable_test")
    name = driver.validate_interface(interface)
    with driver.session(switch, credentials) as session:
        result = driver.read_cable_test(session, name)
    return {"status": result.get("status"), "pairs": result.get("pairs") or [], "warnings": session.warnings}


@router.get("/switches/{switch_id}/firmware")
def api_get_firmware(switch_id: int, _: CurrentPrincipal):
    switch, creds = _get_switch_and_creds(switch_id)
    return get_firmware(switch, creds)


# Fixed paths before ``/diagnostics/{kind}``.
@router.get("/switches/{switch_id}/diagnostics/log")
def api_get_log(switch_id: int, _: AdminPrincipal):
    switch, creds = _get_switch_and_creds(switch_id)
    return get_log(switch, creds)


@router.get("/switches/{switch_id}/diagnostics/cable-test")
def api_get_cable_test(
    switch_id: int, interface: Annotated[str, Query(min_length=1, max_length=100)], _: CurrentPrincipal,
):
    switch, creds = _get_switch_and_creds(switch_id)
    return get_cable_test(switch, creds, interface)


@router.get("/switches/{switch_id}/diagnostics/{kind}")
def api_get_diagnostics(
    switch_id: int,
    kind: Literal["counters", "transceivers", "environment"],
    _: CurrentPrincipal,
    interface: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
):
    switch, creds = _get_switch_and_creds(switch_id)
    if kind == "counters":
        return get_counters(switch, creds, interface)
    if kind == "transceivers":
        return get_transceivers(switch, creds)
    return get_environment(switch, creds)
