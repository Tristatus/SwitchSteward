"""Port security tab: read route (writes go through the change framework, ``ops/security.py``)."""

from fastapi import APIRouter

from ..auth import CurrentPrincipal
from . import features, service
from .coalescing import coalesced_read
from .drivers.base import merge_interface_details
from .ops.security import SECURITY_FEATURES
from .routes import _get_switch_and_creds

router = APIRouter(prefix="/api", tags=["switches"])

_PORT_BLOCKS = (
    "port_security", "dot1x", "stp_guard", "storm_control", "dhcp_snooping_trust", "arp_inspection_trust",
    "ip_source_guard",
)


@coalesced_read
def get_port_security(switch: dict, credentials: dict) -> dict:
    """Global security state and one row per physical port (blocks ``None`` when unknown)."""
    driver = service.driver_for(switch)
    capabilities = features.for_switch(driver, switch)
    if not any(capabilities[feature].supported for feature in SECURITY_FEATURES):
        features.require(capabilities, "port_security")  # raises the driver's reason
    with driver.session(switch, credentials) as session:
        interfaces = driver.read_interfaces(session)
        switchports = driver.read_switchports(session, interfaces)
        data = driver.read_port_security(session) or {}
    ports = data.get("ports") or {}
    rows = []
    for item in merge_interface_details(interfaces, switchports, driver):
        key = driver.interface_key(item["port"])
        security = ports.get(key)
        if security is None and not driver.is_physical_interface(item["port"]):
            continue
        security = security or {}
        rows.append({
            "interface": item["port"],
            "status": item.get("status"),
            "mode": item.get("mode"),
            **{block: security.get(block) for block in _PORT_BLOCKS},
        })
    return {"global": data.get("global"), "ports": rows, "warnings": session.warnings}


@router.get("/switches/{switch_id}/port-security")
def api_port_security(switch_id: int, _: CurrentPrincipal):
    switch, creds = _get_switch_and_creds(switch_id)
    return get_port_security(switch, creds)
