"""Uplink detection: ports whose change can cut off SwitchSteward or the network behind the switch.

Sources: the port carrying SwitchSteward's management connection (ARP of
SwitchSteward's address, else of the gateway, then the MAC table), neighbors that are
switches/routers, and the LAGs those ports belong to. A failing or unsupported source adds
a warning to the session; detection never aborts a change.
"""

from ..i18n import t
from . import clients, features
from .errors import append_warning

MANAGEMENT_REASON = "Management-Verbindung von SwitchSteward läuft über diesen Port."
NEIGHBOR_REASON = "Nachbar {name} ist ein Switch/Router."
LAG_REASON = "Gehört zur Link-Aggregation {lag} mit einem Uplink."
INCOMPLETE_WARNING = "Uplinks konnten nicht vollständig erkannt werden: {source}"


def _warn(session, source: str) -> None:
    append_warning(session.warnings, t(INCOMPLETE_WARNING, source=t(source)))


def _management_port(driver, session) -> str | None:
    address = driver.local_address(session)
    if not address:
        return None
    mac = driver.lookup_arp(session, address)
    if mac is None:
        gateway = driver.read_management_path(session).get("gateway")
        mac = driver.lookup_arp(session, gateway) if gateway else None
    return driver.lookup_mac_port(session, mac) if mac else None


def detect(driver, session, switch: dict) -> dict[str, str]:
    """Interface key -> translated reason; cached per session in ``session.cache["uplinks"]``."""
    cache = getattr(session, "cache", None)
    if cache is not None and "uplinks" in cache:
        return cache["uplinks"]
    capabilities = features.for_switch(driver, switch)
    found: dict[str, str] = {}

    if capabilities["management_path"].supported:
        try:
            port = _management_port(driver, session)
        except Exception:
            _warn(session, "Management-Pfad")
        else:
            if port:
                found[driver.interface_key(port)] = t(MANAGEMENT_REASON)

    if capabilities["neighbors"].supported:
        try:
            neighbors = driver.read_neighbors(session)
        except Exception:
            _warn(session, "Nachbarn")
        else:
            for neighbor in neighbors:
                port = neighbor.get("local_interface")
                if port and clients.is_uplink_neighbor(neighbor):
                    name = neighbor.get("system_name") or neighbor.get("device_id") or port
                    found.setdefault(driver.interface_key(port), t(NEIGHBOR_REASON, name=name))

    if found and capabilities["lag"].supported:
        try:
            lags = driver.read_lags(session)
        except Exception:
            _warn(session, "Link-Aggregation")
        else:
            for lag in lags:
                members = [member["interface"] for member in lag.get("members") or ()]
                keys = [driver.interface_key(name) for name in (lag["interface"], *members)]
                if any(key in found for key in keys):
                    reason = t(LAG_REASON, lag=lag["interface"])
                    for key in keys:
                        found.setdefault(key, reason)

    if cache is not None:
        cache["uplinks"] = found
    return found
