"""Vendor-neutral client correlation, coverage, client inventory and global search.

Input is a client snapshot (see ``drivers.base.client_snapshot``). The driver is
passed in for ``interface_key`` and ``is_physical_interface`` only; nothing here
sends device commands.
"""

import contextvars
import ipaddress
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..i18n import t
from .dns import device_names_by_ip
from .errors import SwitchConnectionError, append_warning

logger = logging.getLogger("switchsteward.switches.clients")

GLOBAL_CLIENT_SEARCH_MAX_WORKERS = 6

_MAC_RE = re.compile(
    r"(?:[0-9a-fA-F]{12}|[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}|[0-9a-fA-F]{6}-[0-9a-fA-F]{6}|"
    r"[0-9a-fA-F]{2}(?P<separator>[:-])[0-9a-fA-F]{2}(?:(?P=separator)[0-9a-fA-F]{2}){4})"
)


# --- MAC helpers ---------------------------------------------------------------


def normalize_mac_address(value: str):
    """12 lowercase hex digits for Cisco, colon/dash and ``001122-334455`` notation, else None."""
    if not isinstance(value, str) or not _MAC_RE.fullmatch(value):
        return None
    return re.sub(r"[.:-]", "", value).lower()


def format_mac_address(value: str) -> str:
    normalized = normalize_mac_address(value)
    if not normalized:
        return value.lower()
    return ":".join(normalized[index : index + 2] for index in range(0, 12, 2))


def normalized_mac_type(value: str | None) -> str:
    normalized = (value or "").upper()
    if normalized.isascii() and normalized.isalnum():
        return normalized
    return re.sub(r"[^A-Z0-9]", "", normalized)


def is_unicast_client_mac(value: str | None) -> bool:
    mac = normalize_mac_address(value or "")
    return bool(mac and mac != "0" * 12 and not (int(mac[:2], 16) & 1))


def is_dynamic_client_mac_type(value: str | None) -> bool:
    return normalized_mac_type(value) in {"DYNAMIC", "SECUREDYNAMIC", "DYNAMICSECURE"}


def is_persistent_secure_mac_type(value: str | None) -> bool:
    normalized = normalized_mac_type(value)
    return normalized == "STATIC" or "STICKY" in normalized


def mac_entry_key(entry: dict, driver) -> tuple[str, str, str]:
    return (
        entry.get("mac") or "",
        str(entry.get("vlan") or ""),
        driver.interface_key(entry.get("interface") or ""),
    )


# --- Association evidence --------------------------------------------------------


def port_security_record(snapshot: dict, key: tuple[str, str, str]) -> dict | None:
    record = snapshot.get("port_security_entries", {}).get(key)
    if not isinstance(record, dict):
        return None
    return {"type": normalized_mac_type(record.get("type")), "source": record.get("source") or "port_security"}


def has_authenticated_session(entry: dict, snapshot: dict, driver) -> bool:
    return (
        entry.get("mac") or "",
        driver.interface_key(entry.get("interface") or ""),
    ) in snapshot.get("authentication_sessions", set())


def client_binding_sources(snapshot: dict, driver) -> dict[tuple[str, str, str], str]:
    """Index current bindings per processing run without mutating the snapshot.

    With several sources for the same tuple the first matching record wins. The
    index is rebuilt per run so updated snapshots never reuse stale mappings.
    """
    sources = {}
    for record in snapshot.get("ip_binding_records", ()):
        source = record.get("source")
        if source not in {"device_tracking", "dhcp_snooping"}:
            continue
        key = (record.get("mac"), str(record.get("vlan")), driver.interface_key(record.get("interface") or ""))
        sources.setdefault(key, source)
    return sources


def matching_client_binding_source(
    entry: dict, binding_sources: dict[tuple[str, str, str], str], driver,
) -> str | None:
    return binding_sources.get(
        (entry.get("mac"), str(entry.get("vlan")), driver.interface_key(entry.get("interface") or ""))
    )


def client_association(
    entry: dict,
    snapshot: dict,
    driver,
    *,
    binding_sources: dict[tuple[str, str, str], str],
) -> tuple[dict | None, str | None]:
    """Decide whether a table entry proves a current local association."""
    if not is_unicast_client_mac(entry.get("mac")):
        return None, "non_unicast_mac"
    normalized_type = normalized_mac_type(entry.get("type"))
    if normalized_type in {"DYNAMIC", "SECUREDYNAMIC", "DYNAMICSECURE"}:
        return {
            "currently_learned": True,
            "association_source": "mac_table_dynamic",
            "association_evidence": ["mac_table"],
        }, None
    if normalized_type in {"CONFIGUREDSECURE", "SECURECONFIGURED"}:
        return None, "configured_secure_mac"
    if normalized_type in {"CPU", "SELF", "SYSTEM"}:
        return None, "system_mac"
    if normalized_type == "STATIC" or "STICKY" in normalized_type:
        if has_authenticated_session(entry, snapshot, driver):
            return {
                "currently_learned": True,
                "association_source": "authenticated_session",
                "association_evidence": ["mac_table", "authentication_session"],
            }, None
        security_record = port_security_record(snapshot, mac_entry_key(entry, driver))
        if security_record is None:
            source_status = snapshot.get("source_status", {})
            if normalized_type == "STATIC" and all(
                source_status.get(source) == "ok"
                for source in ("port_security", "authentication_session")
            ):
                return None, "configured_static_mac"
            return None, "unverified_persistent_mac"
        security_type = security_record["type"]
        if security_type in {"CONFIGUREDSECURE", "SECURECONFIGURED"}:
            return None, "configured_secure_mac"
        if security_type in {"SECUREDYNAMIC", "DYNAMICSECURE"}:
            return {
                "currently_learned": True,
                "association_source": "port_security_dynamic",
                "association_evidence": ["mac_table", security_record["source"]],
            }, None
        if security_type not in {"SECURESTICKY", "STICKY"}:
            return None, "unsupported_mac_type"
        binding_source = matching_client_binding_source(entry, binding_sources, driver)
        if not binding_source:
            return None, "unverified_persistent_mac"
        return {
            "currently_learned": False,
            "association_source": "verified_port_security",
            "association_evidence": ["mac_table", "port_security", binding_source],
        }, None
    return None, "unsupported_mac_type"


# --- Port classification ---------------------------------------------------------


def is_link_up_physical_status(driver, interface: str, status: dict | None) -> bool:
    if not driver.is_physical_interface(interface or "") or not status:
        return False
    link_state = (status.get("link_state") or "").strip().casefold()
    if link_state:
        return link_state in {"up", "connected"}
    return (status.get("status") or "").strip().casefold() in {"up", "connected"}


def is_connected_physical_status(driver, interface: str, status: dict | None) -> bool:
    if not is_link_up_physical_status(driver, interface, status):
        return False
    return (status.get("vlan") or "").strip().casefold() not in {"trunk", "routed"}


def client_status_candidates(interfaces: list[dict], driver) -> list[dict]:
    """Connected physical non-trunk ports, independent of the MAC table."""
    candidates = []
    seen = set()
    for status in interfaces:
        if not is_connected_physical_status(driver, status.get("port", ""), status):
            continue
        key = driver.interface_key(status["port"])
        if key not in seen:
            seen.add(key)
            candidates.append(status)
    return candidates


def prioritize_client_candidates(candidates: list[dict], mac_entries: list[dict], driver) -> list[dict]:
    """Keep ports with client MACs first for a limited per-port fallback."""
    mac_ports = {
        driver.interface_key(entry.get("interface") or "")
        for entry in mac_entries
        if is_unicast_client_mac(entry.get("mac"))
        and (is_dynamic_client_mac_type(entry.get("type")) or is_persistent_secure_mac_type(entry.get("type")))
    }
    return sorted(candidates, key=lambda item: driver.interface_key(item["port"]) not in mac_ports)


def usable_client_switchport_detail(detail: dict | None) -> bool:
    """True only when a detail can classify a client port safely."""
    if not detail:
        return False
    if detail.get("switchport_enabled") is False:
        return True
    mode = (detail.get("mode") or "").casefold()
    operational_mode = (detail.get("operational_mode") or "").casefold()
    if mode.startswith("private-vlan-") or mode in {"access", "trunk", "routed"}:
        return True
    return any(
        marker in operational_mode
        for marker in ("access", "trunk", "private-vlan", "private vlan", "routed")
    )


def client_switchport_scope(detail: dict | None) -> tuple[str, str | None]:
    if not usable_client_switchport_detail(detail):
        return "unresolved", "switchport_details_unavailable"
    administrative_mode = (detail.get("administrative_mode") or "").casefold()
    operational_mode = (detail.get("operational_mode") or "").casefold()
    mode = (detail.get("mode") or "").casefold()
    combined = " ".join((administrative_mode, operational_mode, mode))
    if detail.get("switchport_enabled") is False or mode == "routed" or "routed" in operational_mode:
        return "excluded", "routed_port"
    if "promiscuous" in combined:
        return "excluded", "private_vlan_promiscuous"
    if "trunk" in combined:
        return "excluded", "trunk_port"
    if mode == "private-vlan-host" or (
        ("private-vlan" in operational_mode or "private vlan" in operational_mode)
        and "host" in operational_mode
    ):
        return "edge", None
    if mode == "access" or "access" in operational_mode:
        return "edge", None
    return "unresolved", "switchport_mode_unresolved"


def classify_client_ports(driver, interfaces: list[dict], switchports: dict[str, dict]) -> dict:
    """Snapshot fields describing which link-up physical ports can carry local clients."""
    connected_physical_ports = [
        item for item in interfaces if is_link_up_physical_status(driver, item.get("port", ""), item)
    ]
    possible_candidates = client_status_candidates(interfaces, driver)
    possible_keys = {driver.interface_key(item["port"]) for item in possible_candidates}
    excluded_candidates = [
        {
            "interface": interface["port"],
            "reason": "trunk_port"
            if (interface.get("vlan") or "").strip().casefold() == "trunk"
            else "routed_port",
        }
        for interface in connected_physical_ports
        if driver.interface_key(interface["port"]) not in possible_keys
    ]
    client_candidates = []
    unresolved_candidates = []
    for interface in possible_candidates:
        scope, reason = client_switchport_scope(switchports.get(driver.interface_key(interface["port"])))
        if scope == "edge":
            client_candidates.append(interface)
        elif scope == "unresolved":
            client_candidates.append(interface)
            unresolved_candidates.append(interface)
        else:
            excluded_candidates.append({"interface": interface["port"], "reason": reason})
    return {
        "connected_port_names": [interface["port"] for interface in connected_physical_ports],
        "client_candidate_ports": [interface["port"] for interface in client_candidates],
        "excluded_candidate_ports": excluded_candidates,
        "unresolved_port_names": [interface["port"] for interface in unresolved_candidates],
        "unresolved_switchports": sorted(driver.interface_key(interface["port"]) for interface in unresolved_candidates),
    }


def status_vlan_ids(value: str) -> set[str]:
    text = (value or "").strip()
    if not re.fullmatch(r"\d+(?:\s*,\s*\d+)*", text):
        return set()
    return {part.strip() for part in text.split(",")}


def client_allowed_vlans(status: dict | None, details: dict | None) -> set[str]:
    allowed_vlans = status_vlan_ids(status.get("vlan", "") if status else "")
    if details:
        for field in ("access_vlan", "voice_vlan"):
            value = details.get(field)
            if isinstance(value, int):
                allowed_vlans.add(str(value))
            elif isinstance(value, str) and value.isdigit():
                allowed_vlans.add(value)
    return allowed_vlans


def client_vlan_consistency(vlan: str, status: dict | None, details: dict | None) -> tuple[str, list[str]]:
    allowed_vlans = client_allowed_vlans(status, details)
    if not allowed_vlans:
        return "unknown", []
    return ("verified" if str(vlan) in allowed_vlans else "mismatch"), sorted(allowed_vlans, key=int)


def is_physical_access_port(driver, interface: str, vlan: str, status: dict | None, details: dict | None) -> bool:
    if not is_connected_physical_status(driver, interface, status) or not details:
        return False
    administrative_mode = (details.get("administrative_mode") or "").casefold()
    operational_mode = (details.get("operational_mode") or "").casefold()
    mode = (details.get("mode") or "").casefold()
    combined_modes = " ".join((administrative_mode, operational_mode, mode))
    if (
        details.get("switchport_enabled") is False
        or "promiscuous" in combined_modes
        or "trunk" in combined_modes
        or mode == "routed"
    ):
        return False
    is_private_host = mode == "private-vlan-host" or (
        ("private-vlan" in operational_mode or "private vlan" in operational_mode)
        and "host" in operational_mode
    )
    if not is_private_host and mode != "access" and "access" not in operational_mode:
        return False
    # On a confirmed edge port the MAC stays visible even if the status VLAN and
    # the learned VLAN disagree; coverage and the device entry flag the mismatch.
    return str(vlan).isdigit()


# --- Local clients -----------------------------------------------------------------


def local_clients_from_snapshot(snapshot: dict, driver) -> list[dict]:
    interface_status = {driver.interface_key(item["port"]): item for item in snapshot["interfaces"]}
    switchports = snapshot.get("switchports", {})
    unresolved_switchports = set(snapshot.get("unresolved_switchports", ()))
    binding_sources = client_binding_sources(snapshot, driver)
    clients = []
    clients_by_interface = {}
    access_ports = {}
    seen = set()
    for entry in snapshot["mac_entries"]:
        association, _reason = client_association(entry, snapshot, driver, binding_sources=binding_sources)
        if association is None:
            continue
        key = driver.interface_key(entry["interface"])
        if key in unresolved_switchports:
            continue
        status = interface_status.get(key)
        port_vlan = (key, str(entry["vlan"]))
        if port_vlan not in access_ports:
            access_ports[port_vlan] = is_physical_access_port(
                driver, entry["interface"], entry["vlan"], status, switchports.get(key),
            )
        if not access_ports[port_vlan]:
            continue
        identity = (entry["mac"], entry["vlan"], key)
        if identity in seen:
            continue
        seen.add(identity)
        client = {
            "mac": format_mac_address(entry["mac"]),
            "ip": snapshot["ip_bindings"].get(entry["mac"]),
            "vlan": entry["vlan"],
            "interface": entry["interface"],
        }
        clients.append(client)
        clients_by_interface.setdefault(key, []).append(client)

    # Neighbor advertisements carry a management IP for some end devices (phones,
    # access points) without an ARP entry on the L2 switch. Unique only when
    # exactly one client MAC is on the port.
    for neighbor in snapshot["neighbors"]:
        local_interface = neighbor.get("local_interface")
        if not local_interface:
            continue
        port_clients = clients_by_interface.get(driver.interface_key(local_interface), [])
        if len(port_clients) != 1 or port_clients[0]["ip"]:
            continue
        addresses = valid_neighbor_ipv4_addresses(neighbor)
        if addresses:
            port_clients[0]["ip"] = addresses[0]
    return clients


CLIENT_COVERAGE_REASON_TEXT = {
    "switchport_details_unavailable": "Switchport-Details konnten nicht sicher ermittelt werden.",
    "switchport_mode_unresolved": "Der lokale Switchport-Modus ist nicht eindeutig.",
    "routed_port": "Der Port arbeitet als Layer-3-Port und liegt ausserhalb der Client-Erkennung.",
    "trunk_port": "Der Port arbeitet als Trunk und liegt ausserhalb der lokalen Client-Erkennung.",
    "private_vlan_promiscuous": "Der PVLAN-Promiscuous-Port liegt ausserhalb der lokalen Client-Erkennung.",
    "no_current_mac": "Am verbundenen Edge-Port ist aktuell keine MAC-Adresse sichtbar.",
    "vlan_mismatch": "Die gelernte VLAN-ID weicht von den erkannten Port-VLANs ab.",
    "unverified_persistent_mac": "Eine persistente MAC besitzt keinen aktuellen, portgenauen Sitzungs- oder Binding-Nachweis.",
    "configured_static_mac": "Die statische MAC besitzt keine aktuelle Authentifizierungs- oder Port-Security-Zuordnung.",
    "configured_secure_mac": "Die konfigurierte Secure-MAC belegt keine aktuelle Zuordnung.",
    "system_mac": "Die System-MAC ist kein angeschlossener Client.",
    "unsupported_mac_type": "Der MAC-Tabellentyp belegt keine aktuelle Client-Zuordnung.",
    "non_unicast_mac": "Multicast-, Broadcast- und Null-MACs sind keine lokalen Clients.",
}


def unique_port_names(values, driver) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if not value:
            continue
        key = driver.interface_key(value)
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def client_coverage(snapshot: dict, clients: list[dict], driver) -> dict:
    interface_status = {driver.interface_key(item["port"]): item for item in snapshot.get("interfaces", ())}
    switchports = snapshot.get("switchports", {})
    binding_sources = client_binding_sources(snapshot, driver)
    candidate_ports = unique_port_names(snapshot.get("client_candidate_ports", ()), driver)
    excluded_ports = list(snapshot.get("excluded_candidate_ports", ()))
    connected_ports = unique_port_names(
        snapshot.get("connected_port_names", ())
        or [*candidate_ports, *(item.get("interface") for item in excluded_ports)],
        driver,
    )
    unresolved_keys = {driver.interface_key(port) for port in snapshot.get("unresolved_port_names", ())}
    excluded_by_key = {
        driver.interface_key(item["interface"]): item["reason"]
        for item in excluded_ports
        if item.get("interface") and item.get("reason")
    }
    entries_by_port = {}
    for entry in snapshot.get("mac_entries", ()):
        entries_by_port.setdefault(driver.interface_key(entry.get("interface") or ""), []).append(entry)
    clients_by_port = {}
    for client in clients:
        clients_by_port.setdefault(driver.interface_key(client["interface"]), []).append(client)

    port_details = []
    ports_without_mac = []
    excluded_entries = []
    vlan_mismatches = []
    reason_counts = {}
    ignored_non_unicast_entries = 0
    for port in connected_ports:
        key = driver.interface_key(port)
        status = interface_status.get(key)
        details = switchports.get(key)
        all_port_entries = entries_by_port.get(key, [])
        raw_entries = [entry for entry in all_port_entries if is_unicast_client_mac(entry.get("mac"))]
        ignored_non_unicast_entries += len(all_port_entries) - len(raw_entries)
        port_clients = clients_by_port.get(key, [])
        observed_vlans = sorted(
            {str(entry.get("vlan")) for entry in raw_entries if str(entry.get("vlan") or "").isdigit()},
            key=int,
        )

        if key in excluded_by_key:
            state = "excluded"
            reason = excluded_by_key[key]
        elif key in unresolved_keys:
            state = "unresolved"
            reason = "switchport_details_unavailable"
        else:
            entry_reasons = []
            for entry in raw_entries:
                association, exclusion_reason = client_association(
                    entry, snapshot, driver, binding_sources=binding_sources,
                )
                if association is None:
                    entry_reasons.append(exclusion_reason)
                    excluded_entries.append(
                        {
                            "interface": port,
                            "mac": format_mac_address(entry.get("mac") or ""),
                            "vlan": entry.get("vlan"),
                            "mac_type": entry.get("type"),
                            "reason": exclusion_reason,
                            "reason_text": t(CLIENT_COVERAGE_REASON_TEXT[exclusion_reason]),
                        }
                    )
            allowed_vlans = client_allowed_vlans(status, details) if port_clients else set()
            sorted_allowed_vlans = sorted(allowed_vlans, key=int)
            port_has_vlan_mismatch = False
            for client in port_clients:
                if allowed_vlans and str(client["vlan"]) not in allowed_vlans:
                    port_has_vlan_mismatch = True
                    vlan_mismatches.append(
                        {
                            "interface": port,
                            "mac": client["mac"],
                            "vlan": client["vlan"],
                            "allowed_vlans": list(sorted_allowed_vlans),
                            "reason": "vlan_mismatch",
                            "reason_text": t(CLIENT_COVERAGE_REASON_TEXT["vlan_mismatch"]),
                        }
                    )
            if port_clients:
                reason = "vlan_mismatch" if port_has_vlan_mismatch else None
                state = "detected_with_vlan_mismatch" if reason else "detected"
            elif not raw_entries:
                state, reason = "without_mac", "no_current_mac"
                ports_without_mac.append(port)
            else:
                state = "unverified"
                reason = entry_reasons[0] if entry_reasons else "unsupported_mac_type"

        if reason:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        port_details.append(
            {
                "interface": port,
                "state": state,
                "reason": reason,
                "reason_text": t(CLIENT_COVERAGE_REASON_TEXT[reason]) if reason in CLIENT_COVERAGE_REASON_TEXT else None,
                "mac_count": len(port_clients),
                "observed_vlans": observed_vlans,
            }
        )

    return {
        "connected_ports": connected_ports,
        "candidate_ports": candidate_ports,
        "unresolved_ports": unique_port_names(snapshot.get("unresolved_port_names", ()), driver),
        "ports_without_mac": ports_without_mac,
        "excluded_ports": excluded_ports,
        "excluded_entries": excluded_entries,
        "vlan_mismatches": vlan_mismatches,
        "ports": port_details,
        "reason_counts": reason_counts,
        "classification_complete": not any(
            item["reason"] in {"unverified_persistent_mac", "unsupported_mac_type"}
            for item in excluded_entries
        ),
        "ignored_non_unicast_entries": ignored_non_unicast_entries,
        "mac_table": dict(snapshot.get("mac_table_diagnostics", {})),
    }


def log_client_snapshot_warnings(snapshot: dict) -> None:
    switch = snapshot.get("switch") or {}
    for warning in snapshot.get("warnings", ()):
        logger.warning("Client snapshot warning for switch id=%s: %s", switch.get("id"), warning)


# --- Enrichment --------------------------------------------------------------------


def valid_neighbor_ipv4_addresses(neighbor: dict) -> list[str]:
    addresses = []
    for candidate in neighbor.get("ip_addresses", ()):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 4 and not address.is_unspecified:
            addresses.append(str(address))
    return addresses


def eligible_neighbors_for_client(client: dict, port_mac_count: int, neighbors: list[dict], driver) -> list[dict]:
    """Avoid assigning a neighbor to every client on a port with several MACs."""
    port_neighbors = [
        neighbor
        for neighbor in neighbors
        if neighbor.get("local_interface")
        and driver.interface_key(neighbor["local_interface"]) == driver.interface_key(client["interface"])
    ]
    if not port_neighbors:
        return []

    client_mac = normalize_mac_address(client["mac"])
    client_ip = client.get("ip")
    exact = []
    for neighbor in port_neighbors:
        chassis_mac = normalize_mac_address(neighbor.get("chassis_id") or "")
        if (client_mac and chassis_mac == client_mac) or (
            client_ip and client_ip in valid_neighbor_ipv4_addresses(neighbor)
        ):
            exact.append(neighbor)
    if exact:
        return exact
    return port_neighbors if port_mac_count == 1 else []


def is_infrastructure_neighbor(neighbor: dict) -> bool:
    capabilities = (neighbor.get("capabilities") or "").casefold()
    descriptive_text = " ".join(
        str(neighbor.get(field) or "")
        for field in ("device_id", "system_name", "platform")
    ).casefold()
    if re.search(r"\b(router|switch|bridge|telephone|phone)\b|access[ -]?point|wireless lan", capabilities):
        return True
    capability_codes = {
        token.upper()
        for token in re.findall(r"(?<![A-Za-z])[A-Za-z](?![A-Za-z])", capabilities)
    }
    if capability_codes & {"B", "R", "T", "W"}:
        return True
    return bool(
        re.search(
            r"\b(router|switch|bridge|telephone|phone)\b|access[ -]?point|wireless access|\bAIR-[A-Z0-9]",
            descriptive_text,
            re.IGNORECASE,
        )
    )


def is_uplink_neighbor(neighbor: dict) -> bool:
    """A switch, router or bridge that is not also a phone or access point (uplink detection)."""
    capabilities = (neighbor.get("capabilities") or "").casefold()
    codes = {token.upper() for token in re.findall(r"(?<![A-Za-z])[A-Za-z](?![A-Za-z])", capabilities)}
    if re.search(r"\b(telephone|phone)\b|access[ -]?point|\bwlan\b|wireless", capabilities) or codes & {"T", "W"}:
        return False
    return bool(re.search(r"\b(router|switch|bridge)\b", capabilities) or codes & {"B", "R"})


def neighbor_hint(neighbor: dict) -> dict:
    return {
        "protocol": neighbor.get("protocol"),
        "name": neighbor.get("device_id") or neighbor.get("system_name"),
        "platform": neighbor.get("platform"),
        "capabilities": neighbor.get("capabilities"),
        "remote_interface": neighbor.get("remote_interface"),
    }


def apply_device_dns_names(devices: list[dict], dns_names: dict[str, str]) -> None:
    for device in devices:
        if device.get("device_name") or not device.get("ip"):
            continue
        device_name = dns_names.get(device["ip"])
        if device_name:
            device["device_name"] = device_name
            device["name_source"] = "dns"


def enrich_local_client_devices(
    snapshot: dict,
    driver,
    clients: list[dict] | None = None,
    *,
    resolve_dns: bool = True,
) -> list[dict]:
    """Shared name/neighbor view for the client inventory and the global search."""
    local_clients = [
        dict(client)
        for client in (clients if clients is not None else local_clients_from_snapshot(snapshot, driver))
    ]
    port_counts = {}
    for client in local_clients:
        key = driver.interface_key(client["interface"])
        port_counts[key] = port_counts.get(key, 0) + 1

    binding_sources = client_binding_sources(snapshot, driver)
    entries_by_identity = {}
    for entry in snapshot["mac_entries"]:
        identity = mac_entry_key(entry, driver)
        if identity in entries_by_identity:
            continue
        association, _reason = client_association(entry, snapshot, driver, binding_sources=binding_sources)
        if association is not None:
            entries_by_identity[identity] = (entry, association)
    status_by_port = {driver.interface_key(item["port"]): item for item in snapshot["interfaces"]}
    neighbors_by_port = {}
    for neighbor in snapshot["neighbors"]:
        key = driver.interface_key(neighbor.get("local_interface") or "")
        neighbors_by_port.setdefault(key, []).append(neighbor)
    devices = []
    unresolved_names = []
    for client in local_clients:
        key = driver.interface_key(client["interface"])
        client_entry, association = entries_by_identity[(
            normalize_mac_address(client["mac"]), str(client["vlan"]), key,
        )]
        eligible_neighbors = eligible_neighbors_for_client(
            client, port_counts[key], neighbors_by_port.get(key, []), driver,
        )

        if not client.get("ip"):
            for neighbor in eligible_neighbors:
                addresses = valid_neighbor_ipv4_addresses(neighbor)
                if addresses:
                    client["ip"] = addresses[0]
                    break

        ip_source = snapshot.get("ip_sources", {}).get(normalize_mac_address(client["mac"]))
        if client.get("ip") and not ip_source:
            for neighbor in eligible_neighbors:
                if client["ip"] in valid_neighbor_ipv4_addresses(neighbor):
                    ip_source = neighbor.get("protocol")
                    break

        infrastructure_neighbors = [item for item in eligible_neighbors if is_infrastructure_neighbor(item)]
        selected_neighbor = (infrastructure_neighbors or eligible_neighbors or [None])[0]
        device_name = None
        name_source = None
        if selected_neighbor:
            device_name = selected_neighbor.get("device_id") or selected_neighbor.get("system_name")
            if device_name:
                name_source = selected_neighbor.get("protocol")

        switchport = snapshot.get("switchports", {}).get(key) or {}
        status = status_by_port.get(key, {})
        port_mode = switchport.get("mode") or status.get("mode") or "unknown"
        vlan_consistency, expected_vlans = client_vlan_consistency(client["vlan"], status, switchport)
        device = {
            **client,
            "device_name": device_name,
            "classification": "infrastructure" if infrastructure_neighbors else "unknown",
            "ip_source": ip_source,
            "name_source": name_source,
            "port_mac_count": port_counts[key],
            "currently_learned": association["currently_learned"],
            "mac_type": client_entry.get("type"),
            "association_source": association["association_source"],
            "association_evidence": association["association_evidence"],
            "vlan_consistency": vlan_consistency,
            "expected_vlans": expected_vlans,
            "port_mode": port_mode,
            "neighbor": neighbor_hint(selected_neighbor) if selected_neighbor else None,
        }
        if not device_name and device.get("ip"):
            unresolved_names.append(device)
        devices.append(device)

    if resolve_dns:
        dns_names = device_names_by_ip({device["ip"] for device in unresolved_names if device.get("ip")}, [])
        apply_device_dns_names(unresolved_names, dns_names)
    return devices


# --- Client inventory --------------------------------------------------------------


def build_client_inventory(snapshot: dict, driver) -> dict:
    """Confirmed local wired MACs with source-faithful enrichment.

    The local association is based on a current dynamic MAC or a strictly
    verified port-security entry, a physical link-up port and a safely detected
    access/PVLAN-host mode. Neighbor protocols only provide hints; there is no
    recursion behind neighbors.
    """
    log_client_snapshot_warnings(snapshot)
    clients = local_clients_from_snapshot(snapshot, driver)
    devices = enrich_local_client_devices(snapshot, driver, clients)
    port_counts = {}
    for client in clients:
        key = driver.interface_key(client["interface"])
        port_counts[key] = port_counts.get(key, 0) + 1

    coverage = client_coverage(snapshot, clients, driver)
    unresolved_ports = coverage["unresolved_ports"]
    mac_table_diagnostics = coverage.get("mac_table", {})
    result_warnings = list(snapshot.get("warnings", ()))
    if coverage["vlan_mismatches"]:
        append_warning(
            result_warnings,
            t("Mindestens eine lokale MAC wurde in einem unerwarteten VLAN gelernt; "
            "die Eintraege bleiben sichtbar und sind als VLAN-Abweichung markiert."),
        )
    binding_sources = client_binding_sources(snapshot, driver)
    summary = {
        "raw_dynamic_entries": sum(
            1 for entry in snapshot["mac_entries"] if is_dynamic_client_mac_type(entry.get("type"))
        ),
        "raw_mac_entries": len(snapshot["mac_entries"]),
        "verified_persistent_entries": sum(
            1
            for entry in snapshot["mac_entries"]
            if is_persistent_secure_mac_type(entry.get("type"))
            and client_association(entry, snapshot, driver, binding_sources=binding_sources)[0] is not None
        ),
        "local_devices": len(devices),
        "local_ports": len(port_counts),
        "with_ip": sum(1 for device in devices if device.get("ip")),
        "with_name": sum(1 for device in devices if device.get("device_name")),
        "infrastructure_devices": sum(
            1 for device in devices if device["classification"] == "infrastructure"
        ),
        "unclassified_devices": sum(1 for device in devices if device["classification"] == "unknown"),
        "without_ip": sum(1 for device in devices if not device.get("ip")),
        "multi_mac_ports": sum(1 for count in port_counts.values() if count > 1),
        "ports_without_mac": len(coverage["ports_without_mac"]),
        "vlan_mismatches": len(coverage["vlan_mismatches"]),
    }
    return {
        "devices": devices,
        "summary": summary,
        "coverage": coverage,
        "warnings": result_warnings,
        "complete": (
            coverage["classification_complete"]
            and not unresolved_ports
            and not mac_table_diagnostics.get("unparsed_data_lines", 0)
        ),
    }


# --- Global search -----------------------------------------------------------------


def normalized_mac_search_query(query: str):
    if not re.fullmatch(r"[0-9a-f.:\s-]+", query.strip(), re.IGNORECASE):
        return None
    compact_query = re.sub(r"[^0-9a-f]", "", query.casefold())
    return compact_query if len(compact_query) >= 2 else None


def client_matches_search(client: dict, query: str) -> bool:
    if query.strip().casefold() in (client.get("device_name") or "").casefold():
        return True
    compact_query = normalized_mac_search_query(query)
    compact_mac = normalize_mac_address(client.get("mac") or "")
    return compact_query is not None and compact_mac is not None and compact_query in compact_mac


def search_clients(switches: list[dict], query: str, read_snapshot) -> dict:
    """Search active local clients by name or MAC on the given switches.

    ``read_snapshot(switch) -> (snapshot, driver)`` reads one switch. Unreachable
    switches do not prevent partial results; the bounded parallelism keeps the
    response time acceptable without connecting to every device at once.
    """
    if not switches:
        return {"results": [], "switches_total": 0, "switches_scanned": 0, "failed_switches": []}

    snapshots = []
    failed_switches = []
    with ThreadPoolExecutor(max_workers=min(GLOBAL_CLIENT_SEARCH_MAX_WORKERS, len(switches))) as executor:
        futures = {
            executor.submit(contextvars.copy_context().run, read_snapshot, switch): switch
            for switch in switches
        }
        for future in as_completed(futures):
            switch = futures[future]
            try:
                snapshot, driver = future.result()
                log_client_snapshot_warnings(snapshot)
                snapshots.append((snapshot, driver))
            except SwitchConnectionError:
                logger.warning("Global client search failed for switch id=%s", switch.get("id"))
                failed_switches.append({"id": switch.get("id"), "name": switch.get("name")})
            except Exception:
                logger.exception("Unexpected error in global client search for switch id=%s", switch.get("id"))
                failed_switches.append({"id": switch.get("id"), "name": switch.get("name")})

    devices_by_snapshot = [
        (snapshot, driver, enrich_local_client_devices(snapshot, driver, resolve_dns=False))
        for snapshot, driver in snapshots
    ]
    all_devices = [device for _snapshot, _driver, devices in devices_by_snapshot for device in devices]
    dns_names = device_names_by_ip(
        {device["ip"] for device in all_devices if device.get("ip") and not device.get("device_name")},
        [],
    )
    apply_device_dns_names(all_devices, dns_names)

    results = []
    seen_results = set()
    for snapshot, driver, devices in devices_by_snapshot:
        switch = snapshot["switch"]
        for device in devices:
            if not client_matches_search(device, query):
                continue
            identity = (
                switch.get("id"),
                switch.get("ip"),
                normalize_mac_address(device.get("mac") or ""),
                str(device.get("vlan") or ""),
                driver.interface_key(device.get("interface") or ""),
            )
            if identity in seen_results:
                continue
            seen_results.add(identity)
            results.append(
                {
                    "mac": device.get("mac"),
                    "ip": device.get("ip"),
                    "vlan": device.get("vlan"),
                    "interface": device.get("interface"),
                    "device_name": device.get("device_name"),
                    "switch_id": switch.get("id"),
                    "switch_name": switch.get("name"),
                    "switch_ip": switch.get("ip"),
                    "site": switch.get("site"),
                }
            )

    results.sort(
        key=lambda client: (
            (client.get("switch_name") or "").casefold(),
            (client.get("device_name") or "").casefold(),
            client["mac"],
        )
    )
    failed_switches.sort(key=lambda switch: (switch.get("name") or "").casefold())
    return {
        "results": results,
        "switches_total": len(switches),
        "switches_scanned": len(snapshots),
        "failed_switches": failed_switches,
    }
