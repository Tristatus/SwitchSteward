"""Cisco client snapshot: MAC table, interface status, switchports and optional enrichment sources.

Optional sources never discard core data. After a read timeout the connection
is not reused (``session.broken``); later optional sources are skipped with a warning.
"""

import logging

from netmiko import NetmikoAuthenticationException

from ....i18n import t
from ... import clients, transport
from ...errors import SwitchConnectionError, append_warning
from ..base import client_snapshot
from . import parsers
from .parsers import extract_ios_errors, interface_key, is_physical_interface_name, unsupported_command_errors

logger = logging.getLogger("switchsteward.switches.cisco")

SWITCHPORT_FALLBACK_MAX_PORTS = 64
CLIENT_IP_BINDING_COMMANDS = (
    ("show device-tracking database", "device_tracking", "Device Tracking"),
    ("show ip device tracking all", "device_tracking", "Device Tracking"),
    ("show ip dhcp snooping binding", "dhcp_snooping", "DHCP Snooping"),
)
CLIENT_MAC_TABLE_COMMANDS = ("show mac address-table", "show mac-address-table")
CLIENT_AUTH_SESSION_COMMANDS = ("show authentication sessions", "show access-session")


# --- Parsers of optional client sources ---------------------------------------------


def parse_port_security_addresses(output: str) -> dict[tuple[str, str, str], dict[str, str]]:
    """Port-security tuples with type and unique source provenance."""
    entries = {}
    for line in output.splitlines():
        columns = line.split()
        mac_index = next(
            (index for index, column in enumerate(columns) if clients.normalize_mac_address(column)),
            None,
        )
        if mac_index is None:
            continue
        if mac_index > 0 and columns[mac_index - 1].isdigit() and mac_index + 2 < len(columns):
            vlan, mac_type, interface = columns[mac_index - 1], columns[mac_index + 1], columns[mac_index + 2]
        elif mac_index + 3 < len(columns) and columns[mac_index + 2].isdigit():
            vlan, mac_type, interface = columns[mac_index + 2], columns[mac_index + 1], columns[mac_index + 3]
        else:
            continue
        mac = clients.normalize_mac_address(columns[mac_index])
        security_type = clients.normalized_mac_type(mac_type)
        interface = interface.rstrip(",")
        if (
            mac
            and security_type
            in {
                "SECUREDYNAMIC",
                "DYNAMICSECURE",
                "SECURESTICKY",
                "STICKY",
                "SECURECONFIGURED",
                "CONFIGUREDSECURE",
            }
            and 1 <= int(vlan) <= 4094
            and is_physical_interface_name(interface)
        ):
            entries[(mac, str(int(vlan)), interface_key(interface))] = {
                "type": security_type,
                "source": "port_security",
            }
    return entries


def parse_authentication_sessions(output: str) -> set[tuple[str, str]]:
    """Only explicitly authorized MAC/port pairs from session tables."""
    sessions = set()
    authorized_states = {"AUTH", "AUTHORIZED"}
    for line in output.splitlines():
        columns = [column.strip(",;()[]") for column in line.split()]
        mac = next(
            (clients.normalize_mac_address(column) for column in columns if clients.normalize_mac_address(column)),
            None,
        )
        interface = next((column for column in columns if is_physical_interface_name(column)), None)
        states = [clients.normalized_mac_type(column) for column in columns]
        state_set = set(states)
        authz_results = {
            states[index + 1]
            for index, state in enumerate(states[:-1])
            if state == "AUTHZ"
        }
        explicitly_denied = bool(
            state_set & {"UNAUTH", "UNAUTHORIZED"}
            or authz_results & {"FAIL", "FAILED", "FAILURE"}
        )
        explicitly_authorized = bool(state_set & authorized_states or "SUCCESS" in authz_results)
        if (
            mac
            and clients.is_unicast_client_mac(mac)
            and interface
            and explicitly_authorized
            and not explicitly_denied
        ):
            sessions.add((mac, interface_key(interface)))
    return sessions


def parse_ip_mac_binding_records(output: str, source: str) -> list[dict]:
    """Current binding evidence including port and VLAN."""
    records = []
    seen = set()
    for line in output.splitlines():
        columns = [column.strip(",;()[]") for column in line.split()]
        states = {clients.normalized_mac_type(column) for column in columns}
        if source == "device_tracking" and not states & {"ACTIVE", "REACHABLE"}:
            # STALE/INCOMPLETE and unknown states are no fresh proof for a
            # persistent sticky association.
            continue
        mac = next(
            (clients.normalize_mac_address(column) for column in columns if clients.normalize_mac_address(column)),
            None,
        )
        interface_index = next(
            (index for index, column in enumerate(columns) if is_physical_interface_name(column)),
            None,
        )
        if not mac or interface_index is None:
            continue
        vlan = next(
            (
                str(int(columns[index]))
                for index in (interface_index - 1, interface_index + 1)
                if 0 <= index < len(columns)
                and columns[index].isdigit()
                and 1 <= int(columns[index]) <= 4094
            ),
            None,
        )
        if vlan is None:
            continue
        ip = parsers.parse_ip_mac_bindings(line).get(mac)
        if not ip:
            continue
        identity = (mac, vlan, interface_key(columns[interface_index]), source, ip)
        if identity in seen:
            continue
        seen.add(identity)
        records.append(
            {
                "mac": mac,
                "vlan": vlan,
                "interface": interface_key(columns[interface_index]),
                "source": source,
                "ip": ip,
            }
        )
    return records


# --- Readers ---------------------------------------------------------------------------


def read_optional_output(
    session: transport.SshSession, command: str, label: str, warnings: list[str],
) -> tuple[str, str]:
    """Read an optional source; status ok | timeout | skipped | empty | unsupported | error."""
    if session.broken:
        append_warning(warnings, t("{label} wurde nach einem Zeitlimit der Verbindung nicht mehr abgefragt.", label=t(label)))
        return "", "skipped"
    try:
        output = transport.send_show(session.conn, command)
    except transport.SSH_TIMEOUT_ERRORS:
        logger.warning("Optional source %r timed out", command)
        session.broken = True
        append_warning(warnings, t("{label} lief in ein Zeitlimit; die lokale MAC-Liste bleibt verfuegbar.", label=t(label)))
        return "", "timeout"

    if not isinstance(output, str) or not output.strip():
        append_warning(warnings, t("{label} lieferte keine lesbare Ausgabe.", label=t(label)))
        return "", "empty"

    if extract_ios_errors(output):
        if unsupported_command_errors(output):
            append_warning(warnings, t("{label} wird von dieser Firmware nicht unterstuetzt.", label=t(label)))
            return "", "unsupported"
        append_warning(warnings, t("{label} konnte nicht gelesen werden.", label=t(label)))
        return "", "error"
    return output, "ok"


def read_optional_output_with_syntax_fallback(
    session: transport.SshSession, commands: tuple[str, str], label: str, warnings: list[str],
) -> tuple[str, str, str]:
    """Try a legacy syntax only when the primary command is explicitly unsupported."""
    primary_command, legacy_command = commands
    primary_warnings = []
    output, status = read_optional_output(session, primary_command, label, primary_warnings)
    if status != "unsupported":
        for warning in primary_warnings:
            append_warning(warnings, warning)
        return output, status, primary_command

    legacy_warnings = []
    output, status = read_optional_output(session, legacy_command, label, legacy_warnings)
    if status == "unsupported":
        append_warning(warnings, t("{label} werden von dieser Firmware nicht unterstuetzt.", label=t(label)))
    else:
        for warning in legacy_warnings:
            append_warning(warnings, warning)
    return output, status, legacy_command


def read_mac_table_output(session: transport.SshSession) -> tuple[str, str]:
    """Use the old IOS spelling only after a pure syntax error."""
    primary_command, legacy_command = CLIENT_MAC_TABLE_COMMANDS
    primary_output = transport.send_show(session.conn, primary_command)
    if unsupported_command_errors(primary_output):
        legacy_output = transport.send_show(session.conn, legacy_command)
        parsers.ensure_show_output(legacy_output, legacy_command)
        return legacy_output, legacy_command
    parsers.ensure_show_output(primary_output, primary_command)
    return primary_output, primary_command


def read_switchports_individually(
    session: transport.SshSession, interfaces: list[dict], warnings: list[str],
) -> dict[str, dict]:
    """Safe, deduplicated per-port fallback for validated status ports (max. 64)."""
    ports = parsers.validated_unique_status_ports(interfaces, warnings)
    if not ports:
        return {}
    if len(ports) > SWITCHPORT_FALLBACK_MAX_PORTS:
        ports = ports[:SWITCHPORT_FALLBACK_MAX_PORTS]
        append_warning(
            warnings,
            t(
                "Der Einzelport-Fallback ist auf {limit} Ports begrenzt; weitere Switchport-Details bleiben unbekannt.",
                limit=SWITCHPORT_FALLBACK_MAX_PORTS,
            ),
        )

    details = {}
    for port in ports:
        command = f"show interfaces {port} switchport"
        try:
            output = transport.send_show(session.conn, command)
        except transport.SSH_TIMEOUT_ERRORS:
            logger.warning("Per-interface switchport read timed out for switch id=%s", session.switch.get("id"))
            session.broken = True
            append_warning(
                warnings,
                t("Der Einzelport-Fallback lief in ein Zeitlimit; verbleibende Switchport-Details sind unbekannt."),
            )
            break

        parsers.raise_on_ios_authorization_error(output, command)
        if extract_ios_errors(output or ""):
            append_warning(
                warnings,
                t("Mindestens eine Einzelport-Switchport-Abfrage wurde von der Firmware nicht unterstuetzt."),
            )
            continue
        try:
            parsed = parsers.parse_interfaces_switchport(output)
        except SwitchConnectionError:
            append_warning(
                warnings,
                t("Mindestens eine Einzelport-Switchport-Ausgabe konnte nicht sicher gelesen werden."),
            )
            continue
        key = interface_key(port)
        if key in parsed:
            details[key] = parsed[key]
        else:
            append_warning(
                warnings,
                t("Mindestens eine Einzelport-Switchport-Ausgabe passte nicht zum angefragten Port."),
            )
    return details


def fallback_switchports(
    session: transport.SshSession, netmiko_device_type: str, interfaces: list[dict], warnings: list[str],
) -> dict[str, dict]:
    """Per-port fallback on the session, or on a new connection after a timeout."""
    if not session.broken:
        return read_switchports_individually(session, interfaces, warnings)
    switch = session.switch
    try:
        with transport.open_ssh(switch, session.credentials, netmiko_device_type) as fallback:
            return read_switchports_individually(fallback, interfaces, warnings)
    except NetmikoAuthenticationException as exc:
        transport.raise_connection_error(switch, exc)
    except transport.SSH_TIMEOUT_ERRORS:
        logger.warning("Switchport fallback connection timed out for switch id=%s", switch.get("id"))
        append_warning(
            warnings,
            t("Die optionale Fallback-Verbindung war nicht erreichbar; Switchport-Details sind unbekannt."),
        )
    except transport.SSH_ERRORS as exc:
        transport.raise_connection_error(switch, exc)
    return {}


def read_client_snapshot(driver, session: transport.SshSession) -> dict:
    warnings = session.warnings
    switch = session.switch
    bulk_output = None
    needs_fallback = False
    ip_bindings = {}
    ip_sources = {}
    ip_binding_records = []
    port_security_entries = {}
    authentication_sessions = set()
    authentication_session_command = CLIENT_AUTH_SESSION_COMMANDS[0]
    source_status = {
        "arp": "not_requested",
        "device_tracking": "not_requested",
        "dhcp_snooping": "not_requested",
        "cdp": "not_requested",
        "lldp": "not_requested",
        "port_security": "not_requested",
        "authentication_session": "not_requested",
    }

    mac_out, mac_table_command = read_mac_table_output(session)
    mac_entries, mac_table_diagnostics = parsers.parse_mac_table_with_diagnostics(mac_out)
    if mac_table_diagnostics["unparsed_data_lines"]:
        append_warning(
            warnings,
            t("Mindestens eine relevante Zeile der MAC-Tabelle hatte ein unbekanntes Format; "
            "die Client-Erkennung kann unvollstaendig sein."),
        )
    interfaces = parsers.parse_interface_status(transport.send_show(session.conn, "show interfaces status"))
    interface_status = {interface_key(item["port"]): item for item in interfaces}
    client_candidates = clients.client_status_candidates(interfaces, driver)

    candidate_keys = {interface_key(item["port"]) for item in client_candidates}
    persistent_entries = [
        entry
        for entry in mac_entries
        if clients.is_persistent_secure_mac_type(entry.get("type"))
        and clients.is_unicast_client_mac(entry.get("mac"))
        and interface_key(entry.get("interface") or "") in candidate_keys
    ]
    if persistent_entries:
        port_security_out, source_status["port_security"] = read_optional_output(
            session, "show port-security address", "Port-Security-Adressen", warnings,
        )
        port_security_entries = parse_port_security_addresses(port_security_out)
        (
            authentication_out,
            source_status["authentication_session"],
            authentication_session_command,
        ) = read_optional_output_with_syntax_fallback(
            session, CLIENT_AUTH_SESSION_COMMANDS, "Authentifizierungssitzungen", warnings,
        )
        authentication_sessions = parse_authentication_sessions(authentication_out)

    arp_out, source_status["arp"] = read_optional_output(session, "show ip arp", "ARP-Tabelle", warnings)
    ip_bindings = parsers.parse_arp_table(arp_out)
    ip_sources.update({mac: "arp" for mac in ip_bindings})

    # A connected physical non-trunk port suffices for IP fallbacks here; the
    # stricter access/PVLAN check follows once switchport details are known.
    def has_security_evidence(entry: dict) -> bool:
        return (
            clients.port_security_record(
                {"port_security_entries": port_security_entries}, clients.mac_entry_key(entry, driver),
            ) is not None
            or (entry.get("mac"), interface_key(entry.get("interface") or "")) in authentication_sessions
        )

    client_macs = {
        entry["mac"]
        for entry in mac_entries
        if (
            clients.is_dynamic_client_mac_type(entry.get("type"))
            or (clients.is_persistent_secure_mac_type(entry.get("type")) and has_security_evidence(entry))
        )
        and clients.is_unicast_client_mac(entry.get("mac"))
        and clients.is_connected_physical_status(
            driver, entry["interface"], interface_status.get(interface_key(entry["interface"])),
        )
    }
    missing_macs = client_macs - ip_bindings.keys()
    pending_binding_keys = {
        clients.mac_entry_key(entry, driver)
        for entry in persistent_entries
        if (
            (
                security_record := clients.port_security_record(
                    {"port_security_entries": port_security_entries}, clients.mac_entry_key(entry, driver),
                )
            )
            and security_record["type"] in {"SECURESTICKY", "STICKY"}
        )
    }
    binding_warning_buffers = {}
    binding_source_succeeded = {}
    binding_source_labels = {}
    for command, source, label in CLIENT_IP_BINDING_COMMANDS:
        if not missing_macs and not pending_binding_keys:
            break
        binding_source_labels[source] = label
        source_warnings = binding_warning_buffers.setdefault(source, [])
        output, status = read_optional_output(session, command, label, source_warnings)
        if status == "ok":
            binding_source_succeeded[source] = True
        if status == "ok" or source_status[source] == "not_requested":
            source_status[source] = status
        bindings = parsers.parse_ip_mac_bindings(output)
        for record in parse_ip_mac_binding_records(output, source):
            pending_binding_keys.discard((record["mac"], record["vlan"], interface_key(record["interface"])))
            if record not in ip_binding_records:
                ip_binding_records.append(record)
        for mac in missing_macs & bindings.keys():
            ip_bindings[mac] = bindings[mac]
            ip_sources[mac] = source
        missing_macs -= bindings.keys()
    for source, source_warnings in binding_warning_buffers.items():
        if binding_source_succeeded.get(source) or not source_warnings:
            continue
        append_warning(
            warnings,
            t(
                "{label} ist auf diesem Switch nicht verfuegbar; IP-Zuordnungen koennen unvollstaendig sein.",
                label=t(binding_source_labels[source]),
            ),
        )

    cdp_out, source_status["cdp"] = read_optional_output(
        session, "show cdp neighbors detail", "CDP-Nachbarn", warnings,
    )
    lldp_out, source_status["lldp"] = read_optional_output(
        session, "show lldp neighbors detail", "LLDP-Nachbarn", warnings,
    )

    # Always query for client candidates: only then can numerically identical
    # private-VLAN host and promiscuous ports be told apart. Without candidates
    # the large output would be useless.
    if client_candidates:
        if session.broken:
            needs_fallback = True
        else:
            try:
                bulk_output = transport.send_show(session.conn, "show interfaces switchport")
            except transport.SSH_TIMEOUT_ERRORS:
                logger.warning("Client bulk switchport read timed out for switch id=%s", switch.get("id"))
                session.broken = True
                append_warning(
                    warnings,
                    t("Die optionale Bulk-Switchport-Abfrage lief in ein Zeitlimit; Einzelport-Fallback wird verwendet."),
                )
                needs_fallback = True

    switchports = {}
    if bulk_output is not None:
        switchports, needs_fallback = parsers.parse_optional_switchport_output(bulk_output, warnings)
    missing_candidates = [
        interface
        for interface in client_candidates
        if not clients.usable_client_switchport_detail(switchports.get(interface_key(interface["port"])))
    ]
    if needs_fallback or missing_candidates:
        fallback_candidates = clients.prioritize_client_candidates(
            missing_candidates if switchports else client_candidates, mac_entries, driver,
        )
        switchports.update(
            fallback_switchports(session, driver.netmiko_device_type, fallback_candidates, warnings)
        )

    return client_snapshot(
        switch,
        driver,
        mac_entries=mac_entries,
        interfaces=interfaces,
        switchports=switchports,
        ip_bindings=ip_bindings,
        ip_sources=ip_sources,
        ip_binding_records=ip_binding_records,
        neighbors=[*parsers.parse_cdp_neighbors_detail(cdp_out), *parsers.parse_lldp_neighbors_detail(lldp_out)],
        port_security_entries=port_security_entries,
        authentication_sessions=authentication_sessions,
        source_status=source_status,
        mac_table_diagnostics=mac_table_diagnostics,
        warnings=warnings,
        mac_table_command=mac_table_command,
        authentication_session_command=authentication_session_command,
    )
