"""Parsers for Cisco IOS / IOS-XE show output.

IOS reports rejected commands with lines starting with '%' and no return code;
a parser must never turn ``% Authorization failed`` into a valid empty table.
"""

import ipaddress
import logging
import re

from ....i18n import t
from ...clients import is_unicast_client_mac, normalize_mac_address
from ...errors import InvalidInputError, SwitchConnectionError, append_warning
from ..base import neighbor_row
from ..cli import parse_multiline_field

logger = logging.getLogger("switchsteward.switches.cisco")

INTERFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*[0-9](/[0-9]+)*(\.[0-9]+)?$")
# Show output uses the long name with a dash for port channels (``Port-channel1``);
# input validation and output parsers stay deliberately separate.
OUTPUT_INTERFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*[0-9](/[0-9]+)*(\.[0-9]+)?$")
# Configuration rejections. VTP refusals on ``vlan N`` / ``no vlan N`` (VTP client, or VTPv3 server that
# is not the primary server) are printed without the ``%`` prefix; IOS stays in global configuration mode.
IOS_ERROR_MARKERS = (r"^%", r"^VTP VLAN configuration not allowed\b")
IOS_AUTHORIZATION_MARKERS = (
    "authorization",
    "not authorized",
    "permission denied",
    "access denied",
    "insufficient privilege",
    "privilege level",
)
_UNSUPPORTED_MARKERS = ("invalid input", "unrecognized command", "incomplete command", "ambiguous command")

_INTERFACE_ALIASES = (
    ("fourhundredgigabitethernet", "fourhu"),
    ("fourhundredgige", "fourhu"),
    ("twohundredgigabitethernet", "twohu"),
    ("twohundredgige", "twohu"),
    ("twentyfivegigabitethernet", "twe"),
    ("twentyfivegige", "twe"),
    ("fivegigabitethernet", "fi"),
    ("fivegige", "fi"),
    ("twogigabitethernet", "tw"),
    ("twogige", "tw"),
    ("hundredgigabitethernet", "hu"),
    ("hundredgige", "hu"),
    ("fortygigabitethernet", "fo"),
    ("fortygige", "fo"),
    ("tengigabitethernet", "te"),
    ("appgigabitethernet", "ap"),
    ("gigabitethernet", "gi"),
    ("fastethernet", "fa"),
    ("port-channel", "po"),
    ("portchannel", "po"),
    ("ethernet", "eth"),
)


_PORT_CHANNEL_RE = re.compile(r"^[Pp]ort-[Cc]hannel\d+$")


def validate_interface(interface: str) -> str:
    name = (interface or "").strip()
    if not (INTERFACE_RE.match(name) or _PORT_CHANNEL_RE.match(name)):
        raise InvalidInputError(t("Ungültiger Interface-Name: {interface}", interface=repr(interface)))
    return name


def parse_errdisabled(output: str) -> dict[str, str]:
    """``show interfaces status err-disabled``: interface key -> reason (e.g. ``psecure-violation``)."""
    reasons = {}
    for match in re.finditer(r"^(\S+)\s.*?\berr-disabled\s+(\S+)", output or "", re.MULTILINE):
        if INTERFACE_RE.fullmatch(match.group(1)):
            reasons[interface_key(match.group(1))] = match.group(2)
    return reasons


def interface_key(interface: str) -> str:
    key = interface.strip().lower()
    for long_name, short_name in _INTERFACE_ALIASES:
        if key.startswith(long_name):
            return short_name + key[len(long_name) :]
    return key


def is_physical_interface_name(interface: str) -> bool:
    key = interface_key(interface or "")
    return bool(
        re.match(
            r"^(?:ap|et|eth|fa|fi|fo|fourhu|gi|hu|te|tw|twe|twohu)\d+(?:/\d+)+(?:\.\d+)?$",
            key,
        )
    )


def extract_ios_errors(output: str) -> list:
    return [line.strip() for line in output.splitlines() if line.strip().startswith("%")]


def ensure_show_output(output: str, command: str) -> None:
    """Reject failed or empty IOS show output explicitly."""
    if not isinstance(output, str) or not output.strip():
        logger.warning("IOS returned no output for read command %r", command)
        raise SwitchConnectionError(t("Der Switch hat für '{command}' keine Ausgabe geliefert.", command=command))
    errors = extract_ios_errors(output)
    if errors:
        logger.warning("IOS rejected read command %r: %s", command, "; ".join(errors))
        raise SwitchConnectionError(
            t("Der Switch hat den Lesebefehl '{command}' abgelehnt: {errors}", command=command, errors="; ".join(errors))
        )


def unsupported_command_errors(output: str) -> bool:
    """True when every error line only reports unsupported syntax."""
    errors = extract_ios_errors(output or "")
    return bool(errors) and all(
        any(marker in error.casefold() for marker in _UNSUPPORTED_MARKERS) for error in errors
    )


def raise_on_ios_authorization_error(output: str, command: str) -> None:
    authorization_errors = [
        error
        for error in extract_ios_errors(output or "")
        if any(marker in error.casefold() for marker in IOS_AUTHORIZATION_MARKERS)
    ]
    if authorization_errors:
        logger.warning("IOS denied optional read command %r", command)
        raise SwitchConnectionError(
            t("Keine Berechtigung fuer den Lesebefehl '{command}': {errors}", command=command,
              errors="; ".join(authorization_errors))
        )


def interface_states(status: str) -> tuple[str, str]:
    """Admin and link state without treating err-disabled as shutdown."""
    normalized = (status or "").strip().casefold()
    if normalized in {"disabled", "shutdown", "admin-down", "administratively-down"}:
        return "disabled", "down"
    if normalized in {
        "connected",
        "notconnect",
        "err-disabled",
        "inactive",
        "notpresent",
        "sfpabsent",
        "down",
        "up",
        "link-flap",
    }:
        return "enabled", "up" if normalized in {"connected", "up"} else "down"
    if normalized == "monitoring":
        return "enabled", "unknown"
    return "unknown", "unknown"


def parse_interface_status(output: str) -> list:
    """Parse ``show interfaces status`` at the column boundaries of its header line.

    A whitespace heuristic fails for descriptions that fill the name column and
    leave only one space before the status field.
    """
    ensure_show_output(output, "show interfaces status")
    lines = output.splitlines()
    header_pos = next(
        (
            index
            for index, line in enumerate(lines)
            if re.match(
                r"^\s*Port\s+Name\s+Status\s+Vlan\s+Duplex\s+Speed\s+Type\s*$",
                line,
                re.IGNORECASE,
            )
        ),
        None,
    )
    if header_pos is None:
        raise SwitchConnectionError(
            t("Die Ausgabe von 'show interfaces status' enthaelt keine erkennbare Tabellenkopfzeile.")
        )

    header_line = lines[header_pos]
    column_matches = [
        re.search(rf"\b{column}\b", header_line, re.IGNORECASE)
        for column in ("Port", "Name", "Status", "Vlan", "Duplex", "Speed", "Type")
    ]
    if any(match is None for match in column_matches):
        raise SwitchConnectionError(t("Die Interface-Status-Tabelle hat ein unbekanntes Spaltenformat."))
    port_idx, name_idx, status_idx, vlan_idx, duplex_idx, _, _ = [
        match.start() for match in column_matches
    ]
    if not (port_idx < name_idx < status_idx < vlan_idx < duplex_idx):
        raise SwitchConnectionError(t("Die Interface-Status-Tabelle hat ungueltige Spaltengrenzen."))

    interfaces = []
    malformed_ports = []
    for line in lines[header_pos + 1 :]:
        if not line.strip():
            continue
        port = line[port_idx:name_idx].strip() if len(line) > port_idx else ""
        if not INTERFACE_RE.fullmatch(port):
            continue
        if len(line) < duplex_idx:
            malformed_ports.append(port)
            continue
        description = line[name_idx:status_idx].strip()
        status = line[status_idx:vlan_idx].strip()
        vlan = line[vlan_idx:duplex_idx].strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9._/-]*", status) or not re.fullmatch(
            r"(?:--|[A-Za-z0-9][A-Za-z0-9,._/-]*)", vlan
        ):
            malformed_ports.append(port)
            continue
        admin_state, link_state = interface_states(status)
        interfaces.append(
            {
                "port": port,
                "description": description,
                "status": status,
                "vlan": vlan,
                "admin_state": admin_state,
                "link_state": link_state,
            }
        )

    if malformed_ports:
        raise SwitchConnectionError(
            t("Interface-Status konnte fuer folgende Ports nicht sicher gelesen werden: {ports}",
              ports=", ".join(malformed_ports))
        )
    if not interfaces:
        raise SwitchConnectionError(t("Die Interface-Status-Tabelle enthaelt keine lesbaren Ports."))
    return interfaces


def parse_vlan_brief(output: str) -> list:
    """Parse ``show vlan brief`` at its fixed, firmware-dependent columns."""
    ensure_show_output(output, "show vlan brief")
    lines = output.splitlines()
    header_pos = next(
        (
            index
            for index, line in enumerate(lines)
            if re.match(r"^\s*VLAN\s+Name\s+Status\s+Ports\s*$", line, re.IGNORECASE)
        ),
        None,
    )
    if header_pos is None:
        raise SwitchConnectionError(
            t("Die Ausgabe von 'show vlan brief' enthaelt keine erkennbare Tabellenkopfzeile.")
        )

    header_line = lines[header_pos]
    matches = [re.search(rf"\b{column}\b", header_line, re.IGNORECASE) for column in ("VLAN", "Name", "Status", "Ports")]
    if any(match is None for match in matches):
        raise SwitchConnectionError(t("Die VLAN-Tabelle hat ein unbekanntes Spaltenformat."))
    vlan_idx, name_idx, status_idx, ports_idx = [match.start() for match in matches]
    if not (vlan_idx < name_idx < status_idx < ports_idx):
        raise SwitchConnectionError(t("Die VLAN-Tabelle hat ungueltige Spaltengrenzen."))

    vlans = []
    malformed_ids = []
    for line in lines[header_pos + 1 :]:
        if not line.strip():
            continue
        vlan_text = line[vlan_idx:name_idx].strip() if len(line) > vlan_idx else ""
        if not vlan_text.isdigit():
            continue
        if len(line) < ports_idx:
            # Rows without ports may end after the status column.
            line = line.ljust(ports_idx)
        name = line[name_idx:status_idx].strip()
        status = line[status_idx:ports_idx].strip()
        if not name or not re.fullmatch(r"[A-Za-z][A-Za-z0-9._/()-]*", status):
            malformed_ids.append(vlan_text)
            continue
        vlans.append({"id": int(vlan_text), "name": name, "status": status})

    if malformed_ids:
        raise SwitchConnectionError(
            t("VLAN-Daten konnten fuer folgende IDs nicht sicher gelesen werden: {ids}", ids=", ".join(malformed_ids))
        )
    if not vlans:
        raise SwitchConnectionError(t("Die VLAN-Tabelle enthaelt keine lesbaren VLANs."))
    return vlans


def parse_vlan_interfaces(output) -> frozenset[int] | None:
    """VLAN ids with an SVI from ``show ip interface brief``.

    ``None``: unknown (no output or a rejected command); empty set: the device has
    no layer-3 support (the command is unsupported).
    """
    if not isinstance(output, str) or not output.strip():
        return None
    if unsupported_command_errors(output):
        return frozenset()
    if extract_ios_errors(output):
        return None
    ids = (int(match) for match in re.findall(r"^(?:Vlan|Vl)(\d+)\s", output, re.IGNORECASE | re.MULTILINE))
    return frozenset(vlan for vlan in ids if 1 <= vlan <= 4094)


def switchport_vlan_id(raw_value: str | None):
    match = re.match(r"^\s*(\d+)(?:\s|\(|$)", raw_value or "")
    return int(match.group(1)) if match else None


def switchport_mode(switchport_enabled, administrative_mode: str | None, operational_mode: str | None) -> str:
    if switchport_enabled is False:
        return "routed"

    administrative = (administrative_mode or "").casefold()
    operational = (operational_mode or "").casefold()
    # Keep administrative special modes: a dynamic-desirable port can currently be
    # an operational trunk but must not be edited like a static trunk. Private VLAN
    # host ports must never coincide with promiscuous or trunk ports.
    private_mode = administrative if "private-vlan" in administrative or "private vlan" in administrative else ""
    if not private_mode and ("private-vlan" in operational or "private vlan" in operational):
        private_mode = operational
    if private_mode:
        if "trunk" in private_mode:
            return "private-vlan-trunk"
        if "promiscuous" in private_mode:
            return "private-vlan-promiscuous"
        if "host" in private_mode:
            return "private-vlan-host"
        return "private-vlan"
    if "dynamic" in administrative:
        return "dynamic"
    if "routed" in administrative:
        return "routed"
    for candidate in (operational, administrative):
        if "trunk" in candidate:
            return "trunk"
        if "access" in candidate:
            return "access"
        if "routed" in candidate:
            return "routed"
    return "unknown"


def parse_interfaces_switchport(output: str) -> dict[str, dict]:
    """Parse the bulk output of ``show interfaces switchport`` per interface."""
    command = "show interfaces switchport"
    ensure_show_output(output, command)
    lines = output.splitlines()
    starts = [
        index
        for index, line in enumerate(lines)
        if re.match(r"^\s*Name\s*:\s*\S+\s*$", line, re.IGNORECASE)
    ]
    if not starts:
        raise SwitchConnectionError(
            t("Die Ausgabe von 'show interfaces switchport' enthaelt keine Interface-Bloecke.")
        )

    result = {}
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        block = "\n".join(lines[start:end])
        interface = parse_multiline_field(block, "Name")
        if not interface or not OUTPUT_INTERFACE_RE.fullmatch(interface):
            raise SwitchConnectionError(t("Ein Switchport-Block enthaelt keinen gueltigen Interface-Namen."))

        raw_switchport = parse_multiline_field(block, "Switchport")
        normalized_switchport = (raw_switchport or "").strip().casefold()
        if normalized_switchport in {"enabled", "yes"}:
            switchport_enabled = True
        elif normalized_switchport in {"disabled", "not enabled", "no"}:
            switchport_enabled = False
        else:
            switchport_enabled = None

        administrative_mode = parse_multiline_field(block, "Administrative Mode")
        operational_mode = parse_multiline_field(block, "Operational Mode")
        administrative_mode = administrative_mode.strip().lower() if administrative_mode else None
        operational_mode = operational_mode.strip().lower() if operational_mode else None
        detail = {
            "interface": interface,
            "switchport_enabled": switchport_enabled,
            "administrative_mode": administrative_mode,
            "operational_mode": operational_mode,
            "mode": switchport_mode(switchport_enabled, administrative_mode, operational_mode),
            "access_vlan": switchport_vlan_id(parse_multiline_field(block, "Access Mode VLAN")),
            "voice_vlan": switchport_vlan_id(parse_multiline_field(block, "Voice VLAN")),
            "native_vlan": switchport_vlan_id(parse_multiline_field(block, "Trunking Native Mode VLAN")),
            "trunk_allowed_vlan": parse_multiline_field(block, "Trunking VLANs Enabled"),
        }
        if switchport_enabled is False:
            for field in ("access_vlan", "voice_vlan", "native_vlan", "trunk_allowed_vlan"):
                detail[field] = None

        key = interface_key(interface)
        if key in result:
            raise SwitchConnectionError(t("Interface {interface} kommt mehrfach in der Switchport-Ausgabe vor.", interface=interface))
        result[key] = detail
    return result


def parse_optional_switchport_output(output: str, warnings: list[str]) -> tuple[dict[str, dict], bool]:
    """Details and whether the safe per-port fallback is required."""
    command = "show interfaces switchport"
    raise_on_ios_authorization_error(output, command)
    if extract_ios_errors(output or ""):
        if unsupported_command_errors(output):
            append_warning(warnings, t("Die Firmware unterstuetzt die Bulk-Switchport-Abfrage nicht."))
        else:
            append_warning(warnings, t("Die optionale Bulk-Switchport-Abfrage wurde abgelehnt."))
        return {}, True

    try:
        return parse_interfaces_switchport(output), False
    except SwitchConnectionError:
        logger.warning("Could not parse optional bulk switchport output")
        append_warning(warnings, t("Das Bulk-Switchport-Ausgabeformat ist unbekannt."))
        return {}, True


def validated_unique_status_ports(interfaces: list[dict], warnings: list[str]) -> list[str]:
    ports = []
    seen = set()
    invalid_found = False
    for interface in interfaces:
        try:
            port = validate_interface(interface.get("port"))
        except (AttributeError, InvalidInputError):
            invalid_found = True
            continue
        key = interface_key(port)
        if key not in seen:
            seen.add(key)
            ports.append(port)
    if invalid_found:
        append_warning(
            warnings,
            t("Mindestens ein ungueltiger Portname aus der Status-Tabelle wurde beim Fallback uebersprungen."),
        )
    return ports


def parse_show_version(output: str) -> dict:
    """hostname, model, serial_number, software_version and uptime from ``show version``.

    The format differs slightly between IOS platforms; several fallback patterns per field.
    """
    info = {"hostname": None, "model": None, "serial_number": None, "software_version": None, "uptime": None}

    m = re.search(r"^(\S+)\s+uptime is\s+(.+)$", output, re.MULTILINE)
    if m:
        info["hostname"] = m.group(1)
        info["uptime"] = m.group(2).strip()

    m = re.search(r"[Vv]ersion\s+([^\s,]+)\s*,", output)
    if m:
        info["software_version"] = m.group(1)

    m = re.search(r"[Mm]odel [Nn]umber\s*:\s*(\S+)", output)
    if not m:
        m = re.search(r"[Cc]isco\s+(WS-\S+|C\d\S*|IE-\S+)\s*\(", output)
    if m:
        info["model"] = m.group(1)

    m = re.search(r"System [Ss]erial [Nn]umber\s*:\s*(\S+)", output)
    if not m:
        m = re.search(r"[Pp]rocessor board ID\s+(\S+)", output)
    if m:
        info["serial_number"] = m.group(1)
    return info


def parse_interface_capabilities(output: str) -> dict[str, list[str]]:
    """Speed/duplex options from ``show interfaces <if> capabilities`` (empty dict if unknown)."""
    options = {}
    speed = re.search(r"^\s*Speed\s*:\s*(.+?)\s*$", output or "", re.MULTILINE | re.IGNORECASE)
    if speed:
        values = [value.strip().casefold() for value in re.split(r"[/,\s]+", speed.group(1)) if value.strip()]
        speeds = [value for value in ("10", "100", "1000") if value in values]
        if speeds:
            options["speed"] = (["auto"] if "auto" in values or len(speeds) > 1 else []) + speeds
    duplex = re.search(r"^\s*Duplex\s*:\s*(.+?)\s*$", output or "", re.MULTILINE | re.IGNORECASE)
    if duplex:
        values = [value.strip().casefold() for value in re.split(r"[/,\s]+", duplex.group(1)) if value.strip()]
        duplexes = [value for value in ("auto", "half", "full") if value in values]
        if duplexes:
            options["duplex"] = duplexes
    return options


def parse_cdp_neighbors_detail(output: str) -> list:
    """Split ``show cdp neighbors detail`` into neighbor rows.

    IOS and IOS-XE differ in spacing, optional fields and address types. Blocks
    are split at ``Device ID``; missing fields stay ``None`` instead of discarding
    the whole read.
    """

    def field(block_text: str, pattern: str):
        match = re.search(pattern, block_text, re.MULTILINE | re.IGNORECASE)
        return match.group(1).strip() if match else None

    blocks = re.split(r"(?=^\s*Device ID\s*:\s*)", output, flags=re.MULTILINE | re.IGNORECASE)
    neighbors = []

    for block in blocks:
        device_match = re.search(r"^\s*Device ID\s*:\s*(.+?)\s*$", block, re.MULTILINE | re.IGNORECASE)
        if not device_match:
            continue

        platform_match = re.search(
            r"^\s*Platform\s*:\s*(.*?)(?:,\s*Capabilities\s*:\s*(.*))?\s*$",
            block,
            re.MULTILINE | re.IGNORECASE,
        )
        interface_match = re.search(
            r"^\s*Interface\s*:\s*(.*?),\s*Port ID \(outgoing port\)\s*:\s*(.*?)\s*$",
            block,
            re.MULTILINE | re.IGNORECASE,
        )

        ip_addresses = []
        for address in re.findall(
            r"^\s*(?:IP|IPv4|IPv6) address\s*:\s*(\S+)", block, re.MULTILINE | re.IGNORECASE
        ):
            if address not in ip_addresses:
                ip_addresses.append(address)

        version = None
        version_match = re.search(
            r"^\s*Version\s*:\s*\n(.*?)(?=^\s*(?:advertisement version|VTP Management Domain|Native VLAN|Duplex|"
            r"Management address\(es\)|Power drawn|Physical Location|Device Sensor)\s*:|\Z)",
            block,
            re.MULTILINE | re.IGNORECASE | re.DOTALL,
        )
        if version_match:
            version_lines = [line.strip() for line in version_match.group(1).splitlines() if line.strip()]
            version = "\n".join(version_lines) or None

        holdtime = field(block, r"^\s*Holdtime\s*:\s*(\d+)")
        native_vlan = field(block, r"^\s*Native VLAN\s*:\s*(\d+)")
        vtp_domain = field(block, r"^\s*VTP Management Domain\s*:\s*(.*?)\s*$")
        if vtp_domain:
            vtp_domain = vtp_domain.strip("'").strip(chr(34))
        neighbors.append(
            neighbor_row(
                "cdp",
                device_id=device_match.group(1).strip(),
                platform=platform_match.group(1).strip() if platform_match else None,
                capabilities=platform_match.group(2).strip() if platform_match and platform_match.group(2) else None,
                ip_addresses=ip_addresses,
                local_interface=interface_match.group(1).strip() if interface_match else None,
                remote_interface=interface_match.group(2).strip() if interface_match else None,
                holdtime_seconds=int(holdtime) if holdtime else None,
                software_version=version,
                native_vlan=int(native_vlan) if native_vlan else None,
                duplex=field(block, r"^\s*Duplex\s*:\s*(\S+).*?$"),
                vtp_domain=vtp_domain,
                advertisement_version=field(block, r"^\s*advertisement version\s*:\s*(\S+).*?$"),
            )
        )

    return neighbors


def parse_lldp_neighbors_detail(output: str) -> list[dict]:
    """Parse the common IOS/IOS-XE variants of ``show lldp neighbors detail``.

    Missing fields stay ``None`` or empty and never invalidate locally confirmed clients.
    """

    def field(block_text: str, labels: tuple[str, ...]):
        alternatives = "|".join(re.escape(label) for label in labels)
        match = re.search(
            rf"^\s*(?:{alternatives})\s*:\s*(.*?)\s*$",
            block_text,
            re.MULTILINE | re.IGNORECASE,
        )
        return match.group(1).strip() if match else None

    blocks = re.split(
        r"(?=^\s*Local (?:(?:Intf|Interface)|Port id)\s*:\s*)",
        output or "",
        flags=re.MULTILINE | re.IGNORECASE,
    )
    neighbors = []
    for block in blocks:
        local_interface = field(block, ("Local Intf", "Local Interface", "Local Port id", "Local Port ID"))
        if not local_interface:
            continue

        system_name = field(block, ("System Name",))
        ip_addresses = []
        for address in re.findall(
            r"^[ \t]*(?:IP(?:v4)?(?: address)?|Management Address(?:es)?(?:[ \t]*-[ \t]*IP)?)[ \t]*:[ \t]*(\S+)",
            block,
            re.MULTILINE | re.IGNORECASE,
        ):
            candidate = address.strip(",;()[]")
            try:
                parsed = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            normalized = str(parsed)
            if normalized not in ip_addresses:
                ip_addresses.append(normalized)

        neighbors.append(
            neighbor_row(
                "lldp",
                # A chassis ID is often only a MAC address and no device name; it
                # stays separate for unambiguous correlation.
                device_id=system_name,
                system_name=system_name,
                chassis_id=field(block, ("Chassis id", "Chassis ID")),
                platform=field(block, ("System Description", "System Desc")),
                capabilities=field(block, ("Enabled Capabilities", "System Capabilities")),
                ip_addresses=ip_addresses,
                local_interface=local_interface,
                remote_interface=field(block, ("Port id", "Port ID")),
            )
        )
    return neighbors


def mac_table_row(columns: list[str]) -> dict | None:
    """Parse exactly the two column orders used by IOS families.

    ``VLAN MAC TYPE PORT`` (IOS/IOS-XE) and ``MAC TYPE VLAN PORT`` (older
    platforms). The target interface is at the end of the line, also for
    TYPE2/TYPE3 layouts.
    """
    mac_index = next(
        (index for index, column in enumerate(columns) if normalize_mac_address(column)),
        None,
    )
    if mac_index is None:
        return None

    mac = normalize_mac_address(columns[mac_index])
    if mac_index > 0 and columns[mac_index - 1].isdigit() and mac_index + 2 < len(columns):
        vlan = columns[mac_index - 1]
        mac_type = columns[mac_index + 1]
        interface = columns[-1]
    elif mac_index + 3 < len(columns) and columns[mac_index + 2].isdigit():
        vlan = columns[mac_index + 2]
        mac_type = columns[mac_index + 1]
        interface = columns[-1]
    else:
        return None

    vlan_id = int(vlan)
    if not 1 <= vlan_id <= 4094 or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", mac_type):
        return None
    return {
        "vlan": str(vlan_id),
        "mac": mac,
        "type": mac_type.upper(),
        "interface": interface.rstrip(","),
    }


def parse_mac_table_with_diagnostics(output: str) -> tuple[list[dict], dict]:
    entries = []
    unparsed_data_lines = 0
    ignored_data_lines = 0
    seen = set()
    for line in output.splitlines():
        columns = line.split()
        mac = next(
            (normalize_mac_address(column) for column in columns if normalize_mac_address(column)),
            None,
        )
        if not mac:
            continue
        entry = mac_table_row(columns)
        if entry is None:
            has_physical_port = any(is_physical_interface_name(column.rstrip(",")) for column in columns)
            if is_unicast_client_mac(mac) and has_physical_port:
                unparsed_data_lines += 1
            else:
                ignored_data_lines += 1
            continue
        key = (entry["vlan"], entry["mac"], entry["type"], interface_key(entry["interface"]))
        if key not in seen:
            seen.add(key)
            entries.append(entry)
    return entries, {
        "parsed_entries": len(entries),
        "unparsed_data_lines": unparsed_data_lines,
        "ignored_data_lines": ignored_data_lines,
    }


def parse_arp_table(output: str) -> dict[str, str]:
    result = {}
    for line in output.splitlines():
        columns = line.split()
        if len(columns) < 4 or columns[0].lower() != "internet":
            continue
        mac = normalize_mac_address(columns[3])
        try:
            address = ipaddress.IPv4Address(columns[1])
        except ipaddress.AddressValueError:
            continue
        if mac and not address.is_unspecified:
            result[mac] = str(address)
    return result


def parse_ip_mac_bindings(output: str) -> dict[str, str]:
    """IPv4/MAC pairs from Cisco device-tracking and DHCP snooping tables.

    The column order differs between IOS versions and commands, so values are
    recognized by format, not by position.
    """
    result = {}
    for line in output.splitlines():
        ip = None
        mac = None
        for column in line.split():
            candidate = column.strip(",;()[]")
            if ip is None:
                try:
                    address = ipaddress.ip_address(candidate)
                except ValueError:
                    pass
                else:
                    if address.version == 4 and not address.is_unspecified:
                        ip = str(address)
            if mac is None:
                mac = normalize_mac_address(candidate)
        if ip and mac:
            result[mac] = ip
    return result


# --- Management path ------------------------------------------------------------------


def parse_ip_interfaces(output: str) -> list[tuple[str, str]]:
    """(interface, IPv4 address) rows of ``show ip interface brief``."""
    rows = []
    for line in output.splitlines():
        columns = line.split()
        if len(columns) < 2 or not OUTPUT_INTERFACE_RE.match(columns[0]):
            continue
        try:
            rows.append((columns[0], str(ipaddress.IPv4Address(columns[1]))))
        except ipaddress.AddressValueError:
            continue
    return rows


def is_management_port(interface: str) -> bool:
    """Out-of-band port of Catalyst 9000/3850 (``GigabitEthernet0/0`` in ``Mgmt-vrf``)."""
    return interface_key(interface) == "gi0/0"


def parse_gateway(output) -> str | None:
    """``ip default-gateway X``, ``Gateway of last resort is X`` or ``Default gateway is X``."""
    if not isinstance(output, str):
        return None
    match = re.search(
        r"^\s*(?:ip default-gateway|Gateway of last resort is|Default gateway is)\s+(\d+\.\d+\.\d+\.\d+)",
        output, re.MULTILINE,
    )
    return match.group(1) if match else None


def parse_arp_lookup(output, ip: str) -> str | None:
    """MAC (``aa:bb:cc:dd:ee:ff``) of ``ip`` in ``show ip arp`` output, None if absent/incomplete."""
    if not isinstance(output, str):
        return None
    for line in output.splitlines():
        columns = line.split()
        if len(columns) >= 4 and columns[0].lower() == "internet" and columns[1] == ip:
            mac = normalize_mac_address(columns[3])
            if mac:
                return ":".join(mac[index:index + 2] for index in range(0, 12, 2))
    return None
