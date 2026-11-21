"""Netgear fully managed switches (M4250/M4300/M4350/M5300/M7100, Netmiko ``netgear_prosafe``).

Experimental: commands and output formats follow the Netgear CLI manuals, not
captured device output (see docs/switch-drivers.md). Two VLAN syntaxes exist:
newer firmware accepts ``switchport ...`` (detected per session with
``show interfaces switchport <port>``), older firmware only the classic
``vlan participation``/``vlan tagging``/``vlan pvid`` commands. Classic VLAN
membership is derived from the interface's running configuration.

Netmiko (4.7.0) enters ``enable`` and sends ``terminal length 0`` itself;
``config_mode`` sends ``configure``; ``exit_config_mode`` only leaves the
global ``(Config)#`` level, so every interface sequence ends with ``exit``.
VLAN administration uses the Privileged-EXEC sub-mode ``vlan database``
(prompt ``(Vlan)#``), which is left with an explicit ``exit``.
"""

import ipaddress
import logging
import re
from dataclasses import replace

from netmiko import NetmikoAuthenticationException

from ... import config
from ...i18n import t
from .. import clients, transport
from .. import vlans as vlanlib
from ..catalog import ModelProfile
from ..errors import InvalidInputError, SwitchConnectionError, append_warning
from ..features import VTP_CISCO_ONLY_REASON, supported, unsupported
from ..validation import (
    format_vlan_list,
    parse_vlan_list,
    sanitize_description,
    validate_choice,
    validate_vlan_id,
)
from . import netgear_l2 as l2
from .base import (
    PortChange,
    SshSwitchDriver,
    WriteResult,
    client_snapshot,
    empty_poe_detail,
    empty_poe_summary,
    empty_switchport_detail,
    neighbor_row,
    write_result,
)
from .cisco.poe import STANDARD_LABELS
from .cli import error_lines, parse_key_values, run_config_lines
from .netgear_device import DEVICE_FEATURES, NetgearDeviceMixin
from .netgear_l2 import (
    FAMILY_AV,
    FAMILY_LEGACY,
    LAG_RE,
    NetgearConfig,
    normalize_interface,
    parse_config,
    vlan_list_lines,
)
from .netgear_models import NETGEAR_CATALOG
from .plans import (
    ChangePlan,
    CliCommand,
    CliLines,
    Pause,
    SecurityChange,
    SecurityGlobalChange,
    TransferLocation,
    cli_plan,
    combine_plans,
)

logger = logging.getLogger("switchsteward.switches.netgear")

SPEED_OPTIONS = ("auto", "10", "100", "1000")
DUPLEX_OPTIONS = ("auto", "half", "full")
POE_MODE_OPTIONS = ("auto", "never")
DESCRIPTION_MAX_LENGTH = 64
MAX_PORT_READS = 64
PORT_ACTION_PAUSE_SECONDS = 5
COPY_TIMEOUT_SECONDS = 600
RELOAD_TIMEOUT_SECONDS = 60
# Netgear copy: file names of at most 31 characters.
MAX_TRANSFER_FILENAME = 31
# Prompt answers: "save them now? (y/n)" -> n, every other (y/n) -> y.
SAVE_NO = (r"(?i)save", "n")
YES_NO_YES = (r"\(y/n\)", "y")
HOST_KEY_YES = (r"(?i)\(yes/no\)", "yes")
COPY_SUCCESS = r"(?i)completed successfully"

# Error messages start their own output line; anchoring keeps descriptions such as
# "Failed link" in echoed commands or running-config output from counting as errors.
ERROR_MARKERS = (
    r"^%\s*Invalid input",
    r"^Invalid input",
    r"^Command not found",
    r"^Incomplete command",
    r"^An invalid interface",
    r"^Error\b",
    r"^Failed\b",
)
# Errors meaning "this firmware does not know the command" (syntax detection, optional reads).
UNSUPPORTED_MARKERS = (r"^%?\s*Invalid input", r"^Command not found", r"^Unrecognized command")
SAVE_COMMAND = "write memory confirm"
SAVE_SUCCESS_RE = re.compile(r"(?i)created successfully|configuration saved")

SYNTAX_SWITCHPORT = "switchport"
SYNTAX_CLASSIC = "classic"

_INTERFACE_RE = re.compile(r"^(?:\d{1,2}/\d{1,2}(?:/\d{1,3})?|lag \d{1,3})$")
_MODEL_RE = re.compile(r"\bM(?:4250|4300|4350|5300|7100)-[A-Za-z0-9+\-]+", re.IGNORECASE)
_SEPARATOR_RE = re.compile(r"^\s*-{2,}(?:\s+-{2,})*\s*$")

UNKNOWN_MODE_REASON = (
    "Der VLAN-Modus von Interface {interface} ist nicht eindeutig (General-Modus); bitte den Modus mit angeben."
)
POE_UNCONFIRMED_REASON = "Die PoE-Unterstuetzung dieses Interfaces konnte nicht bestaetigt werden."
NO_POE_PORT_REASON = "Dieses Interface stellt kein PoE bereit."
# Reasons for unsupported features.
VLAN_VOICE_REASON = "Voice-VLAN ist auf dieser Plattform eine Port-Eigenschaft."
ROLLBACK_REASON = "Die Plattform hat kein zeitgesteuertes Rollback."
POE_LIMIT_REASON = "Netgear-Treiber setzt keine PoE-Leistungsprofile."
NOT_ERRDISABLED = "Der Port ist nicht durch eine Schutzfunktion deaktiviert."
POE_CYCLE_OFF = "PoE ist an Port {interface} ausgeschaltet; ein PoE-Neustart ist nicht möglich."
VOICE_EQUALS_ACCESS = "Voice-VLAN und Access-VLAN müssen verschieden sein."
# M4250/M4350 (firmware 13.x/14.x) use the authentication manager; M5300/M7100 LAGs default to static.
_AV_MODEL_RE = re.compile(r"^M4[23]50\b", re.IGNORECASE)
_STATIC_LAG_MODEL_RE = re.compile(r"^M(?:5300|7100)\b", re.IGNORECASE)

FEATURES = {
    "device_summary": supported(),
    "poe_budget": supported(),
    "interfaces": supported(),
    "port_detail": supported(),
    "port_description": supported(),
    "port_mode": supported(("access", "trunk")),
    "access_vlan": supported(),
    "native_vlan": supported(),
    "trunk_allowed_vlans": supported(),
    "voice_vlan": supported(),
    "vlans": supported(),
    "vlan_create": supported(),
    "vlan_rename": supported(),
    "vlan_delete": supported(),
    "vlan_voice": unsupported(VLAN_VOICE_REASON),
    "vtp": unsupported(VTP_CISCO_ONLY_REASON),
    "edge_port": supported(),
    "speed": supported(SPEED_OPTIONS, requires=("duplex",)),
    "duplex": supported(DUPLEX_OPTIONS, requires=("speed",)),
    "port_state": supported(),
    "port_bounce": supported(),
    "poe": supported(),
    "poe_mode": supported(POE_MODE_OPTIONS),
    "poe_limit": unsupported(POE_LIMIT_REASON),
    "poe_cycle": supported(),
    "errdisable_recovery": supported(),
    "neighbors": supported(),
    "clients": supported(),
    "client_search": supported(),
    "save_config": supported(),
    "config_backup": supported(),
    "config_compare": supported(),
    "config_restore": supported(),
    "config_rollback": unsupported(ROLLBACK_REASON),
    "management_path": supported(),
    "port_security": supported(("protect", "restrict", "shutdown")),
    "port_security_sticky": supported(),
    "dot1x": supported(("dot1x", "mab")),
    "dot1x_host_mode": supported(("single", "multi_auth", "multi_host")),
    "dot1x_fallback_vlans": supported(),
    "stp_guard": supported(("root_guard", "loop_guard")),
    "storm_control": supported(("broadcast", "multicast", "unknown_unicast")),
    "storm_control_action": supported(("drop", "shutdown")),
    "dhcp_snooping": supported(),
    "arp_inspection": supported(),
    "ip_source_guard": supported(),
    "lag": supported(("static", "lacp_active", "lacp_passive")),
    "stp": supported(("stp", "rstp", "mstp")),
    "stp_mst": supported(),
    "reload": supported(),
    **DEVICE_FEATURES,
}


# --- Generic output helpers --------------------------------------------------------------


def device_errors(output: str | None) -> list[str]:
    return error_lines(output, ERROR_MARKERS)


def is_unsupported_command(output: str | None) -> bool:
    return bool(error_lines(output, UNSUPPORTED_MARKERS))


def ensure_output(output, command: str) -> str:
    if not isinstance(output, str) or not output.strip():
        raise SwitchConnectionError(t("Der Switch hat für '{command}' keine Ausgabe geliefert.", command=command))
    errors = device_errors(output)
    if errors:
        raise SwitchConnectionError(
            t("Der Switch hat den Lesebefehl '{command}' abgelehnt: {errors}", command=command,
              errors="; ".join(errors))
        )
    return output


def parse_dashed_table(output: str | None) -> list[dict[str, str]] | None:
    """Table whose columns are given by a dashed separator line; header lines above may wrap.

    Column names are the lowercased header words above each dash group (``Link`` over
    ``State`` -> ``link state``). Returns ``None`` without a separator line.
    """
    lines = (output or "").splitlines()
    index = next((i for i, line in enumerate(lines) if _SEPARATOR_RE.match(line)), None)
    if index is None:
        return None
    spans = [match.start() for match in re.finditer(r"-+", lines[index])]
    header_lines = []
    for line in reversed(lines[max(0, index - 3):index]):
        if not line.strip():
            break
        header_lines.insert(0, line)
    names = []
    for position, start in enumerate(spans):
        end = spans[position + 1] if position + 1 < len(spans) else None
        words = " ".join(line[start:end].strip() for line in header_lines if line[start:end].strip())
        names.append(re.sub(r"\s+", " ", words).casefold())
    rows = []
    for line in lines[index + 1:]:
        if not line.strip() or _SEPARATOR_RE.match(line):
            continue
        row = {}
        for position, start in enumerate(spans):
            end = spans[position + 1] if position + 1 < len(spans) else None
            row[names[position]] = line[start:end].strip() if len(line) > start else ""
        rows.append(row)
    return rows


def column(row: dict[str, str], *prefixes: str) -> str:
    """Value of the first column whose name starts with one of the prefixes ('' if none)."""
    for prefix in prefixes:
        for name, value in row.items():
            if name.startswith(prefix):
                return value
    return ""


def _number(text: str | None) -> float | None:
    match = re.search(r"\d+(?:\.\d+)?", text or "")
    return float(match.group(0)) if match else None


def _vlan_set(text: str) -> set[int] | None:
    try:
        selection = parse_vlan_list(text)
    except InvalidInputError:
        return None
    return set(selection) if isinstance(selection, tuple) else None


def _lookup(values: dict[str, str], *keys: str) -> str | None:
    folded = {key.casefold(): value for key, value in values.items()}
    for key in keys:
        value = folded.get(key.casefold())
        if value is not None:
            return value.strip()
    return None


def _leading_int(text: str | None) -> int | None:
    match = re.match(r"\s*(\d{1,4})\b", text or "")
    return int(match.group(1)) if match else None


def _ipv4(text: str | None) -> str | None:
    """Dotted IPv4 address; None for missing, malformed or 0.0.0.0."""
    try:
        address = ipaddress.IPv4Address((text or "").strip())
    except ipaddress.AddressValueError:
        return None
    return None if address.is_unspecified else str(address)


def _is_vlan_database(step) -> bool:
    return isinstance(step, CliLines) and bool(step.lines) and step.lines[0] == "vlan database"


# --- Interface names ---------------------------------------------------------------------


def is_physical(name: str) -> bool:
    """``u/s/p`` with unit >= 1 (unit 0 = logical: 0/3/x LAG, 0/4/x VLAN routing); old ``s/p`` with slot 0."""
    parts = normalize_interface(name).split("/")
    if not all(part.isdigit() for part in parts):
        return False
    if len(parts) == 3:
        return int(parts[0]) >= 1
    return len(parts) == 2 and int(parts[0]) == 0


def is_lag(name: str) -> bool:
    """LAG interfaces: ``lag N`` or the logical ``0/3/N`` notation."""
    return bool(LAG_RE.match(normalize_interface(name)))


# --- Parsers -----------------------------------------------------------------------------


def parse_device_info(version_output: str, sysinfo_output: str | None) -> dict:
    version = parse_key_values(version_output)
    sysinfo = parse_key_values(sysinfo_output or "")
    description = _lookup(version, "System Description") or _lookup(sysinfo, "System Description") or ""
    machine_model = _lookup(version, "Machine Model") or ""
    model = None
    for text in (description, machine_model):
        match = _MODEL_RE.search(text)
        if match:
            model = match.group(0)
            break
    model = model or machine_model or None
    return {
        "hostname": _lookup(sysinfo, "System Name") or None,
        "model": model,
        "serial_number": _lookup(version, "Serial Number") or None,
        "software_version": _lookup(version, "Software Version") or None,
        "uptime": _lookup(sysinfo, "System Up Time") or None,
    }


def parse_port_admin(output: str | None) -> dict[str, dict]:
    """``show port all``: admin and link state per interface key."""
    states = {}
    for row in parse_dashed_table(output) or []:
        port = column(row, "intf", "interface", "port")
        if not _INTERFACE_RE.match(normalize_interface(port)):
            continue
        admin = column(row, "admin mode", "admin").casefold()
        link = column(row, "link status", "link state").casefold()
        states[normalize_interface(port)] = {
            "admin_state": "enabled" if admin.startswith("enable") else "disabled" if admin.startswith("disable")
            else "unknown",
            "link_state": "up" if link == "up" else "down" if link == "down" else "unknown",
        }
    return states


def parse_interface_status(output: str, admin_states: dict[str, dict]) -> list[dict]:
    """``show interfaces status all`` merged with the admin state from ``show port all``."""
    rows = parse_dashed_table(output)
    if rows is None:
        raise SwitchConnectionError(
            t("Die Ausgabe von '{command}' hat ein unbekanntes Format.", command="show interfaces status all")
        )
    interfaces = []
    for row in rows:
        port = re.sub(r"\s+", " ", column(row, "port", "intf", "interface"))
        if not _INTERFACE_RE.match(port.casefold()):
            continue
        state = admin_states.get(normalize_interface(port), {})
        link = column(row, "link state", "link").casefold()
        link_state = "up" if link == "up" else "down" if link == "down" else state.get("link_state", "unknown")
        admin_state = state.get("admin_state", "unknown")
        if admin_state == "disabled":
            status = "disabled"
        elif link_state == "up":
            status = "connected"
        elif link_state == "down":
            status = "notconnect"
        else:
            status = "unknown"
        vlan = column(row, "vlan")
        interfaces.append({
            "port": port,
            "description": column(row, "name", "description"),
            "status": status,
            "vlan": "trunk" if vlan.casefold() == "trunk" else vlan,
            "admin_state": admin_state,
            "link_state": link_state,
        })
    return interfaces


def parse_vlan_brief(output: str) -> list[dict]:
    rows = parse_dashed_table(output)
    if rows is None:
        raise SwitchConnectionError(t("Die Ausgabe von '{command}' hat ein unbekanntes Format.", command="show vlan brief"))
    vlans = []
    for row in rows:
        vlan_id = column(row, "vlan id", "vlan")
        if not vlan_id.isdigit() or not 1 <= int(vlan_id) <= 4094:
            continue
        vlans.append({"id": int(vlan_id), "name": column(row, "vlan name", "name"), "status": "active"})
    return vlans


def parse_running_interfaces(output: str | None) -> dict[str, list[str]]:
    """Interface blocks of ``show running-config [interface <p>]``: key -> stripped config lines."""
    return parse_config(output).interfaces


def parse_voice_vlan(lines: list[str]) -> int | None:
    """``voice vlan {vid}`` of an interface block (dot1p/none/untagged variants carry no VLAN)."""
    match = next((re.fullmatch(r"voice vlan (\d{1,4})", line) for line in lines if line.startswith("voice vlan ")),
                 None)
    return int(match.group(1)) if match else None


def classic_membership(lines: list[str]) -> dict:
    """VLAN membership from classic interface config; defaults: untagged member of VLAN 1, PVID 1."""
    members = {1}
    tagged: set[int] = set()
    pvid = 1
    for line in lines:
        match = re.fullmatch(r"vlan participation (include|exclude|auto) (\S+)", line, re.IGNORECASE)
        if match:
            vlans = _vlan_set(match.group(2)) or set()
            if match.group(1).casefold() == "include":
                members |= vlans
            else:
                members -= vlans
            continue
        match = re.fullmatch(r"(no )?vlan tagging (\S+)", line, re.IGNORECASE)
        if match:
            vlans = _vlan_set(match.group(2)) or set()
            tagged = tagged - vlans if match.group(1) else tagged | vlans
            continue
        match = re.fullmatch(r"vlan pvid (\d{1,4})", line, re.IGNORECASE)
        if match:
            pvid = int(match.group(1))
    return {"member_vlans": members, "tagged_vlans": tagged & members, "pvid": pvid}


def classic_switchport(interface: str, membership: dict, voice: int | None = None) -> dict:
    """Switchport detail derived from classic VLAN membership.

    A port whose only tagged VLAN is its voice VLAN and whose only untagged VLAN is the PVID is
    an access port with a voice VLAN.
    """
    detail = empty_switchport_detail(interface)
    members, tagged, pvid = membership["member_vlans"], membership["tagged_vlans"], membership["pvid"]
    untagged = members - tagged
    detail["switchport_enabled"] = True
    detail["voice_vlan"] = voice
    if voice is not None and tagged == {voice} and untagged == {pvid}:
        mode = "access"
        detail["access_vlan"] = pvid
    elif tagged:
        native = pvid if pvid in untagged else None
        mode = "trunk"
        detail.update(native_vlan=native, trunk_allowed_vlan=format_vlan_list(tuple(sorted(members))))
    elif untagged == {pvid}:
        mode = "access"
        detail["access_vlan"] = pvid
    else:
        mode = "general"
    detail.update(
        administrative_mode=mode,
        operational_mode=mode,
        mode=mode if mode != "general" else "unknown",
        vlan_syntax=SYNTAX_CLASSIC,
        member_vlans=sorted(members),
        tagged_vlans=sorted(tagged),
        pvid=pvid,
    )
    return detail


def _allowed_list_text(output: str, labels: tuple[str, ...]) -> str | None:
    """VLAN list field that may wrap onto follow-up lines consisting only of VLAN IDs."""
    lines = output.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^\s*([^:.]+?)\s*(?:\.{2,}\s*:?|:)\s*(.*?)\s*$", line)
        if not match or match.group(1).casefold() not in {label.casefold() for label in labels}:
            continue
        parts = [match.group(2)]
        for follow in lines[index + 1:]:
            if not re.fullmatch(r"\s+[\d,\-\s]+", follow):
                break
            parts.append(follow.strip())
        return ",".join(part.strip(",") for part in parts if part.strip(","))
    return None


def parse_switchport(output: str, interface: str) -> dict:
    """``show interfaces switchport <port>`` (switchport syntax)."""
    values = parse_key_values(output)
    detail = empty_switchport_detail(interface)
    mode_text = (_lookup(values, "VLAN Membership Mode", "Switchport Mode", "Administrative Mode", "Mode") or "")
    folded = mode_text.casefold()
    mode = "access" if "access" in folded else "trunk" if "trunk" in folded else "general" if "general" in folded \
        else None
    allowed = _allowed_list_text(
        output, ("Trunking Mode VLANs Enabled", "Trunk Allowed VLANs", "Allowed VLANs", "Trunking VLANs Enabled"),
    )
    if allowed is not None:
        allowed = re.sub(r"\s+", "", allowed)
        if allowed.casefold() == "all":
            allowed = "all"
        elif not allowed:
            allowed = "none"
    detail.update(
        switchport_enabled=True if mode else None,
        administrative_mode=mode,
        operational_mode=mode,
        mode=mode if mode in {"access", "trunk"} else "unknown",
        access_vlan=_leading_int(_lookup(values, "Access Mode VLAN", "Access VLAN")),
        native_vlan=_leading_int(_lookup(values, "Trunking Mode Native VLAN", "Trunk Native VLAN", "Native VLAN")),
        trunk_allowed_vlan=allowed,
        vlan_syntax=SYNTAX_SWITCHPORT,
    )
    return detail


def parse_vlan_port_pvid(output: str | None) -> int | None:
    """``show vlan port <p>``: Port VLAN ID (the current value when two columns exist)."""
    for row in parse_dashed_table(output) or []:
        current = column(row, "port vlan id current", "port vlan id")
        if current.isdigit():
            return int(current)
    return None


def parse_interface_config(lines: list[str]) -> dict:
    """Description, edge port, speed/duplex, shutdown and PoE admin state from interface config lines."""
    result = {"description": None, "portfast": False, "speed": "auto", "duplex": "auto", "shutdown": False,
              "poe_disabled": False}
    for line in lines:
        folded = line.casefold()
        match = re.fullmatch(r"description\s+(.+)", line, re.IGNORECASE)
        if match:
            text = match.group(1).strip()
            if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
                text = text[1:-1]
            result["description"] = text
        elif folded == "spanning-tree edgeport":
            result["portfast"] = True
        elif folded == "shutdown":
            result["shutdown"] = True
        elif folded == "no poe":
            result["poe_disabled"] = True
        else:
            match = re.fullmatch(r"speed\s+(\d+)\s+(half|full)-duplex", folded)
            if match:
                result["speed"], result["duplex"] = match.group(1), match.group(2)
    return result


def parse_poe_ports(output: str) -> dict[str, dict] | None:
    """``show poe port info all``: listed ports provide PoE; ``None`` for an unknown format."""
    rows = parse_dashed_table(output)
    if rows is None:
        return None
    ports = {}
    for row in rows:
        port = column(row, "intf", "interface", "port")
        if not _INTERFACE_RE.match(normalize_interface(port)):
            continue
        used = next((value for name, value in row.items() if "power" in name and "(w)" in name
                     and "max" not in name), "")
        maximum = next((value for name, value in row.items() if "max" in name and "power" in name), "")
        ports[normalize_interface(port)] = {
            "poe_supported": True,
            "poe_mode": None,
            "poe_status": column(row, "status").casefold() or None,
            "poe_used_watts": _number(used),
            "poe_max_watts": _number(maximum),
        }
    return ports


def parse_poe_budget(output: str) -> dict:
    """``show poe``: total, consumed and remaining power in watts (missing -> None)."""
    values = parse_key_values(output)
    maximum = used = None
    for key, value in values.items():
        folded = key.casefold()
        number = _number(value)
        if number is not None and "(mw)" in folded:
            number = number / 1000
        if "consum" in folded and used is None:
            used = number
        elif folded.startswith("total power") and maximum is None:
            maximum = number
    remaining = round(maximum - used, 1) if maximum is not None and used is not None else None
    return {"max_watts": maximum, "used_watts": used, "remaining_watts": remaining}


def parse_lldp_summary(output: str) -> list[dict]:
    """``show lldp remote-device all``: one row per remote device (ports without RemID are skipped)."""
    neighbors = []
    for row in parse_dashed_table(output) or []:
        local = re.sub(r"\s+", " ", column(row, "interface", "local interface", "intf"))
        if not _INTERFACE_RE.match(local.casefold()) or not column(row, "remid", "rem id"):
            continue
        system_name = column(row, "system name") or None
        chassis_id = column(row, "chassis id") or None
        neighbors.append(neighbor_row(
            "lldp",
            device_id=system_name or chassis_id,
            system_name=system_name,
            chassis_id=chassis_id,
            local_interface=local,
            remote_interface=column(row, "port id") or None,
        ))
    return neighbors


def parse_lldp_detail(output: str, local_interface: str) -> list[dict]:
    """``show lldp remote-device detail <p>``: one block per ``Remote Identifier``."""
    blocks = re.split(r"(?im)^\s*Remote Identifier\s*:", output or "")[1:]
    neighbors = []
    for block in blocks:
        def field(label: str, text: str = block) -> str | None:
            match = re.search(rf"(?im)^\s*{label}\s*:[ \t]*(.*?)\s*$", text)
            return match.group(1) or None if match else None

        addresses = []
        for address in re.findall(r"(?im)^\s*Address\s*:\s*(\S+)", block):
            try:
                addresses.append(str(ipaddress.IPv4Address(address)))
            except ipaddress.AddressValueError:
                continue
        ttl = field("Time To Live")
        system_name = field("System Name")
        chassis_id = field("Chassis ID")
        neighbors.append(neighbor_row(
            "lldp",
            device_id=system_name or chassis_id,
            system_name=system_name,
            chassis_id=chassis_id,
            platform=field("System Description"),
            capabilities=field("System Capabilities Enabled"),
            ip_addresses=addresses,
            local_interface=local_interface,
            remote_interface=field("Port ID"),
            holdtime_seconds=int(_number(ttl)) if _number(ttl) is not None else None,
        ))
    return neighbors


_MAC_TYPES = {"learned": "DYNAMIC", "dynamic": "DYNAMIC", "management": "SELF", "self": "SELF", "static": "STATIC",
              "config": "STATIC", "configured": "STATIC"}


def parse_mac_table(output: str) -> tuple[list[dict], dict]:
    """``show mac-addr-table``: VLAN ID, MAC Address, Interface, IfIndex, Status."""
    entries = []
    ignored = 0
    seen = set()
    for row in parse_dashed_table(output) or []:
        mac = clients.normalize_mac_address(column(row, "mac address", "mac"))
        vlan = column(row, "vlan id", "vlan")
        interface = re.sub(r"\s+", " ", column(row, "interface", "intf", "port"))
        if not mac or not vlan.isdigit() or not _INTERFACE_RE.match(interface.casefold()):
            ignored += 1
            continue
        status = column(row, "status", "type").casefold()
        entry = {"vlan": vlan, "mac": mac, "type": _MAC_TYPES.get(status, status.upper() or "UNKNOWN"),
                 "interface": interface}
        key = (vlan, mac, normalize_interface(interface))
        if key not in seen:
            seen.add(key)
            entries.append(entry)
    return entries, {"parsed_entries": len(entries), "unparsed_data_lines": 0, "ignored_data_lines": ignored}


def parse_arp(output: str) -> dict[str, str]:
    """IPv4/MAC pairs, recognized by value format (column order differs between firmware lines)."""
    bindings = {}
    for line in (output or "").splitlines():
        tokens = line.split()
        address = mac = None
        for token in tokens:
            if address is None:
                try:
                    address = ipaddress.IPv4Address(token)
                    continue
                except ipaddress.AddressValueError:
                    pass
            mac = mac or clients.normalize_mac_address(token)
        if address is not None and mac and not address.is_unspecified:
            bindings[mac] = str(address)
    return bindings


# --- Command construction ----------------------------------------------------------------


def speed_command(speed: str | None, duplex: str | None) -> str | None:
    if speed is None and duplex is None:
        return None
    if speed is None:
        raise InvalidInputError(t("Speed und Duplex müssen gemeinsam gesetzt werden."))
    speed = validate_choice(str(speed), SPEED_OPTIONS, "Speed")
    if duplex is not None:
        validate_choice(str(duplex), DUPLEX_OPTIONS, "Duplex")
    if speed == "auto":
        if duplex not in (None, "auto"):
            raise InvalidInputError(t("Bei Speed auto muss Duplex auto sein."))
        return "speed auto"
    if duplex not in ("half", "full"):
        raise InvalidInputError(t("Bei fester Geschwindigkeit muss Duplex half oder full sein."))
    if speed == "1000" and duplex == "half":
        raise InvalidInputError(t("1000 Mbit/s ist nur mit Vollduplex möglich."))
    return f"speed {speed} {duplex}-duplex"


def description_command(description: str) -> str:
    clean = sanitize_description(description, DESCRIPTION_MAX_LENGTH)
    if '"' in clean:
        raise InvalidInputError(t("Die Description darf keine Anführungszeichen enthalten."))
    return "no description" if clean == "" else f'description "{clean}"'


def _vlan_change(change: PortChange) -> bool:
    return any(value is not None for value in
               (change.mode, change.access_vlan, change.native_vlan, change.trunk_allowed_vlans))


def requested_vlans(change: PortChange) -> set[int]:
    vlans = {vlan for vlan in (change.access_vlan, change.native_vlan) if vlan is not None}
    if isinstance(change.trunk_allowed_vlans, tuple):
        vlans |= set(change.trunk_allowed_vlans)
    if change.voice_vlan:
        vlans.add(change.voice_vlan)
    return vlans


def target_voice_vlan(change: PortChange, detail: dict) -> int | None:
    """Voice VLAN the port has after the change (None = none)."""
    if change.voice_vlan is not None:
        return change.voice_vlan or None
    return detail.get("voice_vlan")


def voice_vlan_lines(change: PortChange, detail: dict) -> list[str]:
    """``voice vlan {vid}`` / ``no voice vlan`` inside the interface block.

    Classic syntax: the port also carries the voice VLAN tagged; a voice VLAN removed from an access
    port leaves the port's VLANs (when no other VLAN change already rebuilds the membership).
    """
    wanted = change.voice_vlan
    if wanted is None:
        return []
    current = detail.get("voice_vlan")
    classic = detail.get("vlan_syntax") != SYNTAX_SWITCHPORT
    members = set(detail.get("member_vlans") or ())
    tagged = set(detail.get("tagged_vlans") or ())
    data_vlan = change.access_vlan if change.access_vlan is not None else detail.get("access_vlan")
    lines = []
    if wanted:
        wanted = validate_vlan_id(wanted)
        if (change.mode or detail.get("mode")) != "trunk" and wanted == data_vlan:
            raise InvalidInputError(t(VOICE_EQUALS_ACCESS))
        if classic:
            if wanted not in members:
                lines.append(f"vlan participation include {wanted}")
            if wanted not in tagged:
                lines.append(f"vlan tagging {wanted}")
        lines.append(f"voice vlan {wanted}")
    elif current is not None:
        lines.append("no voice vlan")
    stale = current is not None and current != wanted
    if (stale and classic and not _vlan_change(change) and detail.get("mode") == "access"
            and current in members and current != data_vlan):
        lines.append(f"vlan participation exclude {current}")
    return lines


def switchport_vlan_lines(interface: str, change: PortChange, detail: dict, existing: set[int] | None) -> list[str]:
    lines = []
    target_mode = change.mode or detail.get("mode")
    if change.mode is not None:
        lines.append(f"switchport mode {change.mode}")
    if change.access_vlan is not None and target_mode != "trunk":
        lines.append(f"switchport access vlan {validate_vlan_id(change.access_vlan)}")
    if change.native_vlan is not None and target_mode != "access":
        lines.append(f"switchport trunk native vlan {validate_vlan_id(change.native_vlan)}")
    allowed = change.trunk_allowed_vlans
    if allowed == "all":
        lines.append("switchport trunk allowed vlan all")
    elif allowed == "none":
        current = (detail.get("trunk_allowed_vlan") or "").casefold()
        current_vlans = set(existing or ()) if current == "all" else _vlan_set(current) or set()
        lines.extend(vlan_list_lines("switchport trunk allowed vlan remove ", current_vlans))
    elif allowed is not None:
        lines.extend(vlan_list_lines("switchport trunk allowed vlan ", allowed, "switchport trunk allowed vlan add "))
    return lines


def classic_vlan_lines(
    interface: str, change: PortChange, detail: dict, existing: set[int] | None, keep: set[int] = frozenset(),
) -> list[str]:
    """Set-based ``vlan participation``/``vlan tagging``/``vlan pvid`` commands from the current membership.

    ``keep``: VLANs never removed (the port's voice VLAN).
    """
    if not _vlan_change(change):
        return []
    current_mode = detail.get("mode")
    target_mode = change.mode or current_mode
    members = set(detail.get("member_vlans") or ())
    tagged = set(detail.get("tagged_vlans") or ())
    pvid = detail.get("pvid")
    if target_mode == "access":
        vlan = change.access_vlan
        if vlan is None:
            vlan = detail.get("access_vlan") if current_mode == "access" else pvid
        if vlan is None:
            raise InvalidInputError(t("Für den Access-Modus wird ein Access-VLAN benötigt."))
        vlan = validate_vlan_id(vlan)
        lines = [f"vlan participation include {vlan}", f"vlan pvid {vlan}", f"no vlan tagging {vlan}"]
        lines += vlan_list_lines("vlan participation exclude ", members - {vlan} - keep)
        return lines
    if target_mode != "trunk":
        raise InvalidInputError(t(UNKNOWN_MODE_REASON, interface=interface))
    native = change.native_vlan
    if native is None:
        native = detail.get("native_vlan") if current_mode == "trunk" else pvid if pvid in members else None
    allowed = change.trunk_allowed_vlans
    if allowed is None:
        # Keep the current trunk VLANs (an old native becomes tagged). A new trunk carries all
        # existing VLANs, like 'switchport mode trunk' with its default allowed list.
        target_allowed = members if current_mode == "trunk" else set(existing or ())
    elif allowed == "all":
        target_allowed = set(existing or ())
    elif allowed == "none":
        target_allowed = set()
    else:
        target_allowed = set(allowed)
    target_members = target_allowed | ({native} if native is not None else set())
    target_tagged = target_allowed - {native}
    lines = []
    if native is not None:
        native = validate_vlan_id(native)
        lines += [f"vlan participation include {native}", f"vlan pvid {native}", f"no vlan tagging {native}"]
    lines += vlan_list_lines("vlan participation include ", target_tagged - members)
    lines += vlan_list_lines("vlan tagging ", target_tagged - tagged)
    lines += vlan_list_lines("vlan participation exclude ", members - target_members - keep)
    return lines


# --- Driver ------------------------------------------------------------------------------


class NetgearDriver(NetgearDeviceMixin, SshSwitchDriver):
    id = "netgear_prosafe"
    vendor = "Netgear"
    label = "Netgear M4250/M4300/M4350/M5300/M7100"
    netmiko_device_type = "netgear_prosafe"
    experimental = True
    features = FEATURES
    catalog = NETGEAR_CATALOG
    max_vlan_id = 4093  # CLI manual: VLAN IDs 2-4093
    config_error_markers = ERROR_MARKERS
    config_check = None
    # Restore and firmware: the switch downloads per SFTP, only from port 22.
    transfer_method = "sftp"
    sftp_port_22_only = True
    volatile_config_patterns = (r"^!System Up Time\b", r"^!Current SNTP Synchronized Time\b")
    max_lag_id = 64

    # --- Interface names -------------------------------------------------------------

    def validate_interface(self, name: str) -> str:
        text = re.sub(r"\s+", " ", name.strip()) if isinstance(name, str) else ""
        if not _INTERFACE_RE.match(text.casefold()):
            raise InvalidInputError(t("Ungültiger Interface-Name: {interface}", interface=str(name)[:40]))
        return text.casefold() if text.casefold().startswith("lag") else text

    def interface_key(self, name: str) -> str:
        return normalize_interface(name)

    def is_physical_interface(self, name: str) -> bool:
        return is_physical(name)

    def has_switchport(self, name: str) -> bool:
        return is_physical(name) or is_lag(name)

    # --- Session helpers -------------------------------------------------------------

    def _show(self, session: transport.SshSession, command: str) -> str:
        return ensure_output(transport.send_show(session.conn, command), command)

    def _optional(self, session: transport.SshSession, command: str) -> tuple[str, str]:
        """Optional read; status ok | timeout | skipped | empty | unsupported | error (warning added)."""
        if session.broken:
            return "", "skipped"
        try:
            output = transport.send_show(session.conn, command)
        except transport.SSH_TIMEOUT_ERRORS:
            logger.warning("Optional command %r timed out on switch id=%s", command, session.switch.get("id"))
            session.broken = True
            append_warning(session.warnings, t(
                "'{command}' lief in ein Zeitlimit; weitere Abfragen dieser Sitzung entfallen.", command=command,
            ))
            return "", "timeout"
        if not isinstance(output, str) or not output.strip():
            return "", "empty"
        if device_errors(output):
            return "", "unsupported" if is_unsupported_command(output) else "error"
        return output, "ok"

    def vlan_syntax(self, session: transport.SshSession, port: str) -> str:
        """Detect the VLAN syntax once per session with ``show interfaces switchport <port>``."""
        syntax = session.cache.get("netgear_syntax")
        if syntax:
            return syntax
        command = f"show interfaces switchport {port}"
        output = transport.send_show(session.conn, command)
        if not isinstance(output, str) or not output.strip():
            raise SwitchConnectionError(t("Der Switch hat für '{command}' keine Ausgabe geliefert.", command=command))
        if is_unsupported_command(output):
            syntax = SYNTAX_CLASSIC
        else:
            ensure_output(output, command)
            syntax = SYNTAX_SWITCHPORT
            session.cache[("switchport", normalize_interface(port))] = output
        logger.info("VLAN syntax of switch id=%s: %s", session.switch.get("id"), syntax)
        session.cache["netgear_syntax"] = syntax
        return syntax

    def _switchport_output(self, session: transport.SshSession, port: str) -> str:
        cached = session.cache.pop(("switchport", normalize_interface(port)), None)
        return cached if cached is not None else self._show(session, f"show interfaces switchport {port}")

    def _poe_ports(self, session: transport.SshSession) -> dict[str, dict] | None:
        if "poe_ports" in session.cache:
            return session.cache["poe_ports"]
        output, status = self._optional(session, "show poe port info all")
        ports = parse_poe_ports(output) if status == "ok" else None
        if ports is None:
            append_warning(session.warnings, t("PoE-Daten konnten nicht gelesen werden; PoE-Status unbekannt."))
        session.cache["poe_ports"] = ports
        return ports

    # --- Reads -----------------------------------------------------------------------

    def check_connection(self, switch: dict, credentials: dict) -> dict:
        try:
            with transport.open_ssh(switch, credentials, self.netmiko_device_type) as session:
                prompt = session.conn.find_prompt()
                model = None
                try:
                    model = parse_device_info(self._show(session, "show version"), None)["model"]
                except (*transport.SSH_ERRORS, SwitchConnectionError) as exc:
                    logger.warning("Model detection failed for switch id=%s (%s)", switch.get("id"), type(exc).__name__)
            return {"ok": True, "message": t("Verbindung erfolgreich, Prompt: {prompt}", prompt=prompt), "model": model}
        except NetmikoAuthenticationException:
            return {"ok": False, "message": t("Authentifizierung fehlgeschlagen (Benutzername/Passwort prüfen)"),
                    "model": None}
        except transport.SSH_TIMEOUT_ERRORS:
            return {"ok": False, "message": t("Zeitüberschreitung - Switch nicht erreichbar (IP/Port/Firewall prüfen)"),
                    "model": None}
        except Exception as exc:
            logger.warning("SSH connection test failed for switch id=%s (%s)", switch.get("id"), type(exc).__name__)
            return {"ok": False, "message": t("SSH-Verbindung fehlgeschlagen. Server-Log prüfen."), "model": None}

    def read_device_info(self, session: transport.SshSession) -> dict:
        version_out = self._show(session, "show version")
        sysinfo_out, _status = self._optional(session, "show sysinfo")
        return parse_device_info(version_out, sysinfo_out)

    def read_interfaces(self, session: transport.SshSession) -> list[dict]:
        """Cached per session; ``errdisabled_reason`` from ``show interfaces status err-disabled``
        (M5300/M7100 firmware 11.0 lacks the command: no reasons)."""
        if "interfaces" not in session.cache:
            status_out = self._show(session, "show interfaces status all")
            port_out, _status = self._optional(session, "show port all")
            rows = parse_interface_status(status_out, parse_port_admin(port_out))
            reasons = self._errdisabled(session)
            for row in rows:
                row["errdisabled_reason"] = reasons.get(normalize_interface(row["port"]))
            session.cache["interfaces"] = rows
        return [dict(row) for row in session.cache["interfaces"]]

    def _errdisabled(self, session: transport.SshSession) -> dict[str, str]:
        output, status = self._optional(session, "show interfaces status err-disabled")
        return l2.parse_errdisabled(output) if status == "ok" else {}

    def _running_text(self, session: transport.SshSession) -> str:
        """``show running-config`` once per session, read with at least the save timeout."""
        if "running_config" not in session.cache:
            conn = session.conn
            previous = getattr(conn, "read_timeout_override", None)
            conn.read_timeout_override = max(previous or 0, transport.SAVE_CONFIG_MIN_TIMEOUT_SECONDS)
            try:
                session.cache["running_config"] = self._show(session, "show running-config")
            finally:
                conn.read_timeout_override = previous
        return session.cache["running_config"]

    def _running_config(self, session: transport.SshSession) -> NetgearConfig:
        return parse_config(self._running_text(session))

    def _model(self, session: transport.SshSession) -> str | None:
        if "netgear_model" not in session.cache:
            session.cache["netgear_model"] = parse_device_info(self._show(session, "show version"), None)["model"]
        return session.cache["netgear_model"]

    def _family(self, session: transport.SshSession) -> str:
        """802.1X command family: M4250/M4350 authentication manager, otherwise legacy dot1x."""
        return FAMILY_AV if _AV_MODEL_RE.match(self._model(session) or "") else FAMILY_LEGACY

    def read_vlans(self, session: transport.SshSession) -> list[dict]:
        return parse_vlan_brief(self._show(session, "show vlan brief"))

    def _existing_vlans(self, session: transport.SshSession) -> set[int]:
        return {vlan["id"] for vlan in self.read_vlans(session)}

    def read_switchports(self, session: transport.SshSession, interfaces: list[dict]) -> dict[str, dict]:
        """Classic: one ``show running-config``; switchport syntax: per-port reads (max. 64, link-up first).

        Physical ports and LAGs are read; the syntax probe always uses a physical port.
        """
        physical = [item["port"] for item in interfaces if is_physical(item["port"])]
        ports = [item["port"] for item in interfaces if self.has_switchport(item["port"])]
        if not physical:
            return {}
        syntax = self.vlan_syntax(session, physical[0])
        if syntax == SYNTAX_CLASSIC:
            config = self._running_config(session)
            switchports = {}
            for port in ports:
                lines = config.block(port)
                switchports[normalize_interface(port)] = classic_switchport(
                    port, classic_membership(lines), parse_voice_vlan(lines),
                )
            return switchports
        ordered = sorted(interfaces, key=lambda item: item.get("link_state") != "up")
        selected = [item["port"] for item in ordered if self.has_switchport(item["port"])][:MAX_PORT_READS]
        if len(ports) > MAX_PORT_READS:
            append_warning(session.warnings, t(
                "Switchport-Details wurden nur für {count} Ports gelesen.", count=MAX_PORT_READS,
            ))
        switchports = {}
        for port in selected:
            if session.broken:
                break
            output, status = self._optional_switchport(session, port)
            if status == "ok":
                switchports[normalize_interface(port)] = parse_switchport(output, port)
        self._add_voice_vlans(session, switchports)
        return switchports

    def _add_voice_vlans(self, session: transport.SshSession, switchports: dict[str, dict]) -> None:
        """Switchport syntax: the voice VLAN is a line of the interface configuration."""
        if not switchports or session.broken:
            return
        try:
            config = self._running_config(session)
        except SwitchConnectionError:
            append_warning(session.warnings, t(
                "'{command}' ist fehlgeschlagen; die Daten können unvollständig sein.", command="show running-config",
            ))
            return
        for key, detail in switchports.items():
            detail["voice_vlan"] = parse_voice_vlan(config.block(key))

    def _optional_switchport(self, session: transport.SshSession, port: str) -> tuple[str, str]:
        cached = session.cache.pop(("switchport", normalize_interface(port)), None)
        if cached is not None:
            return cached, "ok"
        return self._optional(session, f"show interfaces switchport {port}")

    def read_poe_ports(self, session: transport.SshSession) -> dict[str, dict] | None:
        """PoE ports from ``show poe port info all``; the admin mode stays unknown (port config not read)."""
        return self._poe_ports(session)

    def read_poe_budget(self, session: transport.SshSession, device_info: dict) -> dict:
        summary = empty_poe_summary()
        profile = self.catalog.match(device_info.get("model"))
        output, status = self._optional(session, "show poe")
        if status == "ok":
            summary.update(parse_poe_budget(output))
        else:
            summary["warnings"].append(t("Das PoE-Gesamtbudget ist nicht verfügbar."))
        summary.update(_poe_standards(profile))
        if summary["supported"] is None and (summary["max_watts"] or 0) > 0:
            summary["supported"] = True
        return summary

    def _first_physical_port(self, session: transport.SshSession) -> str:
        """Syntax probe for logical interfaces (LAGs): the switch's first physical port."""
        if session.cache.get("netgear_syntax"):
            return ""
        port = next((row["port"] for row in self.read_interfaces(session) if is_physical(row["port"])), None)
        if port is None:
            raise SwitchConnectionError(t(
                "Die Ausgabe von '{command}' hat ein unbekanntes Format.", command="show interfaces status all",
            ))
        return port

    def _port_state(self, session: transport.SshSession, interface: str, *, with_poe: bool) -> dict:
        interface = self.validate_interface(interface)
        key = normalize_interface(interface)
        probe = interface if is_physical(interface) else self._first_physical_port(session)
        syntax = self.vlan_syntax(session, probe)
        running_out = self._show(session, f"show running-config interface {interface}")
        lines = parse_running_interfaces(running_out).get(key, [])
        if syntax == SYNTAX_SWITCHPORT:
            switchport = parse_switchport(self._switchport_output(session, interface), interface)
        else:
            membership = classic_membership(lines)
            pvid_out, status = self._optional(session, f"show vlan port {interface}")
            pvid = parse_vlan_port_pvid(pvid_out) if status == "ok" else None
            if pvid is not None:
                membership["pvid"] = pvid
            switchport = classic_switchport(interface, membership, parse_voice_vlan(lines))
        config = parse_interface_config(lines)
        poe_disabled = config.pop("poe_disabled")
        detail = {
            "interface": interface,
            **switchport,
            "voice_vlan": parse_voice_vlan(lines),
            **config,
            "warnings": session.warnings,
        }
        if with_poe:
            ports = self._poe_ports(session)
            if ports is None:
                poe = empty_poe_detail(None)
            elif key in ports:
                poe = {**ports[key], "poe_mode": "never" if poe_disabled else "auto"}
            else:
                poe = empty_poe_detail(False)
            detail.update(poe)
        return detail

    def read_port_detail(self, session: transport.SshSession, interface: str) -> dict:
        return self._port_state(session, interface, with_poe=True)

    def read_port_state(self, session: transport.SshSession, interface: str, change: PortChange) -> dict:
        return self._port_state(session, interface, with_poe=change.poe_mode is not None)

    def runtime_overrides(self, detail: dict) -> dict[str, str]:
        if detail.get("poe_supported") is False:
            return dict.fromkeys(("poe", "poe_mode", "poe_cycle"), NO_POE_PORT_REASON)
        return {}

    def read_neighbors(self, session: transport.SshSession) -> list[dict]:
        """LLDP summary plus ``show lldp remote-device detail <p>`` for at most 64 ports."""
        command = "show lldp remote-device all"
        try:
            summary = parse_lldp_summary(self._show(session, command))
        except SwitchConnectionError:
            raise SwitchConnectionError(t("Nachbarn konnten nicht gelesen werden.")) from None
        neighbors = []
        ports = list(dict.fromkeys(row["local_interface"] for row in summary))
        detailed = set()
        for port in ports[:MAX_PORT_READS]:
            output, status = self._optional(session, f"show lldp remote-device detail {port}")
            rows = parse_lldp_detail(output, port) if status == "ok" else []
            if rows:
                neighbors.extend(rows)
                detailed.add(port)
            elif status not in ("skipped", "timeout"):
                append_warning(session.warnings, t(
                    "'{command}' ist fehlgeschlagen; die Daten können unvollständig sein.",
                    command=f"show lldp remote-device detail {port}",
                ))
        neighbors.extend(row for row in summary if row["local_interface"] not in detailed)
        return neighbors

    def read_client_snapshot(self, session: transport.SshSession, switch: dict) -> dict:
        warnings = session.warnings
        source_status = {"arp": "not_requested", "lldp": "not_requested"}
        mac_entries, diagnostics = parse_mac_table(self._show(session, "show mac-addr-table"))
        interfaces = self.read_interfaces(session)

        arp_out, source_status["arp"] = self._optional(session, "show arp")
        if source_status["arp"] in ("unsupported", "error"):
            append_warning(warnings, t(
                "Die ARP-Tabelle ist auf diesem Switch nicht verfügbar (Routing deaktiviert?); IP-Adressen fehlen.",
            ))
        ip_bindings = parse_arp(arp_out)

        neighbors = []
        try:
            neighbors = self.read_neighbors(session)
            source_status["lldp"] = "ok"
        except SwitchConnectionError:
            source_status["lldp"] = "error"
            append_warning(warnings, t("Nachbarn konnten nicht gelesen werden."))

        candidates = clients.prioritize_client_candidates(
            clients.client_status_candidates(interfaces, self), mac_entries, self,
        )
        switchports = self.read_switchports(session, candidates) if candidates and not session.broken else {}
        return client_snapshot(
            switch,
            self,
            mac_entries=mac_entries,
            interfaces=interfaces,
            switchports=switchports,
            ip_bindings=ip_bindings,
            ip_sources=dict.fromkeys(ip_bindings, "arp"),
            neighbors=neighbors,
            source_status=source_status,
            mac_table_diagnostics=diagnostics,
            warnings=warnings,
            mac_table_command="show mac-addr-table",
        )

    # --- Writes ----------------------------------------------------------------------

    def validate_port_change(self, interface: str, change: PortChange) -> None:
        self.validate_interface(interface)
        if change.description is not None:
            description_command(change.description)
        for vlan in (change.access_vlan, change.native_vlan, change.voice_vlan or None):
            if vlan is not None:
                validate_vlan_id(vlan)
        speed_command(change.speed, change.duplex)
        if change.poe_mode is not None:
            validate_choice(change.poe_mode, POE_MODE_OPTIONS, "PoE")

    def port_change_commands(
        self, interface: str, change: PortChange, detail: dict, existing: set[int] | None,
    ) -> list[str]:
        lines = [f"interface {interface}"]
        if change.poe_mode is not None:
            lines.append("poe" if validate_choice(change.poe_mode, POE_MODE_OPTIONS, "PoE") == "auto" else "no poe")
        if change.description is not None:
            lines.append(description_command(change.description))
        if detail.get("vlan_syntax") == SYNTAX_SWITCHPORT:
            lines += switchport_vlan_lines(interface, change, detail, existing)
        else:
            voice = target_voice_vlan(change, detail)
            lines += classic_vlan_lines(interface, change, detail, existing, {voice} if voice else set())
        lines += voice_vlan_lines(change, detail)
        speed = speed_command(change.speed, change.duplex)
        if speed:
            lines.append(speed)
        if change.edge_port is not None:
            lines.append("spanning-tree edgeport" if change.edge_port else "no spanning-tree edgeport")
        if change.shutdown is True:
            lines.append("shutdown")
        elif change.shutdown is False:
            lines.append("no shutdown")
        lines.append("exit")
        return lines

    def plan_port_change(
        self, session: transport.SshSession, interface: str, change: PortChange, detail: dict,
    ) -> ChangePlan:
        interface = self.validate_interface(interface)
        if change.poe_mode is not None and detail.get("poe_supported") is not True:
            raise InvalidInputError(t(
                NO_POE_PORT_REASON if detail.get("poe_supported") is False else POE_UNCONFIRMED_REASON,
            ))
        requested = requested_vlans(change)
        needs_vlans = bool(requested) or change.trunk_allowed_vlans in ("all", "none") or change.mode == "trunk"
        existing = self._existing_vlans(session) if needs_vlans else None
        missing = sorted(requested - (existing or set()))
        if missing:
            raise InvalidInputError(t("VLAN {vlan} existiert auf dem Switch nicht.", vlan=format_vlan_list(tuple(missing))))
        lines = self.port_change_commands(interface, change, detail, existing)
        if change.voice_vlan and "voice vlan" not in self._running_config(session).top:
            lines.insert(0, "voice vlan")  # global enable
        return cli_plan(lines, message=t("Interface-Konfiguration übernommen (noch nicht dauerhaft gespeichert)"))

    def plan_port_state(self, session: transport.SshSession, interface: str, enabled: bool) -> ChangePlan:
        interface = self.validate_interface(interface)
        if enabled:
            message = t("Port {interface} wurde eingeschaltet (noch nicht dauerhaft gespeichert)", interface=interface)
        else:
            message = t("Port {interface} wurde ausgeschaltet (noch nicht dauerhaft gespeichert)", interface=interface)
        return cli_plan([f"interface {interface}", "no shutdown" if enabled else "shutdown", "exit"], message=message)

    # --- Port actions ---------------------------------------------

    def plan_port_bounce(self, session: transport.SshSession, interface: str) -> ChangePlan:
        """``shutdown``, pause, ``no shutdown`` as two configuration blocks."""
        interface = self.validate_interface(interface)
        down = (f"interface {interface}", "shutdown", "exit")
        up = (f"interface {interface}", "no shutdown", "exit")
        return ChangePlan(lines=down + up, steps=(CliLines(down), Pause(PORT_ACTION_PAUSE_SECONDS), CliLines(up)))

    def plan_poe_cycle(self, session: transport.SshSession, interface: str) -> ChangePlan:
        """Native ``poe reset`` (takes effect once, not saved); refused while PoE is switched off."""
        interface = self.validate_interface(interface)
        lines = parse_running_interfaces(self._show(session, f"show running-config interface {interface}")).get(
            normalize_interface(interface), [],
        )
        if parse_interface_config(lines)["poe_disabled"]:
            raise InvalidInputError(t(POE_CYCLE_OFF, interface=interface))
        return cli_plan([f"interface {interface}", "poe reset", "exit"])

    def plan_errdisable_recover(self, session: transport.SshSession, interface: str) -> ChangePlan:
        """Ports listed by ``show interfaces status err-disabled`` are re-enabled with ``no shutdown``."""
        interface = self.validate_interface(interface)
        if normalize_interface(interface) not in self._errdisabled(session):
            raise InvalidInputError(t(NOT_ERRDISABLED))
        return cli_plan([f"interface {interface}", "no shutdown", "exit"])

    # --- Configuration files, restore, reload -------------

    def read_running_config(self, session: transport.SshSession) -> str:
        return self._running_text(session)

    def read_startup_config(self, session: transport.SshSession) -> str:
        conn = session.conn
        previous = getattr(conn, "read_timeout_override", None)
        conn.read_timeout_override = max(previous or 0, transport.SAVE_CONFIG_MIN_TIMEOUT_SECONDS)
        try:
            return self._show(session, "show startup-config")
        finally:
            conn.read_timeout_override = previous

    def plan_reload(self, session: transport.SshSession) -> ChangePlan:
        """``reload``: "save them now? (y/n)" -> ``n``, every reset/reload question -> ``y``."""
        step = CliCommand(
            "reload", prompts=(SAVE_NO, YES_NO_YES), timeout=RELOAD_TIMEOUT_SECONDS, expect_disconnect=True,
        )
        return ChangePlan(lines=(step.command,), steps=(step,), reloads=True)

    def plan_config_restore(self, session: transport.SshSession, transfer: TransferLocation) -> ChangePlan:
        """``copy {sftp-url} nvram:startup-config`` ((y/n) -> y, password), then reload without saving."""
        from ...transfer import location_secrets

        if len(transfer.filename) > MAX_TRANSFER_FILENAME:
            raise InvalidInputError(t(
                "Der Dateiname ist für diese Plattform zu lang (höchstens {limit} Zeichen).",
                limit=MAX_TRANSFER_FILENAME,
            ))
        copy = CliCommand(
            f"copy {transfer.url} nvram:startup-config",
            prompts=(HOST_KEY_YES, (r"(?i)password:", transfer.password), YES_NO_YES),
            timeout=COPY_TIMEOUT_SECONDS,
            success=COPY_SUCCESS,
        )
        restore = ChangePlan(
            lines=(f"copy {transfer.display_url} nvram:startup-config",), steps=(copy,),
            secrets=location_secrets(transfer),
        )
        return combine_plans(restore, self.plan_reload(session))

    # --- Port security -----------------------------------------

    def read_port_security(self, session: transport.SshSession) -> dict:
        config = self._running_config(session)
        family = self._family(session)
        dot1x_enabled = "dot1x system-auth-control" in config.top
        ports = {
            normalize_interface(row["port"]): l2.parse_port(config.block(row["port"]), family, dot1x_enabled)
            for row in self.read_interfaces(session) if self.has_switchport(row["port"])
        }
        return {"global": l2.parse_global(config), "ports": ports}

    def plan_port_security(
        self, session: transport.SshSession, interface: str, change: SecurityChange, detail: dict,
    ) -> ChangePlan:
        interface = self.validate_interface(interface)
        before, lines = l2.port_security_lines(
            change, self._running_config(session), interface, self._family(session), detail.get("mode"),
        )
        if not lines and not before:
            return ChangePlan(lines=(), steps=())
        return cli_plan([*before, f"interface {interface}", *lines, "exit"] if lines else before)

    def plan_security_global(self, session: transport.SshSession, change: SecurityGlobalChange) -> ChangePlan:
        lines = l2.security_global_lines(change, self._running_config(session), self._existing_vlans(session))
        return cli_plan(lines) if lines else ChangePlan(lines=(), steps=())

    # --- Link aggregation ---------------------------------------

    def lag_interface_name(self, lag_id: int) -> str:
        return f"lag {int(lag_id)}"

    def _lag_configs(self, session: transport.SshSession) -> dict[int, dict]:
        default_static = bool(_STATIC_LAG_MODEL_RE.match(self._model(session) or ""))
        return l2.parse_lag_config(self._running_config(session), default_static)

    def read_lags(self, session: transport.SshSession) -> list[dict]:
        """Structure from the running configuration, link and member state from ``show port-channel lag N``."""
        lags = []
        for lag_id, entry in sorted(self._lag_configs(session).items()):
            output, status = self._optional(session, f"show port-channel lag {lag_id}")
            link, states = l2.parse_port_channel(output) if status == "ok" else (None, {})
            lags.append({
                "id": lag_id,
                "interface": self.lag_interface_name(lag_id),
                "mode": entry["mode"],
                "members": [{"interface": member, "state": states.get(member)} for member in entry["members"]],
                "status": link,
            })
        return lags

    def _lag_id(self, lag_id: int) -> int:
        lag_id = int(lag_id)
        if not 1 <= lag_id <= self.max_lag_id:
            raise InvalidInputError(t("LAG-ID außerhalb des gültigen Bereichs 1-{max}: {value}",
                                      max=self.max_lag_id, value=lag_id))
        return lag_id

    def _member_lines(self, lag_id: int, mode: str, members) -> list[str]:
        lines = []
        for member in members:
            lines += [f"interface {self.validate_interface(member)}", f"addport lag {lag_id}"]
            if mode != "static":
                lines.append("port lacpmode")
                lines.append("lacp actor admin state passive" if mode == "lacp_passive"
                             else "no lacp actor admin state passive")
            lines.append("exit")
        return lines

    def plan_lag_create(
        self, session: transport.SshSession, lag_id: int, mode: str, members: tuple[str, ...],
    ) -> ChangePlan:
        """AV (M4250/M4350) creates the LAG (``port-channel lag N chN``); M4300/M5300/M7100 LAG slots exist.
        The LAG type is set on ``interface lag N``; members join with ``addport`` and use the LAG's VLANs."""
        lag_id = self._lag_id(lag_id)
        if mode not in ("static", "lacp_active", "lacp_passive"):
            raise InvalidInputError(t(l2.UNSUPPORTED_VALUE, value=mode))
        if lag_id in self._lag_configs(session):
            raise InvalidInputError(t("LAG {lag} existiert bereits.", lag=lag_id))
        lines = [f"port-channel lag {lag_id} ch{lag_id}"] if self._family(session) == FAMILY_AV else []
        lines += [f"interface lag {lag_id}", "port-channel static" if mode == "static" else "no port-channel static",
                  "exit"]
        return cli_plan(lines + self._member_lines(lag_id, mode, members))

    def _lag(self, session: transport.SshSession, lag_id: int) -> dict:
        lag = self._lag_configs(session).get(self._lag_id(lag_id))
        if lag is None:
            raise InvalidInputError(t("LAG {lag} existiert auf dem Switch nicht.", lag=lag_id))
        return lag

    def plan_lag_update(
        self, session: transport.SshSession, lag_id: int, add: tuple[str, ...], remove: tuple[str, ...],
    ) -> ChangePlan:
        lag = self._lag(session, lag_id)
        lines = self._member_lines(lag["id"], lag["mode"], add)
        for member in remove:
            lines += [f"interface {self.validate_interface(member)}", f"deleteport lag {lag['id']}", "exit"]
        return cli_plan(lines) if lines else ChangePlan(lines=(), steps=())

    def plan_lag_delete(self, session: transport.SshSession, lag_id: int) -> ChangePlan:
        """``deleteport lag N`` removes every member; AV also removes the LAG (``no port-channel lag N``)."""
        lag = self._lag(session, lag_id)
        lines = [f"deleteport lag {lag['id']}"]
        if self._family(session) == FAMILY_AV:
            lines.append(f"no port-channel lag {lag['id']}")
        return cli_plan(lines)

    # --- Spanning tree ------------------------------------------

    def read_stp(self, session: transport.SshSession) -> dict:
        stp = l2.parse_stp_config(self._running_config(session))
        root_out, root_status = self._optional(session, "show spanning-tree")
        ports_out, ports_status = self._optional(session, "show spanning-tree mst port summary 0 active")
        return {
            "mode": stp["mode"],
            "priority": l2.stp_priorities(stp),
            "mst": l2.stp_mst(stp) if stp["mode"] == "mstp" else None,
            "roots": l2.parse_stp_root(root_out) if root_status == "ok" else [],
            "ports": l2.parse_stp_ports(parse_dashed_table(ports_out) if ports_status == "ok" else None, stp),
        }

    def plan_stp_mode(self, session: transport.SshSession, mode: str) -> ChangePlan:
        if mode not in l2.STP_MODES:
            raise InvalidInputError(t(l2.UNSUPPORTED_VALUE, value=mode))
        stp = l2.parse_stp_config(self._running_config(session))
        return cli_plan([*([] if stp["enabled"] else ["spanning-tree"]), f"spanning-tree mode {l2.STP_MODES[mode]}"])

    def plan_stp_priority(
        self, session: transport.SshSession, priority: int, vlans: tuple[int, ...] | None, instance: int | None,
    ) -> ChangePlan:
        """CIST (instance 0) and MST instance priorities; per-VLAN priorities (PVST) are not offered."""
        priority = int(priority)
        if not 0 <= priority <= 61440 or priority % 4096:
            raise InvalidInputError(t("Die Priorität muss ein Vielfaches von 4096 sein."))
        if vlans:
            raise InvalidInputError(t(l2.UNSUPPORTED_VALUE, value="vlan"))
        if instance is None:
            raise InvalidInputError(t("Bitte entweder VLANs oder eine Instanz angeben."))
        return cli_plan([f"spanning-tree mst priority {int(instance)} {priority}"])

    def plan_stp_mst(
        self, session: transport.SshSession, name: str, revision: int,
        instances: tuple[tuple[int, tuple[int, ...]], ...],
    ) -> ChangePlan:
        stp = l2.parse_stp_config(self._running_config(session))
        return cli_plan(l2.mst_lines(name, revision, instances, stp, self._existing_vlans(session)))

    def plan_stp_port(
        self, session: transport.SshSession, interface: str, instance_or_vlan: int | None, cost: int | None,
        priority: int | None,
    ) -> ChangePlan:
        """``spanning-tree mst {inst} cost|port-priority`` (instance 0 = CIST)."""
        interface = self.validate_interface(interface)
        instance = int(instance_or_vlan or 0)
        lines = []
        if cost is not None:
            if not 1 <= int(cost) <= 200000000:
                raise InvalidInputError(t(l2.UNSUPPORTED_VALUE, value=cost))
            lines.append(f"spanning-tree mst {instance} cost {int(cost)}")
        if priority is not None:
            if not 0 <= int(priority) <= 240 or int(priority) % 16:
                raise InvalidInputError(t("Die Port-Priorität muss ein Vielfaches von 16 sein."))
            lines.append(f"spanning-tree mst {instance} port-priority {int(priority)}")
        return cli_plan([f"interface {interface}", *lines, "exit"]) if lines else ChangePlan(lines=(), steps=())

    def execute_plan(self, session: transport.SshSession, plan: ChangePlan) -> WriteResult:
        """VLAN-database blocks are sent in Privileged EXEC and left explicitly; everything else uses the base."""
        if session.broken or not any(_is_vlan_database(step) for step in plan.steps):
            return super().execute_plan(session, plan)
        conn = session.conn
        outputs: list[str] = []
        try:
            for step in plan.steps:
                if _is_vlan_database(step):
                    try:
                        output, errors = send_configuration(conn, list(step.lines), enter=False, exit=False)
                    finally:
                        leave_vlan_database(conn)
                    outputs.append(output)
                    if errors:
                        return write_result(False, t("Der Switch hat einen Befehl abgelehnt: {errors}",
                                                     errors="; ".join(errors)), "\n".join(outputs))
                else:
                    result = super().execute_plan(session, replace(plan, steps=(step,)))
                    outputs.append(result["raw"])
                    if not result["ok"]:
                        return write_result(False, result["message"], "\n".join(outputs))
        finally:
            session.cache.clear()
        return write_result(True, plan.message or t("Änderung übernommen."), "\n".join(outputs))

    # --- Management path (uplink detection) ---------------------------------------------

    def read_management_path(self, session: transport.SshSession) -> dict:
        """``show ip management`` (12.x/AV), ``show network`` (upgraded 10.x), ``show serviceport`` (out-of-band)."""
        values = {}
        for command in ("show ip management", "show network"):
            output, status = self._optional(session, command)
            values = parse_key_values(output) if status == "ok" else {}
            if _ipv4(_lookup(values, "IP Address")):
                break
        address = _ipv4(_lookup(values, "IP Address"))
        interface = _lookup(values, "IPv4 Management Interface", "Management Interface") or None
        vlan = _leading_int(_lookup(values, "Management VLAN ID", "Management VLAN"))
        if interface:
            match = re.match(r"^vlan\s+(\d{1,4})$", interface.strip(), re.IGNORECASE)
            vlan = int(match.group(1)) if match else vlan
        elif vlan is not None:
            interface = f"vlan {vlan}"
        gateway = _ipv4(_lookup(values, "Default Gateway"))
        target = session.switch.get("ip")
        if target and address != target:
            output, status = self._optional(session, "show serviceport")
            service = parse_key_values(output) if status == "ok" else {}
            if _ipv4(_lookup(service, "IP Address")) == target:
                address, interface, vlan = target, "serviceport", None
                gateway = _ipv4(_lookup(service, "Default Gateway"))
        if gateway is None and interface != "serviceport":
            output, status = self._optional(session, "show ip route")
            match = re.search(r"Default gateway is\s+(\d{1,3}(?:\.\d{1,3}){3})", output) if status == "ok" else None
            gateway = _ipv4(match.group(1)) if match else None
        return {"gateway": gateway, "management_ip": address, "management_interface": interface,
                "management_vlan": vlan}

    def lookup_arp(self, session: transport.SshSession, ip: str) -> str | None:
        """Management ARP (``show arp switch``) first, then the routing ARP table (``show arp``)."""
        for command in ("show arp switch", "show arp"):
            output, status = self._optional(session, command)
            if status != "ok":
                continue
            mac = next((mac for mac, address in parse_arp(output).items() if address == ip), None)
            if mac:
                return clients.format_mac_address(mac)
        return None

    def lookup_mac_port(self, session: transport.SshSession, mac: str) -> str | None:
        wanted = clients.normalize_mac_address(mac)
        if not wanted:
            return None
        entries, _diagnostics = parse_mac_table(self._show(session, "show mac-addr-table"))
        return next((entry["interface"] for entry in entries if entry["mac"] == wanted and entry["type"] != "SELF"),
                    None)

    # --- VLAN administration -----------------------------------------------------------

    def read_vlan_constraints(self, session: transport.SshSession) -> vlanlib.VlanConstraints:
        try:
            rows = parse_dashed_table(self._show(session, "show interfaces status all"))
        except SwitchConnectionError:
            rows = None
        if rows is None:
            l3 = None
        else:
            l3 = frozenset(
                int(match.group(1))
                for match in (re.match(r"^vlan\s+(\d+)$", column(row, "port").strip(), re.IGNORECASE) for row in rows)
                if match
            )
        return vlanlib.VlanConstraints(protected={1: vlanlib.DEFAULT_REASON}, l3_interfaces=l3)

    @staticmethod
    def _vlan_plan(action: str, vlan_id: int, commands: list[str]) -> ChangePlan:
        lines = ("vlan database", *commands)
        return ChangePlan(
            lines=lines + ("exit",),
            steps=(CliLines(lines, enter=False, exit=False),),
            message=vlanlib.success_message(action, vlan_id),
        )

    def plan_vlan_create(self, session: transport.SshSession, vlan_id: int, name: str | None) -> ChangePlan:
        commands = [f"vlan {vlan_id}"] + ([f'vlan name {vlan_id} "{name}"'] if name else [])
        return self._vlan_plan("create", vlan_id, commands)

    def plan_vlan_rename(self, session: transport.SshSession, vlan_id: int, name: str) -> ChangePlan:
        return self._vlan_plan("rename", vlan_id, [f'vlan name {vlan_id} "{name}"'])

    def plan_vlan_delete(self, session: transport.SshSession, vlan_id: int) -> ChangePlan:
        return self._vlan_plan("delete", vlan_id, [f"no vlan {vlan_id}"])

    def plan_save_config(self, session: transport.SshSession) -> ChangePlan:
        """``write memory confirm``; success only with an explicit confirmation text."""
        return ChangePlan(
            lines=(SAVE_COMMAND,),
            steps=(CliCommand(SAVE_COMMAND, timeout=transport.SAVE_CONFIG_MIN_TIMEOUT_SECONDS,
                              success=SAVE_SUCCESS_RE.pattern),),
            persistent=True,
            message=t("Konfiguration gespeichert"),
        )


def _poe_standards(profile: ModelProfile | None) -> dict:
    if profile is None or profile.poe_standards is None:
        return {"supported": None, "standards": None, "standards_source": None}
    if profile.poe_standards == ():
        return {"supported": False, "standards": [], "standards_source": None}
    return {
        "supported": True,
        "standards": [STANDARD_LABELS[standard] for standard in STANDARD_LABELS if standard in profile.poe_standards],
        "standards_source": t("Herstellerangabe (nicht an Hardware verifiziert): {model}", model=profile.label),
    }


def send_configuration(conn, commands: list[str], *, enter: bool = True, exit: bool = True) -> tuple[str, list[str]]:
    return run_config_lines(conn, commands, ERROR_MARKERS, enter=enter, exit=exit)


def leave_vlan_database(conn) -> None:
    """Leave ``(Vlan)#``; never send ``exit`` elsewhere (in Privileged EXEC it would end the session)."""
    try:
        if "(vlan)" in conn.find_prompt().casefold():
            conn.send_config_set(
                ["exit"], enter_config_mode=False, exit_config_mode=False,
                read_timeout=config.settings.ssh_timeout_seconds,
            )
    finally:
        transport.reset_prompt(conn)
