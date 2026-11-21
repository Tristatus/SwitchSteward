"""Aruba AOS-CX driver (Netmiko ``aruba_aoscx``), experimental.

Commands and output formats follow the AOS-CX 10.x CLI reference and are not
validated on hardware (docs/switch-drivers.md). AOS-CX has no enable mode;
the port mode follows from the ``vlan access`` / ``vlan trunk`` lines.
"""

import ipaddress
import json
import logging
import re
from contextlib import contextmanager

from netmiko import NetmikoAuthenticationException

from ...i18n import t
from .. import transport
from .. import vlans as vlanlib
from ..clients import format_mac_address, is_unicast_client_mac, normalize_mac_address
from ..errors import InvalidInputError, SwitchConnectionError, append_warning
from ..features import VTP_CISCO_ONLY_REASON, supported, unsupported
from ..validation import format_vlan_list, parse_vlan_list, sanitize_description, validate_vlan_id, vlan_ranges
from . import aruba_aoscx_l2 as l2
from .aruba_aoscx_device import DEVICE_FEATURES, AosCxDeviceMixin
from .aruba_models import AOSCX_CATALOG
from .base import (
    PortChange,
    SshSwitchDriver,
    client_snapshot,
    empty_poe_detail,
    empty_poe_summary,
    empty_switchport_detail,
    neighbor_row,
)
from .cisco.poe import STANDARD_LABELS
from .cli import error_lines, parse_fixed_table, parse_key_values
from .plans import (
    ChangePlan,
    CliCommand,
    CliLines,
    Pause,
    SecurityChange,
    SecurityGlobalChange,
    TransferLocation,
    cli_plan,
)

logger = logging.getLogger("switchsteward.switches.aruba_aoscx")

SPEED_OPTIONS = ("auto", "10", "100", "1000")
DUPLEX_OPTIONS = ("auto", "half", "full")
POE_MODES = ("auto", "never")
_DESCRIPTION_MAX_LENGTH = 64
_VLAN_COMMAND_MAX_LENGTH = 200

POE_LIMIT_REASON = "AOS-CX bietet keine PoE-Leistungsgrenze je Port in Watt."
NO_POE_PORT_REASON = "Dieses Interface stellt kein PoE bereit."
NOT_ERRDISABLED = "Der Port ist nicht durch eine Schutzfunktion deaktiviert."
POE_CYCLE_OFF = "PoE ist an Port {interface} ausgeschaltet; ein PoE-Neustart ist nicht möglich."
VOICE_ACCESS_ONLY = "Ein Voice-VLAN ist nur an Access-Ports möglich."
VOICE_EQUALS_DATA = "Voice-VLAN und Access-VLAN müssen verschieden sein."

PORT_ACTION_PAUSE_SECONDS = 5
COPY_TIMEOUT_SECONDS = 600
RELOAD_TIMEOUT_SECONDS = 120
# Baseline checkpoint for "revert now" (≤ 32 chars, must not start with CPC).
ROLLBACK_CHECKPOINT = "SM_PRE_ROLLBACK"
# Prompts: the save question after a restore is answered "n" (startup config is kept).
SAVE_NO = (r"(?i)save the current configuration.*\(y/n\)", "n")
CONTINUE_YES = (r"(?i)continue \(y/n\)", "y")
HOST_KEY_YES = (r"(?i)\(yes/no\)", "yes")

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
    "vlan_voice": supported(),
    "vtp": unsupported(VTP_CISCO_ONLY_REASON),
    "edge_port": supported(),
    "speed": supported(SPEED_OPTIONS, requires=("duplex",)),
    "duplex": supported(DUPLEX_OPTIONS, requires=("speed",)),
    "port_state": supported(),
    "port_bounce": supported(),
    "poe": supported(),
    "poe_mode": supported(POE_MODES),
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
    "config_rollback": supported(),
    "management_path": supported(),
    "port_security": supported(("restrict", "shutdown")),
    "port_security_sticky": supported(),
    "dot1x": supported(("dot1x", "mab", "dot1x_mab")),
    "dot1x_host_mode": supported(("single", "multi_auth", "multi_host", "multi_domain")),
    "dot1x_fallback_vlans": supported(),
    "stp_guard": supported(("bpdu_guard", "root_guard", "loop_guard")),
    "storm_control": supported(("broadcast", "multicast", "unknown_unicast")),
    "storm_control_action": supported(("drop",)),
    "dhcp_snooping": supported(),
    "arp_inspection": supported(),
    "ip_source_guard": supported(),
    "lag": supported(("static", "lacp_active", "lacp_passive")),
    "stp": supported(("rapid_pvst", "mstp")),
    "stp_mst": supported(),
    "reload": supported(),
    **DEVICE_FEATURES,
}

# Rejected configuration lines; searched per output line, case-insensitive.
CONFIG_ERROR_MARKERS = (
    r"^%\s",
    r"Invalid input",
    r"Command incomplete",
    r"Ambiguous command",
    r"does not exist",
    r"not allowed",
    r"\bError\b",
)
# Show output may legitimately contain words such as "Error-control"; only line-leading markers count.
SHOW_ERROR_MARKERS = (r"^%", r"^Invalid input", r"^Command incomplete", r"^Ambiguous command", r"^Unknown command")

_PHYSICAL_RE = re.compile(r"^\d+/\d+/\d+$")
_LAG_RE = re.compile(r"^lag\s?(\d+)$", re.IGNORECASE)
_WATTS_RE = re.compile(r"(\d+(?:\.\d+)?)")


# --- Interface names -----------------------------------------------------------------------------


def interface_key(name: str) -> str:
    return re.sub(r"\s+", "", (name or "").strip().lower())


def is_interface_name(name: str) -> bool:
    key = interface_key(name)
    return bool(_PHYSICAL_RE.match(key) or _LAG_RE.match(key))


def config_interface_name(interface: str) -> str:
    """Name used in ``interface ...`` configuration lines (running-config shows ``lag 1``)."""
    match = _LAG_RE.match(interface)
    return f"lag {match.group(1)}" if match else interface


# --- Output checks -------------------------------------------------------------------------------


def ensure_show_output(output, command: str, *, allow_empty: bool = False) -> str:
    if not isinstance(output, str) or (not output.strip() and not allow_empty):
        logger.warning("AOS-CX returned no output for read command %r", command)
        raise SwitchConnectionError(t("Der Switch hat für '{command}' keine Ausgabe geliefert.", command=command))
    errors = error_lines(output, SHOW_ERROR_MARKERS)
    if errors:
        logger.warning("AOS-CX rejected read command %r: %s", command, "; ".join(errors))
        raise SwitchConnectionError(
            t("Der Switch hat den Lesebefehl '{command}' abgelehnt: {errors}", command=command, errors="; ".join(errors))
        )
    return output


def _config_check(line: str, _output: str, errors: list[str]) -> list[str]:
    """Ignore the echoed command itself (a description may contain e.g. the word 'error')."""
    return [error for error in errors if not error.endswith(line)]


def _unknown_format(command: str) -> SwitchConnectionError:
    return SwitchConnectionError(t("Die Ausgabe von '{command}' hat ein unbekanntes Format.", command=command))


# --- Parsers -------------------------------------------------------------------------------------


def _table(output: str, header_pattern: str, names: tuple[str, ...]) -> list[dict[str, str]] | None:
    """``parse_fixed_table`` with only those columns that the header line actually contains."""
    header = next(
        (line for line in (output or "").splitlines() if re.search(header_pattern, line, re.IGNORECASE)), None,
    )
    if header is None:
        return None
    present = tuple(
        name for name in names if re.search(rf"(?<!\S){re.escape(name)}(?!\S)", header, re.IGNORECASE)
    )
    return parse_fixed_table(output, header_pattern, present)


def parse_show_system(output: str) -> dict:
    values = parse_key_values(output)
    return {
        "hostname": values.get("Hostname") or None,
        "model": values.get("Product Name") or None,
        "serial_number": values.get("Chassis Serial Nbr") or values.get("Chassis Serial Number") or None,
        "uptime": values.get("Up Time") or None,
    }


def parse_show_version(output: str) -> str | None:
    return parse_key_values(output).get("Version") or None


def _vlan_int(text: str | None) -> int | None:
    value = (text or "").strip()
    return int(value) if value.isdigit() and 1 <= int(value) <= 4094 else None


def parse_interface_brief(output: str) -> list[dict]:
    """``show interface brief``: interface rows plus ``mode`` / ``native_vlan`` per port."""
    rows = _table(
        output,
        r"^\s*Port\s+Native\b",
        ("Port", "Native", "Mode", "Type", "Enabled", "Status", "Reason", "Speed", "Description"),
    )
    if rows is None or not rows or "Enabled" not in rows[0] or "Status" not in rows[0]:
        raise _unknown_format("show interface brief")
    interfaces = []
    for row in rows:
        port = row["Port"]
        if not is_interface_name(port):
            continue
        enabled = row["Enabled"].casefold()
        admin_state = {"yes": "enabled", "no": "disabled"}.get(enabled, "unknown")
        status = row["Status"].casefold()
        link_state = status if status in {"up", "down"} else "unknown"
        mode = (row.get("Mode") or "").casefold()
        native = _vlan_int(row.get("Native"))
        if mode in {"trunk", "routed"}:
            vlan = mode
        else:
            vlan = str(native) if native is not None else ""
        description = row.get("Description", "")
        disabled_by = re.search(r"(?i)\bdisabled by\s+(.+)", row.get("Reason") or "")
        interfaces.append({
            "port": port,
            "description": "" if description == "--" else description,
            "status": "disabled" if admin_state == "disabled" else (status or "unknown"),
            "vlan": vlan,
            "admin_state": admin_state,
            "link_state": link_state,
            # No unified err-disabled state; protection features report "Disabled by <feature>".
            "errdisabled_reason": disabled_by.group(1).strip() if disabled_by else None,
            "mode": mode if mode in {"access", "trunk", "routed"} else None,
            "native_vlan": native,
        })
    if not interfaces:
        raise _unknown_format("show interface brief")
    return interfaces


def parse_vlans(output: str) -> list[dict]:
    rows = _table(output, r"^\s*VLAN\s+Name\b", ("VLAN", "Name", "Status", "Reason", "Type", "Interfaces"))
    if rows is None:
        raise _unknown_format("show vlan")
    vlans = []
    for row in rows:
        vlan_id = _vlan_int(row["VLAN"])
        if vlan_id is None:
            continue
        status = (row.get("Status") or "").split()
        vlans.append({"id": vlan_id, "name": row.get("Name", ""), "status": status[0] if status else ""})
    return vlans


def parse_running_interfaces(output: str) -> dict[str, list[str]]:
    """Interface blocks of the running configuration: key -> stripped sub-lines."""
    blocks: dict[str, list[str]] = {}
    current = None
    for line in (output or "").splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            match = re.match(r"^interface\s+(.+?)\s*$", line)
            current = blocks.setdefault(interface_key(match.group(1)), []) if match else None
            continue
        if current is not None and line.strip() != "exit":
            current.append(line.strip())
    return blocks


def _line_value(lines: list[str], prefix: str) -> str | None:
    pattern = re.compile(rf"^{re.escape(prefix)}\s+(\S+)$")
    return next((match.group(1) for match in map(pattern.match, lines) if match), None)


def routing_state(lines: list[str]) -> bool | None:
    """True = ``routing`` configured, False = ``no routing``, None = not shown."""
    if "routing" in lines:
        return True
    if "no routing" in lines:
        return False
    return None


def configured_allowed_vlans(lines: list[str]):
    """``vlan trunk allowed`` lines: "all", the VLAN tuple (() = none) or None when unreadable."""
    items = [line.split(None, 3)[3] for line in lines if re.match(r"^vlan trunk allowed\s+\S", line)]
    if any(item.strip().casefold() == "all" for item in items):
        return "all"
    vlans: set[int] = set()
    for item in items:
        try:
            selection = parse_vlan_list(item.replace(" ", ""))
        except InvalidInputError:
            return None
        if isinstance(selection, str):
            return None
        vlans.update(selection)
    return tuple(sorted(vlans))


def voice_candidate(lines: list[str]) -> int | None:
    """The one tagged VLAN of a port with ``vlan trunk native D`` and allowed ``D,V`` (or ``V``), else None."""
    native = _vlan_int(_line_value(lines, "vlan trunk native"))
    allowed = configured_allowed_vlans(lines)
    if native is None or not isinstance(allowed, tuple):
        return None
    tagged = set(allowed) - {native}
    return tagged.pop() if len(tagged) == 1 else None


def switchport_detail(
    interface: str, lines: list[str], brief: dict | None = None, vlan_mode: str | None = None,
    voice_vlans: frozenset[int] | None = None,
) -> dict:
    """Switchport detail from the running config, the brief table (mode) and ``VLAN Mode`` of ``show interface``.

    A trunk carrying its native (data) VLAN untagged and exactly one tagged VLAN marked
    ``voice`` is reported as access port with ``voice_vlan``.
    """
    detail = empty_switchport_detail(interface)
    routing = routing_state(lines)
    access = _vlan_int(_line_value(lines, "vlan access"))
    native = _vlan_int(_line_value(lines, "vlan trunk native"))
    has_allowed = any(line.startswith("vlan trunk allowed") for line in lines)
    brief_mode = (brief or {}).get("mode")
    vlan_mode = (vlan_mode or "").casefold()
    if routing is True:
        mode = "routed"
    elif brief_mode:
        mode = brief_mode
    elif vlan_mode == "access":
        mode = "access"
    elif vlan_mode.startswith("native"):
        mode = "trunk"
    elif native is not None or has_allowed:
        mode = "trunk"
    elif access is not None or routing is False:
        mode = "access"
    else:
        return detail
    brief_native = (brief or {}).get("native_vlan")
    voice = voice_candidate(lines) if mode != "routed" else None
    if voice is not None and voice not in (voice_vlans or ()):
        voice = None
    if voice is not None:
        mode = "access"
    detail.update({
        "switchport_enabled": mode != "routed",
        "administrative_mode": mode,
        "operational_mode": mode,
        "mode": mode,
    })
    if voice is not None:
        detail.update(access_vlan=native, voice_vlan=voice)
    elif mode == "access":
        # Without a 'vlan access' line the port is in the default VLAN 1.
        detail["access_vlan"] = access or brief_native or 1
    elif mode == "trunk":
        detail["native_vlan"] = native or brief_native or 1
        # No 'vlan trunk allowed' line: the effective list is not derived here (stays None).
        allowed = configured_allowed_vlans(lines)
        if allowed == "all":
            detail["trunk_allowed_vlan"] = "all"
        elif allowed:
            detail["trunk_allowed_vlan"] = format_vlan_list(allowed)
    return detail


def configured_speed(lines: list[str]) -> tuple[str | None, str | None]:
    speed = next((line.split(None, 1)[1] for line in lines if re.match(r"^speed\s+\S", line)), None)
    if speed is None or speed.split()[0] == "auto":
        return "auto", "auto"
    match = re.fullmatch(r"(\d+)-(full|half)", speed)
    return (match.group(1), match.group(2)) if match else (None, None)


def _poe_columns(lines: list[str], header_index: int) -> list[tuple[int, str]]:
    header = lines[header_index]
    starts = [(match.start(), match.group(0)) for match in re.finditer(r"\S+", header)]
    follow = lines[header_index + 1] if header_index + 1 < len(lines) else ""
    if follow.strip() and not re.match(r"^[\s\-=]+$", follow) and not is_interface_name(follow.split()[0]):
        suffixes = [(match.start(), match.group(0)) for match in re.finditer(r"\S+", follow)]
        named = []
        for index, (start, name) in enumerate(starts):
            end = starts[index + 1][0] if index + 1 < len(starts) else 10**6
            extra = [word for position, word in suffixes if start <= position < end]
            named.append((start, " ".join([name, *extra])))
        starts = named
    return [(start, name.casefold()) for start, name in starts]


def _column_value(line: str, columns: list[tuple[int, str]], index: int) -> str:
    start = columns[index][0]
    end = columns[index + 1][0] if index + 1 < len(columns) else None
    return line[start:end].strip() if len(line) > start else ""


def _watts(text: str) -> float | None:
    match = _WATTS_RE.match(text)
    return float(match.group(1)) if match else None


def parse_poe_brief(output: str) -> dict[str, dict]:
    """``show power-over-ethernet brief``: PoE port rows located by the header columns."""
    lines = (output or "").splitlines()
    header_index = next(
        (index for index, line in enumerate(lines) if re.match(r"^\s*Port\s+\S", line) and "status" in line.casefold()),
        None,
    )
    if header_index is None:
        raise _unknown_format("show power-over-ethernet brief")
    columns = _poe_columns(lines, header_index)

    def column(predicate):
        return next((index for index, (_start, name) in enumerate(columns) if predicate(name)), None)

    enable_col = column(lambda name: "enable" in name)
    status_col = column(lambda name: "status" in name)
    alloc_col = column(lambda name: "power" in name and ("alloc" in name or "reserved" in name))
    actual_col = column(lambda name: "actual" in name or "drawn" in name)
    ports = {}
    for line in lines[header_index + 1 :]:
        tokens = line.split()
        if not tokens or not is_interface_name(tokens[0]):
            continue

        values = {
            index: _column_value(line, columns, index)
            for index in (enable_col, status_col, alloc_col, actual_col) if index is not None
        }
        detail = empty_poe_detail(True)
        enabled = values.get(enable_col, "").casefold()
        detail["poe_mode"] = {"yes": "auto", "enabled": "auto", "no": "never", "disabled": "never"}.get(enabled)
        detail["poe_status"] = values.get(status_col, "").casefold() or None
        detail["poe_max_watts"] = _watts(values.get(alloc_col, ""))
        detail["poe_used_watts"] = _watts(values.get(actual_col, ""))
        ports[interface_key(tokens[0])] = detail
    return ports


def parse_poe_budget(output: str) -> tuple[dict, list[dict]]:
    """System totals of ``show power-over-ethernet``; VSF stacks report one block per member."""
    fields = {
        "max_watts": r"Total Available Power",
        "used_watts": r"Total Power Drawn",
        "remaining_watts": r"Total Remaining Power",
    }
    found = {
        field: [float(value) for value in re.findall(rf"^\s*{label}\s*:\s*(\d+(?:\.\d+)?)", output or "", re.MULTILINE)]
        for field, label in fields.items()
    }
    members = len(found["max_watts"])
    modules = []
    if members > 1:
        for index in range(members):
            modules.append({
                "module": str(index + 1),
                **{field: values[index] if len(values) == members else None for field, values in found.items()},
            })
    budget = {
        field: round(sum(values), 3) if values and len(values) == members else None for field, values in found.items()
    }
    if budget["remaining_watts"] is None and budget["max_watts"] is not None and budget["used_watts"] is not None:
        budget["remaining_watts"] = round(budget["max_watts"] - budget["used_watts"], 3)
    return budget, modules


def _ip_addresses(values: list[str]) -> list[str]:
    addresses = []
    for value in values:
        try:
            address = str(ipaddress.ip_address(value.strip(",;()[]")))
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses


def parse_lldp_detail(output: str) -> list[dict]:
    """``show lldp neighbor-info detail``: one block per local port starting with ``Port : …``."""

    def field(block: str, label: str):
        match = re.search(rf"^[ \t]*{re.escape(label)}[ \t]*:[ \t]*(.*?)[ \t]*$", block, re.MULTILINE | re.IGNORECASE)
        return match.group(1) or None if match else None

    neighbors = []
    for block in re.split(r"(?=^\s*Port\s*:)", output or "", flags=re.MULTILINE):
        local = field(block, "Port")
        if not local or not is_interface_name(local):
            continue
        chassis_id = field(block, "Neighbor Chassis-ID")
        name = field(block, "Neighbor Chassis-Name")
        if not chassis_id and not name:
            continue
        ttl = field(block, "TTL")
        neighbors.append(neighbor_row(
            "lldp",
            device_id=name or chassis_id,
            system_name=name,
            chassis_id=chassis_id,
            platform=field(block, "Neighbor Chassis-Description"),
            capabilities=field(block, "Chassis Capabilities Enabled") or field(block, "Chassis Capabilities Available"),
            ip_addresses=_ip_addresses(
                re.findall(r"^[ \t]*Neighbor Management-Address[ \t]*:[ \t]*(\S+)", block, re.MULTILINE | re.IGNORECASE)
            ),
            local_interface=local,
            remote_interface=field(block, "Neighbor Port-ID"),
            holdtime_seconds=int(ttl) if ttl and ttl.isdigit() else None,
        ))
    return neighbors


def parse_lldp_table(output: str) -> list[dict]:
    """``show lldp neighbor-info`` summary table (fallback without detail fields)."""
    rows = _table(output, r"^\s*LOCAL-PORT\b", ("LOCAL-PORT", "CHASSIS-ID", "PORT-ID", "PORT-DESC", "TTL", "SYS-NAME"))
    if rows is None:
        raise _unknown_format("show lldp neighbor-info")
    neighbors = []
    for row in rows:
        local = row["LOCAL-PORT"]
        if not is_interface_name(local):
            continue
        name = row.get("SYS-NAME") or None
        chassis_id = row.get("CHASSIS-ID") or None
        ttl = row.get("TTL", "")
        neighbors.append(neighbor_row(
            "lldp",
            device_id=name or chassis_id,
            system_name=name,
            chassis_id=chassis_id,
            local_interface=local,
            remote_interface=row.get("PORT-ID") or None,
            holdtime_seconds=int(ttl) if ttl.isdigit() else None,
        ))
    return neighbors


def parse_mac_table(output: str) -> tuple[list[dict], dict]:
    """``show mac-address-table``: ``MAC VLAN Type Port`` rows."""
    entries = []
    seen = set()
    unparsed = ignored = 0
    for line in (output or "").splitlines():
        tokens = line.split()
        mac_index = next((index for index, token in enumerate(tokens) if normalize_mac_address(token)), None)
        if mac_index is None:
            continue
        mac = normalize_mac_address(tokens[mac_index])
        rest = tokens[mac_index + 1 :]
        if len(rest) >= 3 and _vlan_int(rest[0]) and is_interface_name(rest[-1]) \
                and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", rest[1]):
            entry = {"vlan": rest[0], "mac": mac, "type": rest[1].upper(), "interface": rest[-1]}
            key = (entry["vlan"], mac, entry["type"], interface_key(entry["interface"]))
            if key not in seen:
                seen.add(key)
                entries.append(entry)
        elif is_unicast_client_mac(mac) and any(_PHYSICAL_RE.match(token) for token in tokens):
            unparsed += 1
        else:
            ignored += 1
    return entries, {"parsed_entries": len(entries), "unparsed_data_lines": unparsed, "ignored_data_lines": ignored}


def parse_arp(output: str) -> dict[str, str]:
    """``show arp`` / ``show arp all-vrfs``: IPv4 address and MAC per line."""
    bindings = {}
    for line in (output or "").splitlines():
        tokens = line.split()
        if len(tokens) < 2:
            continue
        try:
            address = ipaddress.IPv4Address(tokens[0])
        except ValueError:
            continue
        mac = normalize_mac_address(tokens[1])
        if mac and not address.is_unspecified:
            bindings[mac] = str(address)
    return bindings


def ipv4_or_none(text: str | None) -> str | None:
    """Canonical IPv4 text or None (``0.0.0.0`` counts as not configured)."""
    try:
        address = ipaddress.IPv4Address((text or "").strip())
    except ValueError:
        return None
    return None if address.is_unspecified else str(address)


def parse_mgmt_interface(output: str) -> dict:
    """``show interface mgmt``: address (without prefix length) and default gateway of the management port."""
    values = parse_key_values(output)
    address = (values.get("IPv4 address/subnet-mask") or "").split("/", 1)[0]
    return {"ip": ipv4_or_none(address), "gateway": ipv4_or_none(values.get("Default gateway IPv4"))}


def parse_default_route(output: str) -> str | None:
    """``show ip route 0.0.0.0/0``: next hop of the first ``via`` line of the default route."""
    match = re.search(
        r"^\s*0\.0\.0\.0/0\b.*?^\s*via\s+(\d{1,3}(?:\.\d{1,3}){3})", output or "", re.MULTILINE | re.DOTALL,
    )
    return ipv4_or_none(match.group(1)) if match else None


def svi_with_address(blocks: dict[str, list[str]], address: str) -> int | None:
    """VLAN id of the ``interface vlan N`` block configured with ``ip address <address>/len``."""
    for key, lines in blocks.items():
        vlan = re.fullmatch(r"vlan(\d{1,4})", key)
        if vlan and any(re.fullmatch(rf"ip address {re.escape(address)}/\d{{1,2}}", line) for line in lines):
            return int(vlan.group(1))
    return None


def parse_inconsistent_ports(output: str | None) -> dict[str, str]:
    """``show spanning-tree inconsistent-ports``: interface key -> reason (``BPDU Guard``, ``Root Guard`` …)."""
    reasons = {}
    for line in (output or "").splitlines():
        match = re.match(r"^\s*\d+\s+(\S+)\s+(\S.*?)\s*$", line)
        if match and is_interface_name(match.group(1)):
            reasons[interface_key(match.group(1))] = match.group(2)
    return reasons


def parse_loop_protect(output: str | None) -> bool:
    """``show loop-protect <if>``: True when a loop was detected and the port is down."""
    values = parse_key_values(output or "")
    return (values.get("Loop detected") or "").casefold() == "yes" and \
        (values.get("Interface status") or "").casefold() == "down"


def normalize_json_config(output: str, command: str) -> str:
    """``show … json`` output as ``json.dumps(indent=2, sort_keys=True)`` (stable for diffs and hashes)."""
    start = (output or "").find("{")
    try:
        data, _end = json.JSONDecoder().raw_decode(output[start:]) if start >= 0 else (None, 0)
    except ValueError:
        data = None
    if not isinstance(data, dict):
        raise _unknown_format(command)
    return json.dumps(data, indent=2, sort_keys=True) + "\n"



def allowed_vlan_commands(current, target) -> list[str]:
    """Set-based change of the allowed list; ``current`` from ``configured_allowed_vlans``.

    ``vlan trunk allowed`` adds to the existing list, so only differences are sent.
    An ``all`` or unreadable list is replaced completely.
    """
    if target == "all":
        return [] if current == "all" else ["vlan trunk allowed all"]
    if target == "none":
        return [] if current == () else ["no vlan trunk allowed"]
    if not isinstance(current, tuple):
        return ["no vlan trunk allowed", *_chunked("vlan trunk allowed ", target)]
    added = tuple(sorted(set(target) - set(current)))
    removed = tuple(sorted(set(current) - set(target)))
    return [*_chunked("vlan trunk allowed ", added), *_chunked("no vlan trunk allowed ", removed)]


def _chunked(prefix: str, vlans: tuple[int, ...]) -> list[str]:
    commands = []
    chunk = ""
    for item in vlan_ranges(vlans):
        candidate = f"{chunk},{item}" if chunk else item
        if chunk and len(prefix) + len(candidate) > _VLAN_COMMAND_MAX_LENGTH:
            commands.append(prefix + chunk)
            chunk = item
        else:
            chunk = candidate
    if chunk:
        commands.append(prefix + chunk)
    return commands


def requested_vlans(change: PortChange) -> list[int]:
    vlans = {vlan for vlan in (change.access_vlan, change.native_vlan, change.voice_vlan) if vlan}
    if isinstance(change.trunk_allowed_vlans, tuple):
        vlans.update(change.trunk_allowed_vlans)
    return sorted(vlans)


# --- Driver --------------------------------------------------------------------------------------


class ArubaAosCxDriver(AosCxDeviceMixin, SshSwitchDriver):
    id = "aruba_aoscx"
    vendor = "Aruba"
    label = "Aruba AOS-CX"
    netmiko_device_type = "aruba_aoscx"
    experimental = True
    features = FEATURES
    catalog = AOSCX_CATALOG
    config_error_markers = CONFIG_ERROR_MARKERS
    config_check = _config_check

    @contextmanager
    def session(self, switch: dict, credentials: dict):
        # AOS-CX has no enable mode: administrators log in at '#'.
        with transport.ssh_session(switch, credentials, self.netmiko_device_type, privileged=False) as session:
            yield session

    # --- Interface names ---------------------------------------------------------------------

    def validate_interface(self, name: str) -> str:
        text = (name or "").strip()
        if _PHYSICAL_RE.match(text):
            return text
        match = _LAG_RE.match(text)
        if match:
            return f"lag{int(match.group(1))}"
        raise InvalidInputError(t("Ungültiger Interface-Name: {interface}", interface=repr(name)))

    def interface_key(self, name: str) -> str:
        return interface_key(name)

    def is_physical_interface(self, name: str) -> bool:
        return bool(_PHYSICAL_RE.match(interface_key(name)))

    # --- Session helpers ---------------------------------------------------------------------

    def _show(self, session, command: str, *, allow_empty: bool = False) -> str:
        return ensure_show_output(transport.send_show(session.conn, command), command, allow_empty=allow_empty)

    def _optional_show(self, session, command: str, warnings: list[str]) -> tuple[str | None, str]:
        """Read an optional source; a timeout ends all further reads of this session."""
        if session.broken:
            return None, "timeout"
        try:
            return self._show(session, command), "ok"
        except transport.SSH_TIMEOUT_ERRORS:
            logger.warning("Optional read %r timed out for switch id=%s", command, session.switch.get("id"))
            session.broken = True
            append_warning(
                warnings, t("'{command}' lief in ein Zeitlimit; weitere Abfragen dieser Sitzung entfallen.",
                            command=command),
            )
            return None, "timeout"
        except SwitchConnectionError:
            append_warning(
                warnings, t("'{command}' ist fehlgeschlagen; die Daten können unvollständig sein.", command=command),
            )
            return None, "error"

    # --- Reads -------------------------------------------------------------------------------

    def check_connection(self, switch: dict, credentials: dict) -> dict:
        try:
            with transport.open_ssh(switch, credentials, self.netmiko_device_type, privileged=False) as session:
                prompt = session.conn.find_prompt()
                model = None
                try:
                    model = parse_show_system(self._show(session, "show system"))["model"]
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

    def read_device_info(self, session) -> dict:
        info = parse_show_system(self._show(session, "show system"))
        version_out, _status = self._optional_show(session, "show version", session.warnings)
        info["software_version"] = parse_show_version(version_out) if version_out else None
        return info

    def read_interfaces(self, session) -> list[dict]:
        rows = parse_interface_brief(self._show(session, "show interface brief"))
        session.cache["brief"] = {
            interface_key(row["port"]): {"mode": row.pop("mode"), "native_vlan": row.pop("native_vlan")} for row in rows
        }
        # BPDU/root/loop guard block ports without "Disabled by" in the brief table.
        guards = parse_inconsistent_ports(self._optional_show(session, "show spanning-tree inconsistent-ports", [])[0])
        for row in rows:
            if row["errdisabled_reason"] is None:
                row["errdisabled_reason"] = guards.get(interface_key(row["port"]))
        return rows

    def read_vlans(self, session) -> list[dict]:
        """VLAN rows with ``voice`` (VLAN marked ``voice``; None without running configuration)."""
        vlans = parse_vlans(self._show(session, "show vlan"))
        marked = self._voice_vlans(session)
        for vlan in vlans:
            vlan["voice"] = vlan["id"] in marked if marked is not None else None
        return vlans

    def _running_text(self, session) -> str | None:
        """Full running configuration (cached per session; None when unreadable, with a warning)."""
        if "running_text" not in session.cache:
            output, _status = self._optional_show(session, "show running-config", session.warnings)
            session.cache["running_text"] = output
        return session.cache["running_text"]

    def _sections(self, session, *, required: bool = False) -> list:
        text = self._running_text(session)
        if text is None and required:
            raise SwitchConnectionError(t("Die Ausgabe von '{command}' hat ein unbekanntes Format.",
                                          command="show running-config"))
        return l2.config_sections(text or "")

    def _voice_vlans(self, session) -> frozenset[int] | None:
        text = self._running_text(session)
        return l2.voice_vlans(l2.config_sections(text)) if text is not None else None

    def _running_blocks(self, session) -> dict[str, list[str]] | None:
        if "running" not in session.cache:
            output = self._running_text(session)
            session.cache["running"] = parse_running_interfaces(output) if output is not None else None
        return session.cache["running"]

    def read_switchports(self, session, interfaces: list[dict]) -> dict[str, dict]:
        blocks = self._running_blocks(session) or {}
        brief = session.cache.get("brief") or {}
        voice = self._voice_vlans(session) if blocks else None
        switchports = {}
        for interface in interfaces:
            key = interface_key(interface["port"])
            switchports[key] = switchport_detail(interface["port"], blocks.get(key, []), brief.get(key), voice_vlans=voice)
        return switchports

    def _read_poe_ports(self, session, warnings: list[str]) -> dict[str, dict] | None:
        output, status = self._optional_show(session, "show power-over-ethernet brief", [])
        if status != "ok":
            append_warning(warnings, t("PoE-Daten konnten nicht gelesen werden; PoE-Status unbekannt."))
            return None
        try:
            return parse_poe_brief(output)
        except SwitchConnectionError:
            append_warning(warnings, t("PoE-Daten konnten nicht gelesen werden; PoE-Status unbekannt."))
            return None

    def read_poe_ports(self, session) -> dict[str, dict] | None:
        ports = self._read_poe_ports(session, session.warnings)
        blocks = session.cache.get("running")
        if ports and blocks:
            # The running config is authoritative for the administrative PoE setting.
            for key, detail in ports.items():
                if key in blocks:
                    detail["poe_mode"] = "never" if "no power-over-ethernet" in blocks[key] else "auto"
        return ports

    def read_poe_budget(self, session, device_info: dict) -> dict:
        summary = empty_poe_summary()
        output, _status = self._optional_show(session, "show power-over-ethernet", [])
        if output is not None:
            budget, modules = parse_poe_budget(output)
            summary.update(budget)
            summary["modules"] = modules
        if summary["max_watts"] is None:
            summary["warnings"].append(t("Das PoE-Gesamtbudget ist nicht verfügbar."))
        elif summary["max_watts"] > 0:
            summary["supported"] = True
        profile = self.catalog.match(device_info.get("model"))
        if profile is not None and profile.poe_standards is not None:
            summary["standards"] = [STANDARD_LABELS[standard] for standard in profile.poe_standards]
            summary["standards_source"] = t("Herstellerangabe (nicht an Hardware verifiziert): {model}",
                                            model=device_info.get("model"))
            if not profile.poe_standards and summary["supported"] is None:
                summary["supported"] = False
        return summary

    def _port_state(self, session, interface: str) -> tuple[dict, list[str]]:
        interface = self.validate_interface(interface)
        warnings = session.warnings
        command = f"show running-config interface {interface}"
        blocks = parse_running_interfaces(self._show(session, command, allow_empty=True))
        lines = blocks.get(interface_key(interface), [])
        if blocks and interface_key(interface) not in blocks:
            raise SwitchConnectionError(t("Die Ausgabe von '{command}' hat ein unbekanntes Format.", command=command))
        interface_out, _status = self._optional_show(session, f"show interface {interface}", warnings)
        interface_out = interface_out or ""
        vlan_mode = re.search(r"^\s*VLAN Mode\s*:\s*(\S+)", interface_out, re.MULTILINE | re.IGNORECASE)
        poe_ports = self._read_poe_ports(session, warnings)
        poe_detail = dict(
            poe_ports.get(interface_key(interface), empty_poe_detail(False)) if poe_ports is not None
            else empty_poe_detail(None)
        )
        if poe_detail["poe_supported"]:
            poe_detail["poe_mode"] = "never" if "no power-over-ethernet" in lines else "auto"

        admin = re.search(r"^\s*Admin state is (up|down)", interface_out, re.MULTILINE | re.IGNORECASE)
        if admin:
            shutdown = admin.group(1).casefold() == "down"
        elif "shutdown" in lines:
            shutdown = True
        elif "no shutdown" in lines:
            shutdown = False
        else:
            shutdown = None
        speed, duplex = configured_speed(lines)
        description = next((line.split(None, 1)[1] for line in lines if line.startswith("description ")), None)
        voice = self._voice_vlans(session) if voice_candidate(lines) is not None else None
        disabled_by = re.search(r"^\s*State information:\s*Disabled by\s+(.+?)\s*$", interface_out,
                                re.MULTILINE | re.IGNORECASE)
        detail = {
            "interface": interface,
            "description": description,
            **switchport_detail(interface, lines, vlan_mode=vlan_mode.group(1) if vlan_mode else None,
                                voice_vlans=voice),
            "errdisabled_reason": disabled_by.group(1) if disabled_by else None,
            "portfast": "spanning-tree port-type admin-edge" in lines,
            "speed": speed,
            "duplex": duplex,
            "shutdown": shutdown,
            **poe_detail,
            "poe_standard_options": [],
            "poe_standards_reason": None,
            "poe_configured_max_watts": None,
            "port_options": {},
            "warnings": warnings,
        }
        return detail, lines

    def read_port_detail(self, session, interface: str) -> dict:
        detail, _lines = self._port_state(session, interface)
        return detail

    def runtime_overrides(self, detail: dict) -> dict[str, str]:
        if detail.get("poe_supported") is False:
            return {"poe": NO_POE_PORT_REASON, "poe_mode": NO_POE_PORT_REASON}
        return {}

    def read_neighbors(self, session) -> list[dict]:
        failures: list[str] = []
        output, _status = self._optional_show(session, "show lldp neighbor-info detail", failures)
        if output is not None:
            return parse_lldp_detail(output)
        output, _status = self._optional_show(session, "show lldp neighbor-info", failures)
        if output is not None:
            try:
                return parse_lldp_table(output)
            except SwitchConnectionError as exc:
                failures.append(str(exc))
        raise SwitchConnectionError(t("Nachbarn konnten nicht gelesen werden.") + " " + " ".join(failures))

    def read_client_snapshot(self, session, switch: dict) -> dict:
        warnings = session.warnings
        mac_entries, diagnostics = parse_mac_table(self._show(session, "show mac-address-table"))
        if diagnostics["unparsed_data_lines"]:
            append_warning(warnings, t(
                "Mindestens eine relevante Zeile der MAC-Tabelle hatte ein unbekanntes Format; "
                "die Client-Erkennung kann unvollständig sein."
            ))
        interfaces = self.read_interfaces(session)
        switchports = self.read_switchports(session, interfaces)
        arp_warnings: list[str] = []
        arp_out, arp_status = self._optional_show(session, "show arp all-vrfs", arp_warnings)
        if arp_status == "error":
            arp_warnings.clear()
            arp_out, arp_status = self._optional_show(session, "show arp", arp_warnings)
        for warning in arp_warnings:
            append_warning(warnings, warning)
        ip_bindings = parse_arp(arp_out)
        lldp_out, lldp_status = self._optional_show(session, "show lldp neighbor-info detail", warnings)
        return client_snapshot(
            switch,
            self,
            mac_entries=mac_entries,
            interfaces=interfaces,
            switchports=switchports,
            ip_bindings=ip_bindings,
            ip_sources=dict.fromkeys(ip_bindings, "arp"),
            neighbors=parse_lldp_detail(lldp_out),
            source_status={"arp": arp_status, "lldp": lldp_status},
            mac_table_diagnostics=diagnostics,
            warnings=warnings,
        )

    # --- Writes ------------------------------------------------------------------------------

    def validate_port_change(self, interface: str, change: PortChange) -> None:
        self.validate_interface(interface)
        if change.description is not None:
            sanitize_description(change.description, _DESCRIPTION_MAX_LENGTH)
        for vlan in (change.access_vlan, change.native_vlan, change.voice_vlan or None):
            if vlan is not None:
                validate_vlan_id(vlan)
        if change.poe_mode is not None and change.poe_mode not in POE_MODES:
            raise InvalidInputError(t("Der Wert {value} wird von diesem Gerät nicht unterstützt.", value=change.poe_mode))
        speed, duplex = change.speed, change.duplex
        if speed is None and duplex is None:
            return
        if speed not in SPEED_OPTIONS or (duplex is not None and duplex not in DUPLEX_OPTIONS):
            raise InvalidInputError(t("Der Wert {value} wird von diesem Gerät nicht unterstützt.",
                                      value=speed if speed not in SPEED_OPTIONS else duplex))
        if speed == "auto":
            if duplex not in (None, "auto"):
                raise InvalidInputError(t("Bei Speed auto muss Duplex auto sein."))
            return
        if duplex not in ("half", "full"):
            raise InvalidInputError(t("Bei fester Geschwindigkeit muss Duplex half oder full sein."))
        if speed == "1000" and duplex == "half":
            raise InvalidInputError(t("1000 Mbit/s ist nur mit Vollduplex möglich."))

    def read_port_state(self, session, interface: str, change: PortChange) -> dict:
        """Current port state plus the existing VLANs (checked before the first write command)."""
        detail, lines = self._port_state(session, interface)
        detail["config_lines"] = lines
        if requested_vlans(change):
            detail["existing_vlans"] = {vlan["id"] for vlan in self.read_vlans(session)}
        return detail

    def port_change_commands(self, interface: str, change: PortChange, detail: dict) -> list[str]:
        lines = detail.get("config_lines") or []
        current_mode = detail.get("mode")
        target = change.mode or current_mode
        commands = [f"interface {config_interface_name(interface)}"]
        if change.description is not None:
            clean = sanitize_description(change.description, _DESCRIPTION_MAX_LENGTH)
            commands.append("no description" if clean == "" else f"description {clean}")
        if change.poe_mode is not None:
            commands.append("power-over-ethernet" if change.poe_mode == "auto" else "no power-over-ethernet")

        vlan_commands = []
        vlan_change = any(
            value is not None
            for value in (change.mode, change.access_vlan, change.native_vlan, change.trunk_allowed_vlans,
                          change.voice_vlan)
        )
        mode_changes = change.mode is not None and change.mode != current_mode
        current_voice = detail.get("voice_vlan")
        voice = current_voice if change.voice_vlan is None else (change.voice_vlan or None)
        if vlan_change and target == "access":
            if mode_changes and change.access_vlan is None:
                raise InvalidInputError(t("Für den Wechsel in den Access-Modus ist ein Access VLAN erforderlich."))
            data = change.access_vlan if change.access_vlan is not None else detail.get("access_vlan")
            if voice:
                # Data VLAN untagged (native), voice VLAN tagged.
                if data is None:
                    raise InvalidInputError(t("Für den Wechsel in den Access-Modus ist ein Access VLAN erforderlich."))
                if voice == data:
                    raise InvalidInputError(t(VOICE_EQUALS_DATA))
                if _vlan_int(_line_value(lines, "vlan trunk native")) != data:
                    vlan_commands.append(f"vlan trunk native {validate_vlan_id(data)}")
                vlan_commands.extend(allowed_vlan_commands(
                    configured_allowed_vlans(lines), tuple(sorted({data, validate_vlan_id(voice)})),
                ))
            else:
                if any(line.startswith("vlan trunk native") for line in lines):
                    vlan_commands.append("no vlan trunk native")
                if any(line.startswith("vlan trunk allowed") for line in lines):
                    vlan_commands.append("no vlan trunk allowed")
                if change.access_vlan is not None or (current_voice and data is not None):
                    vlan_commands.append(f"vlan access {validate_vlan_id(data)}")
        elif vlan_change and target == "trunk":
            if change.voice_vlan:
                raise InvalidInputError(t(VOICE_ACCESS_ONLY))
            if mode_changes and change.native_vlan is None:
                raise InvalidInputError(t("Für den Wechsel in den Trunk-Modus ist ein Native VLAN erforderlich."))
            if change.native_vlan is not None:
                vlan_commands.append(f"vlan trunk native {validate_vlan_id(change.native_vlan)}")
            if change.trunk_allowed_vlans is not None:
                vlan_commands.extend(allowed_vlan_commands(configured_allowed_vlans(lines), change.trunk_allowed_vlans))
        elif vlan_change:
            raise InvalidInputError(t("Der Portmodus ist unbekannt; bitte Access oder Trunk ausdrücklich wählen."))
        if vlan_commands and routing_state(lines) is not False:
            # Routed ports (default on 8xxx) accept VLAN commands only after 'no routing'.
            vlan_commands.insert(0, "no routing")
        commands.extend(vlan_commands)

        if change.edge_port is not None:
            commands.append("spanning-tree port-type admin-edge" if change.edge_port else "no spanning-tree port-type")
        if change.speed is not None:
            commands.append("speed auto" if change.speed == "auto" else f"speed {change.speed}-{change.duplex}")
        if change.shutdown is True:
            commands.append("shutdown")
        elif change.shutdown is False:
            commands.append("no shutdown")
        return commands

    def plan_port_change(self, session, interface: str, change: PortChange, detail: dict) -> ChangePlan:
        interface = self.validate_interface(interface)
        self.validate_port_change(interface, change)
        vlans = requested_vlans(change)
        if vlans:
            existing = detail.get("existing_vlans")
            if existing is None:
                existing = {vlan["id"] for vlan in self.read_vlans(session)}
            missing = [vlan for vlan in vlans if vlan not in existing]
            if missing:
                raise InvalidInputError(t("VLAN {vlan} existiert auf dem Switch nicht.", vlan=missing[0]))
        prefix = []
        if change.voice_vlan:
            # The voice VLAN must be marked "voice" (LLDP-MED advertises it to phones).
            marked = self._voice_vlans(session)
            if marked is None or change.voice_vlan not in marked:
                prefix = [f"vlan {change.voice_vlan}", "voice", "exit"]
        return cli_plan(
            [*prefix, *self.port_change_commands(interface, change, detail)],
            message=t("Interface-Konfiguration übernommen (noch nicht dauerhaft gespeichert)"),
        )

    def plan_port_state(self, session, interface: str, enabled: bool) -> ChangePlan:
        interface = self.validate_interface(interface)
        message = (
            "Port {interface} wurde eingeschaltet (noch nicht dauerhaft gespeichert)" if enabled
            else "Port {interface} wurde ausgeschaltet (noch nicht dauerhaft gespeichert)"
        )
        return cli_plan(
            [f"interface {config_interface_name(interface)}", "no shutdown" if enabled else "shutdown"],
            message=t(message, interface=interface),
        )

    # --- Port actions -----------------------------------------------

    def _interface_lines(self, session, interface: str) -> list[str]:
        command = f"show running-config interface {interface}"
        blocks = parse_running_interfaces(self._show(session, command, allow_empty=True))
        if blocks and interface_key(interface) not in blocks:
            raise _unknown_format(command)
        return blocks.get(interface_key(interface), [])

    def plan_port_bounce(self, session, interface: str) -> ChangePlan:
        """``shutdown``, pause, ``no shutdown`` as two separate configuration blocks."""
        interface = self.validate_interface(interface)
        down = (f"interface {config_interface_name(interface)}", "shutdown")
        up = (f"interface {config_interface_name(interface)}", "no shutdown")
        return ChangePlan(lines=down + up, steps=(CliLines(down), Pause(PORT_ACTION_PAUSE_SECONDS), CliLines(up)))

    def plan_poe_cycle(self, session, interface: str) -> ChangePlan:
        """No native power cycle: toggle ``power-over-ethernet`` (priority/allocation lines stay untouched)."""
        interface = self.validate_interface(interface)
        if "no power-over-ethernet" in self._interface_lines(session, interface):
            raise InvalidInputError(t(POE_CYCLE_OFF, interface=interface))
        off = (f"interface {interface}", "no power-over-ethernet")
        on = (f"interface {interface}", "power-over-ethernet")
        return ChangePlan(lines=off + on, steps=(CliLines(off), Pause(PORT_ACTION_PAUSE_SECONDS), CliLines(on)))

    def plan_errdisable_recover(self, session, interface: str) -> ChangePlan:
        """"Disabled by …", an STP guard or loop-protect must have blocked the port; recovery = shutdown/no shutdown."""
        interface = self.validate_interface(interface)
        state, _status = self._optional_show(session, f"show interface {interface}", [])
        disabled = re.search(r"^\s*State information:\s*Disabled by\s+\S", state or "", re.MULTILINE | re.IGNORECASE)
        if not disabled:
            inconsistent, _status = self._optional_show(session, "show spanning-tree inconsistent-ports", [])
            disabled = interface_key(interface) in parse_inconsistent_ports(inconsistent)
        if not disabled:
            loop, _status = self._optional_show(session, f"show loop-protect {interface}", [])
            disabled = parse_loop_protect(loop)
        if not disabled:
            raise InvalidInputError(t(NOT_ERRDISABLED))
        return cli_plan([f"interface {config_interface_name(interface)}", "shutdown", "no shutdown"])

    # --- Management path ----------------------------------------------------------

    def read_management_path(self, session) -> dict:
        """Out-of-band ``mgmt`` port when it carries the session address, else the SVI with that address."""
        target = ipv4_or_none(session.switch.get("ip"))
        path = {"gateway": None, "management_ip": target, "management_interface": None, "management_vlan": None}
        # 6000/6100 have no management port: the read fails silently.
        mgmt_out, _status = self._optional_show(session, "show interface mgmt", [])
        mgmt = parse_mgmt_interface(mgmt_out or "")
        if target is not None and mgmt["ip"] == target:
            path.update(gateway=mgmt["gateway"], management_interface="mgmt")
            return path
        vlan = svi_with_address(self._running_blocks(session) or {}, target) if target else None
        if vlan is not None:
            path.update(management_interface=f"vlan{vlan}", management_vlan=vlan)
        route_out, _status = self._optional_show(session, "show ip route 0.0.0.0/0", session.warnings)
        path["gateway"] = parse_default_route(route_out or "")
        return path

    def lookup_arp(self, session, ip: str) -> str | None:
        ip = str(ipaddress.IPv4Address(ip))
        try:
            output = self._show(session, f"show arp all-vrfs | include {ip}", allow_empty=True)
        except SwitchConnectionError:
            output = self._show(session, f"show arp | include {ip}", allow_empty=True)
        mac = next((mac for mac, address in parse_arp(output).items() if address == ip), None)
        return format_mac_address(mac) if mac else None

    def lookup_mac_port(self, session, mac: str) -> str | None:
        normalized = normalize_mac_address(mac)
        if not normalized:
            return None
        mac = format_mac_address(normalized)
        entries, _diagnostics = parse_mac_table(
            self._show(session, f"show mac-address-table address {mac}", allow_empty=True),
        )
        return next((entry["interface"] for entry in entries if entry["mac"] == normalized), None)

    # --- VLAN administration -------------------------------------------------------------------

    def read_vlan_constraints(self, session) -> vlanlib.VlanConstraints:
        if "running" in session.cache and session.cache["running"] is None:
            # read_switchports had no configuration and fell back to defaults: port usage is unknown.
            l3 = None
        else:
            try:
                blocks = parse_running_interfaces(self._show(session, "show running-config"))
            except SwitchConnectionError:
                l3 = None
            else:
                l3 = frozenset(
                    int(match.group(1)) for match in (re.match(r"^vlan(\d+)$", key) for key in blocks) if match
                )
        return vlanlib.VlanConstraints(protected={1: vlanlib.DEFAULT_REASON}, l3_interfaces=l3)

    def plan_vlan_create(self, session, vlan_id: int, name: str | None) -> ChangePlan:
        lines = [f"vlan {vlan_id}"] + ([f"name {name}"] if name else [])
        return cli_plan(lines, message=vlanlib.success_message("create", vlan_id))

    def plan_vlan_rename(self, session, vlan_id: int, name: str) -> ChangePlan:
        return cli_plan([f"vlan {vlan_id}", f"name {name}"], message=vlanlib.success_message("rename", vlan_id))

    def plan_vlan_delete(self, session, vlan_id: int) -> ChangePlan:
        return cli_plan([f"no vlan {vlan_id}"], message=vlanlib.success_message("delete", vlan_id))

    def plan_vlan_voice(self, session, vlan_id: int, voice: bool) -> ChangePlan:
        """Mark/unmark the VLAN as voice VLAN."""
        vlan_id = validate_vlan_id(vlan_id)
        return cli_plan([f"vlan {vlan_id}", "voice" if voice else "no voice", "exit"])

    def plan_save_config(self, session) -> ChangePlan:
        """``write memory``; every output without an error line counts as saved."""
        timeout = max(session.conn.read_timeout_override or 0, transport.SAVE_CONFIG_MIN_TIMEOUT_SECONDS)
        step = CliCommand("write memory", timeout=int(timeout))
        return ChangePlan(lines=(step.command,), steps=(step,), persistent=True, message=t("Konfiguration gespeichert"))

    # --- Configuration files, restore, rollback, reload ----------

    # Backups are JSON, because "copy … startup-config" only accepts JSON or checkpoints.
    # ``transfer_method = "sftp"`` and ``_mgmt_vrf`` come from ``AosCxDeviceMixin``.
    restore_filename = "startup.json"

    def _show_long(self, session, command: str) -> str:
        """Full configuration read with at least the save timeout (large configurations)."""
        conn = session.conn
        previous = conn.read_timeout_override
        conn.read_timeout_override = max(previous or 0, transport.SAVE_CONFIG_MIN_TIMEOUT_SECONDS)
        try:
            return self._show(session, command)
        finally:
            conn.read_timeout_override = previous

    def read_running_config(self, session) -> str:
        command = "show running-config json"
        return normalize_json_config(self._show_long(session, command), command)

    def read_startup_config(self, session) -> str:
        command = "show startup-config json"
        return normalize_json_config(self._show_long(session, command), command)

    def plan_reload(self, session) -> ChangePlan:
        """``boot system``: the save question is answered "n", the reboot question "y"; the session drops."""
        step = CliCommand(
            "boot system", prompts=(SAVE_NO, CONTINUE_YES), timeout=RELOAD_TIMEOUT_SECONDS, expect_disconnect=True,
        )
        return ChangePlan(lines=(step.command,), steps=(step,), reloads=True)

    def plan_config_restore(self, session, transfer: TransferLocation) -> ChangePlan:
        """``copy {sftp-url} startup-config vrf {vrf}`` and ``boot system`` without saving."""
        from ...transfer import location_secrets

        vrf = self._mgmt_vrf(session)
        copy = CliCommand(
            f"copy {transfer.url} startup-config vrf {vrf}",
            prompts=(HOST_KEY_YES, (r"(?i)password:", transfer.password)),
            timeout=COPY_TIMEOUT_SECONDS,
            success=r"(?i)\bsuccess",
        )
        reload = self.plan_reload(session)
        return ChangePlan(
            lines=(f"copy {transfer.display_url} startup-config vrf {vrf}", *reload.lines),
            steps=(copy, *reload.steps),
            reloads=True,
            secrets=location_secrets(transfer),
        )

    def plan_rollback_arm(self, session, minutes: int) -> ChangePlan:
        """Baseline checkpoint (for "revert now"), then ``checkpoint auto N`` (1–60 min) at the exec prompt."""
        minutes = int(minutes)
        if not 1 <= minutes <= 60:
            raise InvalidInputError(t("Der Wert {value} wird von diesem Gerät nicht unterstützt.", value=minutes))
        listing, _status = self._optional_show(session, "show checkpoint", [])
        commands = []
        if re.search(rf"^\s*{ROLLBACK_CHECKPOINT}\b", listing or "", re.MULTILINE):
            commands.append(CliCommand(f"erase checkpoint {ROLLBACK_CHECKPOINT}"))
        commands += [
            CliCommand(f"copy running-config checkpoint {ROLLBACK_CHECKPOINT}"),
            CliCommand(f"checkpoint auto {minutes}", success=r"(?i)expires in"),
        ]
        return ChangePlan(lines=tuple(step.command for step in commands), steps=tuple(commands))

    def plan_rollback_confirm(self, session) -> ChangePlan:
        steps = (CliCommand("checkpoint auto confirm"), CliCommand(f"erase checkpoint {ROLLBACK_CHECKPOINT}"))
        return ChangePlan(lines=tuple(step.command for step in steps), steps=steps)

    def plan_rollback_revert(self, session) -> ChangePlan:
        """Restore the baseline now and stop the timer (``checkpoint auto confirm`` [inferred])."""
        steps = (
            CliCommand(f"checkpoint rollback {ROLLBACK_CHECKPOINT}", timeout=COPY_TIMEOUT_SECONDS),
            CliCommand("checkpoint auto confirm"),
            CliCommand(f"erase checkpoint {ROLLBACK_CHECKPOINT}"),
        )
        return ChangePlan(lines=tuple(step.command for step in steps), steps=steps)

    # --- Port security -----------------------------------------

    def read_port_security(self, session) -> dict:
        sections = self._sections(session, required=True)
        roles = l2.role_vlans(sections)
        ports = {
            key: l2.parse_port(children, roles)
            for key, children in l2.interface_sections(sections).items() if is_interface_name(key)
        }
        return {"global": l2.parse_global(sections), "ports": ports}

    def _existing_vlans(self, session) -> set[int]:
        return {vlan["id"] for vlan in parse_vlans(self._show(session, "show vlan"))}

    def plan_port_security(self, session, interface: str, change: SecurityChange, detail: dict) -> ChangePlan:
        interface = self.validate_interface(interface)
        sections = self._sections(session, required=True)
        dot1x = change.dot1x
        fallback = [vlan for vlan in (dot1x.guest_vlan, dot1x.auth_fail_vlan) if vlan] if dot1x else []
        if fallback:
            missing = sorted(set(fallback) - self._existing_vlans(session))
            if missing:
                raise InvalidInputError(t("VLAN {vlan} existiert auf dem Switch nicht.", vlan=missing[0]))
        before, lines = l2.port_security_lines(
            change,
            l2.interface_sections(sections).get(interface_key(interface), []),
            l2.role_vlans(sections),
            global_port_security=l2.GLOBAL_PORT_SECURITY in l2.top_lines(sections),
            mode=detail.get("mode"),
        )
        if not lines and not before:
            return ChangePlan(lines=(), steps=())
        return cli_plan([*before, f"interface {config_interface_name(interface)}", *lines])

    def plan_security_global(self, session, change: SecurityGlobalChange) -> ChangePlan:
        sections = self._sections(session, required=True)
        needs_vlans = change.dhcp_snooping_vlans is not None or change.arp_inspection_vlans is not None
        lines = l2.security_global_lines(
            change, l2.parse_global(sections), self._existing_vlans(session) if needs_vlans else set(),
        )
        return cli_plan(lines) if lines else ChangePlan(lines=(), steps=())

    # --- Link aggregation ---------------------------------------

    max_lag_id = 256

    def lag_interface_name(self, lag_id: int) -> str:
        return f"lag{int(lag_id)}"

    def read_lags(self, session) -> list[dict]:
        lags = l2.parse_lag_config(self._sections(session, required=True))
        brief_out, _status = self._optional_show(session, "show interface brief", session.warnings)
        try:
            brief = {interface_key(row["port"]): row["link_state"] for row in parse_interface_brief(brief_out or "")}
        except SwitchConnectionError:
            brief = {}
        lacp = {}
        if any(lag["mode"] in ("lacp_active", "lacp_passive") for lag in lags):
            lacp = l2.parse_lacp_interfaces(self._optional_show(session, "show lacp interfaces", session.warnings)[0])
        result = []
        for lag in lags:
            members = []
            for member in lag["members"]:
                link = brief.get(member)
                static_state = {"up": "bundled", "down": "down"}.get(link)
                state = lacp.get(member) if lag["mode"] in ("lacp_active", "lacp_passive") else static_state
                members.append({"interface": member, "state": state})
            name = self.lag_interface_name(lag["id"])
            result.append({
                "id": lag["id"], "interface": name, "mode": lag["mode"], "members": members,
                "status": brief.get(name),
            })
        return result

    def _lag_id(self, lag_id: int) -> int:
        lag_id = int(lag_id)
        if not 1 <= lag_id <= self.max_lag_id:
            raise InvalidInputError(t("LAG-ID außerhalb des gültigen Bereichs 1-{max}: {value}",
                                      max=self.max_lag_id, value=lag_id))
        return lag_id

    def plan_lag_create(self, session, lag_id: int, mode: str, members: tuple[str, ...]) -> ChangePlan:
        """``interface lag N`` (L2, VLAN lines of the first member, LACP mode), then ``lag N`` per member."""
        lag_id = self._lag_id(lag_id)
        if mode not in l2.LAG_MODES:
            raise InvalidInputError(t(l2.UNSUPPORTED_VALUE, value=mode))
        members = tuple(self.validate_interface(member) for member in members)
        sections = l2.interface_sections(self._sections(session, required=True))
        vlan_lines = l2.vlan_lines(sections.get(interface_key(members[0]), [])) if members else []
        lacp = l2.LAG_MODES[mode]
        lines = [f"interface lag {lag_id}", "no shutdown", "no routing", *vlan_lines,
                 *([f"lacp mode {lacp}"] if lacp else []), "exit"]
        for member in members:
            lines += [f"interface {member}", f"lag {lag_id}", "exit"]
        return cli_plan(lines)

    def plan_lag_update(self, session, lag_id: int, add: tuple[str, ...], remove: tuple[str, ...]) -> ChangePlan:
        """New members take over the LAG's configuration on joining (their own settings are dropped)."""
        lag_id = self._lag_id(lag_id)
        lines = []
        for member in add:
            lines += [f"interface {self.validate_interface(member)}", f"lag {lag_id}", "exit"]
        for member in remove:
            lines += [f"interface {self.validate_interface(member)}", f"no lag {lag_id}", "exit"]
        return cli_plan(lines)

    def plan_lag_delete(self, session, lag_id: int) -> ChangePlan:
        return cli_plan([f"no interface lag {self._lag_id(lag_id)}"])

    # --- Spanning tree ------------------------------------------

    def _stp_config(self, session) -> dict:
        return l2.parse_stp_config(self._sections(session, required=True))

    def read_stp(self, session) -> dict:
        config = self._stp_config(session)
        summary_out, _status = self._optional_show(session, "show spanning-tree summary root", session.warnings)
        summary = l2.parse_stp_summary(summary_out or "")
        mode = summary["mode"] or config["mode"]
        ports_out, _status = self._optional_show(session, "show spanning-tree", session.warnings)
        return {
            "mode": mode,
            "priority": l2.stp_priorities(config, mode),
            "mst": l2.stp_mst(config) if mode == "mstp" else None,
            "roots": summary["roots"],
            "ports": l2.parse_stp_ports(ports_out, 0 if mode == "mstp" else None),
        }

    def plan_stp_mode(self, session, mode: str) -> ChangePlan:
        if mode not in l2.STP_MODES:
            raise InvalidInputError(t(l2.UNSUPPORTED_VALUE, value=mode))
        return cli_plan([f"spanning-tree mode {l2.STP_MODES[mode]}"])

    def plan_stp_priority(
        self, session, priority: int, vlans: tuple[int, ...] | None, instance: int | None,
    ) -> ChangePlan:
        """Absolute priorities become AOS-CX multipliers (32768 -> 8)."""
        multiplier = l2.bridge_multiplier(priority)
        if instance is not None:
            instance = int(instance)
            if instance == 0:
                return cli_plan([f"spanning-tree priority {multiplier}"])
            return cli_plan([f"spanning-tree instance {instance} priority {multiplier}"])
        if not vlans:
            raise InvalidInputError(t("Bitte entweder VLANs oder eine Instanz angeben."))
        vlan_list = format_vlan_list(tuple(sorted({validate_vlan_id(vlan) for vlan in vlans})))
        return cli_plan([f"spanning-tree vlan {vlan_list}", f"spanning-tree vlan {vlan_list} priority {multiplier}"])

    def plan_stp_mst(
        self, session, name: str, revision: int, instances: tuple[tuple[int, tuple[int, ...]], ...],
    ) -> ChangePlan:
        config = self._stp_config(session)
        lines = l2.mst_lines(name, revision, instances, config["instances"], config)
        return cli_plan(lines) if lines else ChangePlan(lines=(), steps=())

    def plan_stp_port(
        self, session, interface: str, instance_or_vlan: int | None, cost: int | None, priority: int | None,
    ) -> ChangePlan:
        interface = self.validate_interface(interface)
        if cost is not None and not 1 <= int(cost) <= 200000000:
            raise InvalidInputError(t(l2.UNSUPPORTED_VALUE, value=cost))
        multiplier = l2.port_multiplier(priority) if priority is not None else None
        mode = self._stp_config(session)["mode"]
        if mode == "rapid_pvst" and instance_or_vlan is not None:
            prefix = f"spanning-tree vlan {validate_vlan_id(instance_or_vlan)}"
        elif mode == "mstp" and instance_or_vlan:
            prefix = f"spanning-tree instance {int(instance_or_vlan)}"
        else:
            prefix = "spanning-tree"
        lines = [f"interface {config_interface_name(interface)}"]
        if cost is not None:
            lines.append(f"{prefix} cost {int(cost)}")
        if multiplier is not None:
            lines.append(f"{prefix} port-priority {multiplier}")
        return cli_plan(lines) if len(lines) > 1 else ChangePlan(lines=(), steps=())
