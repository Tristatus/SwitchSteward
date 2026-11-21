"""Aruba AOS-S / ProVision driver (Netmiko ``aruba_osswitch``, experimental).

AOS-S configures VLAN membership per VLAN (``vlan N untagged|tagged <ports>``), so
access/trunk/native are derived: access = untagged in N and tagged nowhere, trunk =
tagged in at least one VLAN, native = the untagged VLAN of a trunk. The word
``trunk`` means link aggregation on AOS-S and is never sent by this driver.
Every write reads the running configuration first; VLANs are only created through the VLAN tab (plan_vlan_create);
port writes never create VLANs. A voice VLAN is a tagged membership of a VLAN marked ``voice``; such a port
(one untagged data VLAN, exactly one tagged voice VLAN) is reported as access port with ``voice_vlan``.
Port security, LAGs and spanning tree: ``aruba_aoss_l2``.
"""

import ipaddress
import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from netmiko import NetmikoAuthenticationException

from ...i18n import t
from .. import clients, transport
from .. import vlans as vlanlib
from ..errors import InvalidInputError, SwitchConnectionError, append_warning
from ..features import VTP_CISCO_ONLY_REASON, supported, unsupported
from ..validation import format_vlan_list, sanitize_description, validate_choice, validate_vlan_id
from . import aruba_aoss_l2 as l2
from .aruba_aoscx_l2 import UNSUPPORTED_VALUE, bridge_multiplier, port_multiplier
from .aruba_aoss_device import DEVICE_FEATURES, AossDeviceMixin
from .aruba_aoss_l2 import canonical_interface, is_valid_interface
from .aruba_models import AOSS_CATALOG
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
from .cli import error_lines, expand_port_list, parse_fixed_table, parse_key_values
from .plans import (
    REDACTED,
    ChangePlan,
    CliCommand,
    CliLines,
    Pause,
    SecurityChange,
    SecurityGlobalChange,
    TransferLocation,
    cli_plan,
)

logger = logging.getLogger("switchsteward.switches.aruba_aoss")

SPEED_OPTIONS = ("auto", "10", "100", "1000")
DUPLEX_OPTIONS = ("auto", "half", "full")
POE_MODE_OPTIONS = ("auto", "never")
DESCRIPTION_MAX_LENGTH = 64
MAX_LLDP_DETAIL_PORTS = 64
MAX_MAC_VLANS = 64
PORT_ACTION_PAUSE_SECONDS = 5
COPY_TIMEOUT_SECONDS = 600
RELOAD_TIMEOUT_SECONDS = 120

# Interactive questions: the save question is always answered "n"
# (it would overwrite a downloaded startup configuration); reboot/continue questions "y".
SAVE_NO = (r"(?i)save current configuration", "n")
REBOOT_YES = (r"(?i)(?:rebooted|continue).*\[y/n\]|continue \(y/n\)", "y")
HOST_KEY_YES = (r"(?i)\(yes/no\)", "yes")

# Configuration errors (F10); the command echo is filtered out in ``_config_check``.
ERROR_MARKERS = (
    r"Invalid input",
    r"Ambiguous input",
    r"Incomplete input",
    r"Module not present",
    r"not found",
    r"not valid",
    r"\bError\b",
    r"^Unable to",
)
# Read errors: only line-leading markers, so port names or descriptions in data never match.
READ_ERROR_MARKERS = (
    r"^Invalid input",
    r"^Ambiguous input",
    r"^Incomplete input",
    r"^Module not present",
)

NOT_ERRDISABLED = "Der Port ist nicht durch eine Schutzfunktion deaktiviert."
POE_CYCLE_OFF = "PoE ist an Port {interface} ausgeschaltet; ein PoE-Neustart ist nicht möglich."
VOICE_ACCESS_ONLY = "Ein Voice-VLAN ist nur an Access-Ports möglich."
VOICE_EQUALS_DATA = "Voice-VLAN und Access-VLAN müssen verschieden sein."
UNKNOWN_REASON = "unbekannt"
# Log modules of protection features -> err-disable reason.
ERRDISABLE_MODULES = {
    "stp": "bpdu-protection", "loop-protect": "loop-protect", "ffi": "fault-finder", "port-security": "port-security",
    "portsec": "port-security", "port-access": "port-access",
}
POE_LIMIT_REASON = "PoE-Leistungsprofile werden für AOS-S nicht unterstützt."
LAG_MEMBER_REASON = (
    "Der Port ist Mitglied einer Link-Aggregation (Trk); VLANs und Edge-Port werden an der "
    "Trk-Schnittstelle konfiguriert."
)
NO_POE_PORT_REASON = "Dieses Interface stellt kein PoE bereit."
NO_TIMED_ROLLBACK_REASON = "Die Plattform hat kein zeitgesteuertes Rollback."
NO_QOS_TRUST_REASON = "AOS-S hat keine QoS-Trust-Einstellung pro Port."
LAG_FEATURES = ("port_mode", "access_vlan", "native_vlan", "trunk_allowed_vlans", "voice_vlan", "edge_port")

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
    "config_rollback": unsupported(NO_TIMED_ROLLBACK_REASON),
    "management_path": supported(),
    "port_security": supported(("restrict", "shutdown")),
    "port_security_sticky": supported(),
    "dot1x": supported(("dot1x", "mab", "dot1x_mab")),
    "dot1x_host_mode": supported(("single", "multi_auth", "multi_host")),
    "dot1x_fallback_vlans": supported(),
    "stp_guard": supported(("bpdu_guard", "root_guard", "loop_guard")),
    "storm_control": supported(("broadcast", "multicast", "unknown_unicast")),
    "storm_control_action": supported(("drop", "shutdown")),
    "dhcp_snooping": supported(),
    "arp_inspection": supported(),
    "ip_source_guard": supported(),
    "lag": supported(("static", "lacp_active", "lacp_passive")),
    "stp": supported(("rapid_pvst", "mstp")),
    "stp_mst": supported(),
    "qos": unsupported(NO_QOS_TRUST_REASON),
    "qos_voice": unsupported(NO_QOS_TRUST_REASON),
    "reload": supported(),
    **DEVICE_FEATURES,
}

_MAC_RE = re.compile(r"^[0-9a-f]{6}-[0-9a-f]{6}$", re.IGNORECASE)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# --- Parsers ---------------------------------------------------------------------------


def _system_value(output: str, label: str) -> str | None:
    """Value of ``Label : value`` in the two-column ``show system`` layout."""
    match = re.search(
        rf"(?:^|\s){label}\s*:[ \t]*(.*?)(?=\s{{2,}}[A-Za-z][A-Za-z ()%/-]*?\s*:|[ \t]*$)",
        output or "",
        re.MULTILINE | re.IGNORECASE,
    )
    if not match:
        return None
    return match.group(1).strip() or None


def parse_show_system(output: str) -> dict:
    return {
        "hostname": _system_value(output, "System Name"),
        "model": _system_value(output, r"Product(?: Name)?"),
        "serial_number": _system_value(output, "Serial Number"),
        "software_version": _system_value(output, "Software revision"),
        "uptime": _system_value(output, "Up Time"),
    }


def parse_modules_chassis(output: str) -> str | None:
    """``Chassis: 2930F-24G-PoE+-4SFP+ JL255A      Serial Number: ...`` -> model text."""
    match = re.search(r"^\s*Chassis\s*:\s*(.+)$", output or "", re.MULTILINE | re.IGNORECASE)
    if not match:
        return None
    value = re.split(r"\s{2,}|\s+Serial Number\s*:", match.group(1).strip(), maxsplit=1)[0].strip()
    return value or None


def parse_interfaces_brief(output: str) -> list[dict]:
    """Rows of ``show interfaces brief``; ``21-Trk1`` denotes port 21 as member of Trk1."""
    rows = []
    for line in (output or "").splitlines():
        if "|" not in line:
            continue
        left, right = line.split("|", 1)
        tokens = left.split()
        if not tokens:
            continue
        match = re.fullmatch(r"(.+?)(?:-(Trk\d+))?", tokens[0], re.IGNORECASE)
        port = canonical_interface(match.group(1))
        if not is_valid_interface(port):
            continue
        state = re.search(r"\b(Yes|No)\s+(Up|Down)\b(?:\s+(\S+))?", right, re.IGNORECASE)
        intrusion = re.match(r"\s*(Yes|No)\s+(?:Yes|No)\b", right, re.IGNORECASE)
        rows.append({
            "port": port,
            "lag": canonical_interface(match.group(2)) if match.group(2) else None,
            "enabled": None if not state else state.group(1).casefold() == "yes",
            "link": None if not state else state.group(2).casefold(),
            "mode": None if not state else state.group(3),
            "intrusion": bool(intrusion) and intrusion.group(1).casefold() == "yes",
        })
    return rows


@dataclass
class RunningConfig:
    # id -> {"name", "untagged": set, "tagged": set, "ip": bool, "voice": bool}
    vlans: dict[int, dict] = field(default_factory=dict)
    interfaces: dict[str, dict] = field(default_factory=dict)  # key -> {"name", "speed_duplex", "disabled"}
    edge_ports: set[str] = field(default_factory=set)
    lag_members: dict[str, str] = field(default_factory=dict)  # member key -> Trk name

    def target(self, port: str) -> str:
        """VLAN/spanning-tree settings of a LAG member live on its Trk interface."""
        key = canonical_interface(port)
        return self.lag_members.get(key, key)

    def membership(self, port: str) -> tuple[list[int], list[int]]:
        key = self.target(port)
        untagged = sorted(vlan for vlan, entry in self.vlans.items() if key in entry["untagged"])
        tagged = sorted(vlan for vlan, entry in self.vlans.items() if key in entry["tagged"])
        return untagged, tagged

    def interface(self, port: str) -> dict:
        return self.interfaces.get(canonical_interface(port), {"name": None, "speed_duplex": None, "disabled": False})


def _expand_ports(text: str) -> set[str]:
    try:
        return {canonical_interface(port) for port in expand_port_list(text)}
    except ValueError:
        raise SwitchConnectionError(
            t("Die Ausgabe von '{command}' hat ein unbekanntes Format.", command="show running-config")
        ) from None


def _config_name(value: str) -> str | None:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value or None


def parse_running_config(output: str) -> RunningConfig:
    """VLAN blocks, interface blocks, LAG membership and admin-edge ports; unknown lines are ignored."""
    config = RunningConfig()
    block: tuple[str, object] | None = None
    for raw in (output or "").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith(";"):
            continue
        if not raw[:1].isspace():
            block = None
            if match := re.fullmatch(r"vlan (\d{1,4})", stripped):
                vlan = int(match.group(1))
                config.vlans.setdefault(
                    vlan, {"name": None, "untagged": set(), "tagged": set(), "ip": False, "voice": False},
                )
                block = ("vlan", vlan)
            elif match := re.fullmatch(r"interface (\S+)", stripped):
                key = canonical_interface(match.group(1))
                config.interfaces.setdefault(key, {"name": None, "speed_duplex": None, "disabled": False})
                block = ("interface", key)
            elif match := re.fullmatch(r"trunk (\S+) (trk\d+)(?: \S+)?", stripped, re.IGNORECASE):
                lag = canonical_interface(match.group(2))
                for port in _expand_ports(match.group(1)):
                    config.lag_members[port] = lag
            elif match := re.fullmatch(r"spanning-tree (\S+) admin-edge-port", stripped):
                config.edge_ports |= _expand_ports(match.group(1))
            continue
        if block is None:
            continue
        if stripped == "exit":
            block = None
            continue
        kind, key = block
        if kind == "vlan":
            entry = config.vlans[key]
            if match := re.fullmatch(r"(untagged|tagged) (\S+)", stripped):
                entry[match.group(1)] |= _expand_ports(match.group(2))
            elif match := re.fullmatch(r"name (.+)", stripped):
                entry["name"] = _config_name(match.group(1))
            elif re.match(r"^ip address \S", stripped) or stripped.startswith("ipv6 "):
                entry["ip"] = True
            elif stripped == "voice":
                entry["voice"] = True
        else:
            entry = config.interfaces[key]
            if match := re.fullmatch(r"name (.+)", stripped):
                entry["name"] = _config_name(match.group(1))
            elif match := re.fullmatch(r"speed-duplex (\S+)", stripped):
                entry["speed_duplex"] = match.group(1)
            elif stripped == "disable":
                entry["disabled"] = True
    return config


def parse_vlans(output: str) -> list[dict]:
    """``show vlans``: ``10   Office   | Port-based No No`` (columns Status, Voice, Jumbo)."""
    vlans = []
    for line in (output or "").splitlines():
        match = re.match(r"^\s*(\d{1,4})\s+(.*?)\s*\|\s*(\S+)(?:\s+(Yes|No)\b)?", line, re.IGNORECASE)
        if match and 1 <= int(match.group(1)) <= 4094:
            voice = match.group(4).casefold() == "yes" if match.group(4) else None
            vlans.append({
                "id": int(match.group(1)), "name": match.group(2), "status": match.group(3).casefold(), "voice": voice,
            })
    return vlans


def parse_vlans_header(output: str) -> dict:
    """``show vlans`` header: ``max_vlans`` (int | None), ``primary`` and ``management`` VLAN names (or None)."""

    def value(label: str) -> str | None:
        match = re.search(rf"^\s*{label}\s*:[ \t]*(.*?)[ \t]*$", output or "", re.MULTILINE | re.IGNORECASE)
        return (match.group(1) or None) if match else None

    maximum = value("Maximum VLANs to support")
    return {
        "max_vlans": int(maximum) if maximum and maximum.isdigit() else None,
        "primary": value("Primary VLAN"),
        "management": value("Management VLAN"),
    }


def speed_duplex_from_config(value: str | None) -> tuple[str, str | None]:
    """Configured ``speed-duplex`` -> (speed, duplex); unknown keywords are shown unchanged."""
    if value is None or value == "auto":
        return "auto", "auto"
    if match := re.fullmatch(r"(10|100|1000)-(half|full)", value):
        return match.group(1), match.group(2)
    if match := re.fullmatch(r"auto-(10|100|1000)", value):
        return match.group(1), "auto"
    return value, None


def speed_duplex_value(speed: str, duplex: str | None) -> str:
    """Request values -> ``speed-duplex`` keyword (speed and duplex are coupled on AOS-S)."""
    speed = validate_choice(str(speed), SPEED_OPTIONS, "Speed")
    if duplex is not None:
        duplex = validate_choice(str(duplex), DUPLEX_OPTIONS, "Duplex")
    if speed == "auto":
        if duplex not in (None, "auto"):
            raise InvalidInputError(t("Bei Speed auto muss Duplex auto sein."))
        return "auto"
    if duplex not in ("half", "full"):
        raise InvalidInputError(t("Bei fester Geschwindigkeit muss Duplex half oder full sein."))
    if speed == "1000" and duplex == "half":
        raise InvalidInputError(t("1000 Mbit/s ist nur mit Vollduplex möglich."))
    return f"{speed}-{duplex}"


_POE_STATUS = re.compile(
    r"\b(Delivering|Searching|Disabled|Other Fault|Fault|Denied|Deny|Test|Invalid PD|Overload|Off)\b", re.IGNORECASE,
)


def parse_poe_brief(output: str) -> dict[str, dict]:
    """``show power-over-ethernet brief`` rows ``1 | Yes low usage 17.0 W 4.2 W  Delivering 2 ...``."""
    ports = {}
    for line in (output or "").splitlines():
        match = re.match(r"^\s*(\S+)\s*\|\s*(Yes|No)\b(.*)$", line, re.IGNORECASE)
        if not match:
            continue
        port = canonical_interface(match.group(1))
        if not is_valid_interface(port):
            continue
        rest = match.group(3)
        watts = [float(value) for value in re.findall(r"(\d+(?:\.\d+)?)\s*W\b", rest)]
        status = _POE_STATUS.search(rest)
        detail = empty_poe_detail(True)
        detail.update({
            "poe_mode": "auto" if match.group(2).casefold() == "yes" else "never",
            "poe_status": status.group(1).casefold() if status else None,
            "poe_used_watts": watts[1] if len(watts) >= 2 else None,
        })
        ports[port] = detail
    return ports


def _watts(output: str, pattern: str) -> float | None:
    match = re.search(pattern + r"\s*:\s*(\d+(?:\.\d+)?)", output or "", re.IGNORECASE)
    return float(match.group(1)) if match else None


def parse_poe_budget(output: str) -> dict:
    """System totals of ``show power-over-ethernet``; missing values stay ``None``."""
    budget = {
        "max_watts": _watts(output, r"Total Available Power"),
        "used_watts": _watts(output, r"Total (?:used Power|Power Drawn)"),
        "remaining_watts": _watts(output, r"Total Remaining Power"),
    }
    if all(value is None for value in budget.values()):
        match = re.search(
            r"Available\s*:\s*(\d+(?:\.\d+)?)\s*W\s+Used\s*:\s*(\d+(?:\.\d+)?)\s*W\s+Remaining\s*:\s*(\d+(?:\.\d+)?)\s*W",
            output or "", re.IGNORECASE,
        )
        if match:
            budget = dict(zip(budget, (float(value) for value in match.groups()), strict=True))
    return budget


def parse_lldp_remote(output: str) -> list[dict]:
    """``show lldp info remote-device`` table -> {local_port, chassis_id, port_id, port_descr, system_name}."""
    rows = parse_fixed_table(
        output, r"LocalPort\s*\|?\s*ChassisId", ["LocalPort", "ChassisId", "PortId", "PortDescr", "SysName"],
    )
    neighbors = []
    for row in rows or ():
        port = canonical_interface(row["LocalPort"].rstrip("|").strip())
        if not is_valid_interface(port):
            continue
        neighbors.append({
            "local_port": port,
            "chassis_id": row["ChassisId"].lstrip("|").strip() or None,
            "port_id": row["PortId"] or None,
            "port_descr": row["PortDescr"] or None,
            "system_name": row["SysName"] or None,
        })
    return neighbors


def lldp_summary_row(row: dict) -> dict:
    return neighbor_row(
        "lldp",
        device_id=row["system_name"] or row["chassis_id"],
        system_name=row["system_name"],
        chassis_id=row["chassis_id"],
        local_interface=row["local_port"],
        remote_interface=row["port_id"] or row["port_descr"],
    )


def _ip_addresses(block: str) -> list[str]:
    addresses = []
    for value in re.findall(r"^\s*Address\s*:\s*(\S+)", block, re.MULTILINE | re.IGNORECASE):
        try:
            address = str(ipaddress.ip_address(value))
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses


def parse_lldp_detail(output: str) -> list[dict]:
    """``show lldp info remote-device <port>``; one block per neighbor, starting at ``Local Port``."""
    neighbors = []
    for block in re.split(r"(?m)^(?=\s*Local Port\s*:)", output or ""):
        values = parse_key_values(block)
        port = canonical_interface(values.get("Local Port"))
        if not is_valid_interface(port):
            continue
        system_name = values.get("SysName") or None
        chassis_id = values.get("ChassisId") or None
        neighbors.append(neighbor_row(
            "lldp",
            device_id=system_name or chassis_id,
            system_name=system_name,
            chassis_id=chassis_id,
            platform=values.get("System Descr") or None,
            capabilities=values.get("System Capabilities Enabled") or None,
            ip_addresses=_ip_addresses(block),
            local_interface=port,
            remote_interface=values.get("PortId") or values.get("PortDescr") or None,
        ))
    return neighbors


def parse_mac_table(output: str, vlan: int) -> tuple[list[dict], int]:
    """``show mac-address vlan <id>`` -> entries and the number of unparsed data lines."""
    entries = []
    unparsed = 0
    for line in (output or "").splitlines():
        tokens = line.split()
        if not tokens or not re.match(r"^[0-9a-f]{6}-", tokens[0], re.IGNORECASE):
            continue
        port = canonical_interface(tokens[1]) if len(tokens) > 1 else ""
        mac = clients.normalize_mac_address(tokens[0]) if _MAC_RE.fullmatch(tokens[0]) else None
        if not mac or not is_valid_interface(port):
            unparsed += 1
            continue
        entries.append({"vlan": str(vlan), "mac": mac, "type": "DYNAMIC", "interface": port})
    return entries, unparsed


def parse_arp(output: str) -> dict[str, str]:
    """``show arp``: ``192.0.2.20   001122-334455   dynamic  1`` -> normalized MAC -> IPv4."""
    bindings = {}
    for line in (output or "").splitlines():
        tokens = line.split()
        if len(tokens) < 2 or not _IPV4_RE.fullmatch(tokens[0]) or not _MAC_RE.fullmatch(tokens[1]):
            continue
        mac = clients.normalize_mac_address(tokens[1])
        if mac and mac not in bindings:
            bindings[mac] = tokens[0]
    return bindings


def ipv4_or_none(text: str | None) -> str | None:
    """Canonical IPv4 text or None (``0.0.0.0`` counts as not configured)."""
    try:
        address = ipaddress.IPv4Address((text or "").strip())
    except ValueError:
        return None
    return None if address.is_unspecified else str(address)


def parse_management(output: str) -> dict:
    """``show management``: default gateway and the ``VLAN-name MAC | IP`` rows."""
    gateway = re.search(r"^\s*Default Gateway\s*:\s*(\S+)", output or "", re.MULTILINE | re.IGNORECASE)
    rows = []
    for line in (output or "").splitlines():
        match = re.match(r"^\s*(\S.*?)\s+[0-9a-f]{6}-[0-9a-f]{6}\s*\|\s*(\S+)", line, re.IGNORECASE)
        if match:
            rows.append({"vlan_name": match.group(1), "ip": ipv4_or_none(match.group(2))})
    return {"gateway": ipv4_or_none(gateway.group(1)) if gateway else None, "vlans": rows}


def parse_oobm_ip(output: str) -> dict:
    """``show oobm ip detail``: default gateway and the configured addresses (without prefix length)."""
    gateway = re.search(r"^\s*IPv4 Default Gateway\s*:\s*(\S+)", output or "", re.MULTILINE | re.IGNORECASE)
    addresses = [ipv4_or_none(value) for value in re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})/\d{1,2}\b", output or "")]
    return {
        "gateway": ipv4_or_none(gateway.group(1)) if gateway else None,
        "addresses": [address for address in addresses if address],
    }


def parse_default_route(output: str) -> str | None:
    """``show ip route``: gateway of the ``0.0.0.0/0`` row."""
    for line in (output or "").splitlines():
        tokens = line.split()
        if len(tokens) >= 2 and tokens[0] == "0.0.0.0/0":
            return ipv4_or_none(tokens[1])
    return None


def parse_mac_address_port(output: str, mac: str) -> str | None:
    """``show mac-address <mac>``: ``Port VLAN`` rows (or ``MAC Port`` rows) -> port where ``mac`` was learned."""
    for line in (output or "").splitlines():
        tokens = line.split()
        if len(tokens) >= 2 and _MAC_RE.fullmatch(tokens[0]):
            port = canonical_interface(tokens[1]) if clients.normalize_mac_address(tokens[0]) == mac else ""
        elif len(tokens) >= 2 and tokens[1].isdigit():
            port = canonical_interface(tokens[0])
        else:
            continue
        if is_valid_interface(port):
            return port
    return None


def voice_vlan_of(config: RunningConfig, port: str) -> int | None:
    """The one tagged VLAN marked ``voice`` of a port with an untagged data VLAN, else None."""
    untagged, tagged = config.membership(port)
    if len(untagged) == 1 and len(tagged) == 1 and config.vlans[tagged[0]].get("voice"):
        return tagged[0]
    return None


def switchport_detail(config: RunningConfig, port: str) -> dict:
    """Switchport fields derived from VLAN membership (see module docstring)."""
    detail = empty_switchport_detail(port)
    untagged, tagged = config.membership(port)
    detail["switchport_enabled"] = True
    voice = voice_vlan_of(config, port)
    if voice is not None:
        detail.update({"mode": "access", "access_vlan": untagged[0], "voice_vlan": voice})
    elif tagged:
        detail.update({
            "mode": "trunk",
            "native_vlan": untagged[0] if untagged else None,
            # Like IOS, the allowed list includes the native VLAN.
            "trunk_allowed_vlan": format_vlan_list(tuple(sorted({*tagged, *untagged}))),
        })
    elif untagged:
        detail.update({"mode": "access", "access_vlan": untagged[0]})
    if detail["mode"] != "unknown":
        detail["administrative_mode"] = detail["operational_mode"] = detail["mode"]
    return detail


def parse_poe_port(output: str) -> dict:
    """``show power-over-ethernet <port>``: enable state, priority and allocation (missing values None)."""

    def value(pattern: str) -> str | None:
        match = re.search(pattern, output or "", re.IGNORECASE)
        return match.group(1) if match else None

    enabled = value(r"\bPower Enable\s*:\s*(Yes|No)\b")
    watts = value(r"\bValue\s*:\s*(\d+)\s*W\b")
    return {
        "enabled": None if enabled is None else enabled.casefold() == "yes",
        "priority": (value(r"\bPriority\s*:\s*(critical|high|low)\b") or "").casefold() or None,
        "allocate_by": (value(r"\bAllocateBy\s*:\s*(usage|class|value)\b") or "").casefold() or None,
        "value_watts": int(watts) if watts else None,
    }


def errdisable_log_reason(output: str | None, port: str) -> str | None:
    """Newest ``show logging -r`` line of a protection module naming ``port {port}`` -> reason."""
    for line in (output or "").splitlines():
        match = re.match(r"^\s*[A-Z]\s+\S+\s+\S+\s+\d+\s+([A-Za-z][\w-]*):\s*(.*)$", line)
        if not match or not re.search(rf"\bports?\s+{re.escape(port)}\b", match.group(2), re.IGNORECASE):
            continue
        module = match.group(1).casefold()
        if module in ERRDISABLE_MODULES:
            return ERRDISABLE_MODULES[module]
    return None


def _config_check(line: str, output: str, errors: list[str]) -> list[str]:
    """Ignore the command echo: descriptions such as "Error port" must not count as errors."""
    return [error for error in errors if line not in error]


# --- Driver ----------------------------------------------------------------------------


class ArubaAossDriver(AossDeviceMixin, SshSwitchDriver):
    id = "aruba_osswitch"
    vendor = "Aruba"
    label = "Aruba AOS-S"
    experimental = True
    features = FEATURES
    catalog = AOSS_CATALOG
    netmiko_device_type = "aruba_osswitch"
    config_error_markers = ERROR_MARKERS
    config_check = _config_check

    @contextmanager
    def session(self, switch: dict, credentials: dict) -> Iterator[transport.SshSession]:
        """Netmiko enters the manager level itself and raises ``ValueError`` when that fails."""
        opened = False
        try:
            with transport.ssh_session(switch, credentials, self.netmiko_device_type) as session:
                opened = True
                yield session
        except ValueError:
            if opened:
                raise
            logger.warning("Enable failed for switch id=%s", switch.get("id"))
            raise SwitchConnectionError(
                t("Der Manager-Modus (enable) konnte nicht aktiviert werden. Enable-Zugangsdaten prüfen.")
            ) from None

    # --- Interface names ---------------------------------------------------------------

    def validate_interface(self, name: str) -> str:
        interface = canonical_interface(name)
        if not is_valid_interface(interface):
            raise InvalidInputError(t("Ungültiger Interface-Name: {interface}", interface=name))
        return interface

    def interface_key(self, name: str) -> str:
        return canonical_interface(name)

    def is_physical_interface(self, name: str) -> bool:
        interface = canonical_interface(name)
        return is_valid_interface(interface) and not interface.startswith("Trk")

    # --- Show helpers ------------------------------------------------------------------

    def _show(self, session: transport.SshSession, command: str, *, allow_empty: bool = False) -> str:
        output = transport.send_show(session.conn, command)
        if not isinstance(output, str) or (not output.strip() and not allow_empty):
            raise SwitchConnectionError(t("Der Switch hat für '{command}' keine Ausgabe geliefert.", command=command))
        errors = error_lines(output, READ_ERROR_MARKERS)
        if errors:
            raise SwitchConnectionError(t(
                "Der Switch hat den Lesebefehl '{command}' abgelehnt: {errors}", command=command,
                errors="; ".join(errors),
            ))
        return output

    def _optional(self, session: transport.SshSession, command: str) -> tuple[str | None, str]:
        """Optional read; failures add a warning. Status ok | timeout | skipped | error."""
        if session.broken:
            return None, "skipped"
        try:
            return self._show(session, command), "ok"
        except transport.SSH_TIMEOUT_ERRORS:
            logger.warning("Optional read %r timed out for switch id=%s", command, session.switch.get("id"))
            session.broken = True
            append_warning(
                session.warnings, t("'{command}' lief in ein Zeitlimit; weitere Abfragen dieser Sitzung entfallen.",
                                    command=command),
            )
            return None, "timeout"
        except (*transport.SSH_ERRORS, SwitchConnectionError) as exc:
            logger.warning("Optional read %r failed for switch id=%s (%s)", command, session.switch.get("id"),
                           type(exc).__name__)
            append_warning(
                session.warnings, t("'{command}' ist fehlgeschlagen; die Daten können unvollständig sein.",
                                    command=command),
            )
            return None, "error"

    def _running_config(self, session: transport.SshSession, *, fresh: bool = False) -> RunningConfig:
        if fresh or "running" not in session.cache:
            text = self._show(session, "show running-config")
            session.cache["running"] = parse_running_config(text)
            session.cache["running_text"] = text
            session.cache.pop("security", None)
        return session.cache["running"]

    def _security(self, session: transport.SshSession, *, fresh: bool = False) -> l2.SecurityConfig:
        """Port security, LAG and spanning-tree settings of the (cached) running configuration."""
        self._running_config(session, fresh=fresh)
        if "security" not in session.cache:
            session.cache["security"] = l2.SecurityConfig(session.cache["running_text"])
        return session.cache["security"]

    def _brief(self, session: transport.SshSession) -> list[dict]:
        rows = parse_interfaces_brief(self._show(session, "show interfaces brief"))
        if not rows:
            raise SwitchConnectionError(
                t("Die Ausgabe von '{command}' hat ein unbekanntes Format.", command="show interfaces brief")
            )
        return rows

    def _errdisabled(self, session: transport.SshSession, brief: list[dict], config: RunningConfig) -> dict[str, str]:
        """Port -> reason for ports disabled by a protection feature (``Enabled=No`` without ``disable``
        in the configuration, or an intrusion alert); the reason comes from ``show logging -r``."""
        intrusion = {row["port"] for row in brief if row.get("intrusion")}
        disabled = {
            row["port"] for row in brief if row["enabled"] is False and not config.interface(row["port"])["disabled"]
        }
        if not intrusion and not disabled:
            return {}
        log = None
        if disabled - intrusion:
            log, _status = self._optional(session, "show logging -r")
        return {
            port: "port-security" if port in intrusion else (errdisable_log_reason(log, port) or t(UNKNOWN_REASON))
            for port in sorted(intrusion | disabled)
        }

    def _model(self, session: transport.SshSession, system: dict) -> str | None:
        output, _status = self._optional(session, "show modules")
        return parse_modules_chassis(output or "") or system.get("model")

    # --- Reads -------------------------------------------------------------------------

    def check_connection(self, switch: dict, credentials: dict) -> dict:
        try:
            with transport.open_ssh(switch, credentials, self.netmiko_device_type) as session:
                prompt = session.conn.find_prompt()
                model = None
                try:
                    model = parse_modules_chassis(self._show(session, "show modules"))
                except (*transport.SSH_ERRORS, SwitchConnectionError) as exc:
                    logger.warning("Model detection failed for switch id=%s (%s)", switch.get("id"), type(exc).__name__)
            return {"ok": True, "message": t("Verbindung erfolgreich, Prompt: {prompt}", prompt=prompt), "model": model}
        except NetmikoAuthenticationException:
            return {"ok": False, "message": t("Authentifizierung fehlgeschlagen (Benutzername/Passwort prüfen)"),
                    "model": None}
        except transport.SSH_TIMEOUT_ERRORS:
            return {"ok": False, "message": t("Zeitüberschreitung - Switch nicht erreichbar (IP/Port/Firewall prüfen)"),
                    "model": None}
        except ValueError:
            return {"ok": False, "model": None, "message": t(
                "Der Manager-Modus (enable) konnte nicht aktiviert werden. Enable-Zugangsdaten prüfen.")}
        except Exception as exc:
            logger.warning("SSH connection test failed for switch id=%s (%s)", switch.get("id"), type(exc).__name__)
            return {"ok": False, "message": t("SSH-Verbindung fehlgeschlagen. Server-Log prüfen."), "model": None}

    def read_device_info(self, session: transport.SshSession) -> dict:
        system = parse_show_system(self._show(session, "show system"))
        return {
            "hostname": system["hostname"],
            "model": self._model(session, system),
            "serial_number": system["serial_number"],
            "software_version": system["software_version"],
            "uptime": system["uptime"],
        }

    def read_interfaces(self, session: transport.SshSession) -> list[dict]:
        brief = self._brief(session)
        config = self._running_config(session)
        errdisabled = self._errdisabled(session, brief, config)
        rows = []
        for item in brief:
            detail = switchport_detail(config, item["port"])
            if item["enabled"] is None:
                admin_state, link_state = "unknown", "unknown"
            else:
                admin_state = "enabled" if item["enabled"] else "disabled"
                link_state = item["link"]
            rows.append({
                "port": item["port"],
                "description": config.interface(item["port"])["name"] or "",
                "status": "disabled" if admin_state == "disabled" else link_state,
                "vlan": "trunk" if detail["mode"] == "trunk" else str(detail["access_vlan"] or ""),
                "admin_state": admin_state,
                "link_state": link_state,
                "errdisabled_reason": errdisabled.get(item["port"]),
            })
        return rows

    def read_vlans(self, session: transport.SshSession) -> list[dict]:
        if "vlans" not in session.cache:
            output = self._show(session, "show vlans")
            vlans = parse_vlans(output)
            if not vlans:
                raise SwitchConnectionError(
                    t("Die Ausgabe von '{command}' hat ein unbekanntes Format.", command="show vlans")
                )
            session.cache["vlans"] = vlans
            session.cache["vlans_output"] = output
        return session.cache["vlans"]

    def read_switchports(self, session: transport.SshSession, interfaces: list[dict]) -> dict[str, dict]:
        config = self._running_config(session)
        return {canonical_interface(item["port"]): switchport_detail(config, item["port"]) for item in interfaces}

    def read_poe_ports(self, session: transport.SshSession) -> dict[str, dict] | None:
        output, _status = self._optional(session, "show power-over-ethernet brief")
        if output is None:
            append_warning(session.warnings, t("PoE-Daten konnten nicht gelesen werden; PoE-Status unbekannt."))
            return None
        return parse_poe_brief(output)

    def read_poe_budget(self, session: transport.SshSession, device_info: dict) -> dict:
        summary = empty_poe_summary()
        output, _status = self._optional(session, "show power-over-ethernet")
        if output is None:
            append_warning(summary["warnings"], t("Das PoE-Gesamtbudget ist nicht verfügbar."))
        else:
            summary.update(parse_poe_budget(output))
            if summary["max_watts"]:
                summary["supported"] = True
        model = device_info.get("model")
        profile = self.catalog.match(model)
        if profile is not None and profile.poe_standards is not None:
            summary["standards"] = [STANDARD_LABELS[standard] for standard in profile.poe_standards]
            summary["standards_source"] = t("Herstellerangabe (nicht an Hardware verifiziert): {model}", model=model)
            if not profile.poe_standards:
                summary["supported"] = False
        return summary

    def read_port_detail(self, session: transport.SshSession, interface: str) -> dict:
        interface = self.validate_interface(interface)
        brief_rows = self._brief(session)
        brief = {item["port"]: item for item in brief_rows}
        config = self._running_config(session, fresh=True)
        if interface not in brief and interface not in config.lag_members.values():
            raise InvalidInputError(t("Interface {interface} existiert auf dem Switch nicht.", interface=interface))
        errdisabled = self._errdisabled(session, [row for row in brief_rows if row["port"] == interface], config)
        poe_ports = self.read_poe_ports(session) if interface in brief else {}
        poe_detail = empty_poe_detail(None) if poe_ports is None else poe_ports.get(interface, empty_poe_detail(False))
        settings = config.interface(interface)
        speed, duplex = speed_duplex_from_config(settings["speed_duplex"])
        status = brief.get(interface)
        detail = {
            "interface": interface,
            "description": settings["name"],
            **switchport_detail(config, interface),
            "lag": config.lag_members.get(interface),
            "errdisabled_reason": errdisabled.get(interface),
            "portfast": config.target(interface) in config.edge_ports,
            "speed": speed,
            "duplex": duplex,
            "shutdown": settings["disabled"] if status is None or status["enabled"] is None else not status["enabled"],
            **poe_detail,
            "poe_standard_options": [],
            "poe_standards_reason": None,
            "poe_configured_max_watts": None,
            "port_options": {},
            "warnings": session.warnings,
        }
        return detail

    def runtime_overrides(self, detail: dict) -> dict[str, str]:
        overrides = {}
        if detail.get("lag"):
            overrides.update(dict.fromkeys(LAG_FEATURES, LAG_MEMBER_REASON))
        if detail.get("poe_supported") is False:
            overrides.update(dict.fromkeys(("poe", "poe_mode", "poe_cycle"), NO_POE_PORT_REASON))
        return overrides

    def read_neighbors(self, session: transport.SshSession) -> list[dict]:
        try:
            summary = parse_lldp_remote(self._show(session, "show lldp info remote-device"))
        except SwitchConnectionError as exc:
            raise SwitchConnectionError(t("Nachbarn konnten nicht gelesen werden.") + " " + str(exc)) from None
        ports = list(dict.fromkeys(row["local_port"] for row in summary))
        if len(ports) > MAX_LLDP_DETAIL_PORTS:
            append_warning(session.warnings, t(
                "Mehr als {limit} Ports mit LLDP-Nachbarn; Details werden nur für die ersten {limit} Ports gelesen.",
                limit=MAX_LLDP_DETAIL_PORTS,
            ))
        details: dict[str, list[dict]] = {}
        for port in ports[:MAX_LLDP_DETAIL_PORTS]:
            output, _status = self._optional(session, f"show lldp info remote-device {port}")
            rows = [row for row in parse_lldp_detail(output or "") if row["local_interface"] == port]
            if rows:
                details[port] = rows
        neighbors = []
        for port in ports:
            neighbors.extend(
                details.get(port) or [lldp_summary_row(row) for row in summary if row["local_port"] == port]
            )
        return neighbors

    def read_client_snapshot(self, session: transport.SshSession, switch: dict) -> dict:
        warnings = session.warnings
        interfaces = self.read_interfaces(session)
        switchports = self.read_switchports(session, interfaces)
        vlan_ids = sorted(vlan["id"] for vlan in self.read_vlans(session))
        if len(vlan_ids) > MAX_MAC_VLANS:
            append_warning(warnings, t(
                "Mehr als {limit} VLANs; die MAC-Tabelle wird nur für die ersten {limit} VLANs gelesen.",
                limit=MAX_MAC_VLANS,
            ))
        mac_entries = []
        unparsed = 0
        read_any = False
        for vlan in vlan_ids[:MAX_MAC_VLANS]:
            output, _status = self._optional(session, f"show mac-address vlan {vlan}")
            if output is None:
                continue
            read_any = True
            entries, failed = parse_mac_table(output, vlan)
            mac_entries.extend(entries)
            unparsed += failed
        if not read_any:
            raise SwitchConnectionError(t("Die MAC-Adresstabelle konnte nicht gelesen werden."))
        if unparsed:
            append_warning(warnings, t(
                "Mindestens eine relevante Zeile der MAC-Tabelle hatte ein unbekanntes Format; "
                "die Client-Erkennung kann unvollständig sein."
            ))
        source_status = dict.fromkeys(
            ("arp", "device_tracking", "dhcp_snooping", "cdp", "lldp", "port_security", "authentication_session"),
            "not_requested",
        )
        arp_out, source_status["arp"] = self._optional(session, "show arp")
        ip_bindings = parse_arp(arp_out or "")
        lldp_out, source_status["lldp"] = self._optional(session, "show lldp info remote-device")
        return client_snapshot(
            switch,
            self,
            mac_entries=mac_entries,
            interfaces=interfaces,
            switchports=switchports,
            ip_bindings=ip_bindings,
            ip_sources=dict.fromkeys(ip_bindings, "arp"),
            neighbors=[lldp_summary_row(row) for row in parse_lldp_remote(lldp_out or "")],
            source_status=source_status,
            mac_table_diagnostics={
                "parsed_entries": len(mac_entries), "unparsed_data_lines": unparsed, "ignored_data_lines": 0,
            },
            warnings=warnings,
        )

    # --- Writes ------------------------------------------------------------------------

    def validate_port_change(self, interface: str, change: PortChange) -> None:
        """Reject invalid values before the session is opened."""
        self.validate_interface(interface)
        if change.description is not None:
            _description(change.description)
        for vlan in (change.access_vlan, change.native_vlan, change.voice_vlan or None):
            if vlan is not None:
                validate_vlan_id(vlan)
        if isinstance(change.trunk_allowed_vlans, tuple):
            for vlan in change.trunk_allowed_vlans:
                validate_vlan_id(vlan)
        if change.speed is not None:
            speed_duplex_value(change.speed, change.duplex)
        if change.poe_mode is not None:
            validate_choice(change.poe_mode, POE_MODE_OPTIONS, "PoE")

    def read_port_state(self, session: transport.SshSession, interface: str, change: PortChange) -> dict:
        """Fresh VLAN membership (plus existing VLANs and PoE ports when needed) before any write."""
        config = self._running_config(session, fresh=True)
        untagged, tagged = config.membership(interface)
        state = {
            "interface": interface,
            "untagged": untagged,
            "tagged": tagged,
            "mode": switchport_detail(config, interface)["mode"],
            "voice_vlan": voice_vlan_of(config, interface),
            "voice_vlans": sorted(vlan for vlan, entry in config.vlans.items() if entry.get("voice")),
            "lag": config.lag_members.get(canonical_interface(interface)),
            "existing_vlans": None,
        }
        if any(value is not None for value in (
            change.mode, change.access_vlan, change.native_vlan, change.trunk_allowed_vlans, change.voice_vlan,
        )):
            state["existing_vlans"] = sorted(vlan["id"] for vlan in self.read_vlans(session))
        if change.poe_mode is not None:
            poe_ports = self.read_poe_ports(session)
            if poe_ports is not None:
                state["poe_supported"] = canonical_interface(interface) in poe_ports
        return state

    def port_change_commands(self, interface: str, change: PortChange, state: dict) -> list[str]:
        """Global-context commands; enable/disable comes last."""
        commands = []
        if change.description is not None:
            text = _description(change.description)
            commands.append(f"no interface {interface} name" if text == "" else f'interface {interface} name "{text}"')
        if change.voice_vlan and change.voice_vlan not in (state.get("voice_vlans") or ()):
            # Phones learn the voice VLAN (LLDP-MED) only from VLANs marked "voice".
            commands += [f"vlan {validate_vlan_id(change.voice_vlan)}", "voice", "exit"]
        commands.extend(vlan_commands(interface, change, state))
        if change.edge_port is not None:
            command = f"spanning-tree {interface} admin-edge-port"
            commands.append(command if change.edge_port else f"no {command}")
        if change.speed is not None:
            commands.append(f"interface {interface} speed-duplex {speed_duplex_value(change.speed, change.duplex)}")
        if change.poe_mode is not None:
            mode = validate_choice(change.poe_mode, POE_MODE_OPTIONS, "PoE")
            commands.append(
                f"interface {interface} power-over-ethernet" if mode == "auto"
                else f"no interface {interface} power-over-ethernet"
            )
        if change.shutdown is not None:
            commands.append(f"interface {interface} {'disable' if change.shutdown else 'enable'}")
        return commands

    def plan_port_change(
        self, session: transport.SshSession, interface: str, change: PortChange, detail: dict,
    ) -> ChangePlan:
        """Plan without steps when the port already has the requested state."""
        interface = self.validate_interface(interface)
        commands = self.port_change_commands(interface, change, detail)
        message = t("Interface-Konfiguration übernommen (noch nicht dauerhaft gespeichert)")
        return cli_plan(commands, message=message) if commands else ChangePlan(lines=(), steps=(), message=message)

    def plan_port_state(self, session: transport.SshSession, interface: str, enabled: bool) -> ChangePlan:
        interface = self.validate_interface(interface)
        message = (
            "Port {interface} wurde eingeschaltet (noch nicht dauerhaft gespeichert)" if enabled
            else "Port {interface} wurde ausgeschaltet (noch nicht dauerhaft gespeichert)"
        )
        return cli_plan(
            [f"interface {interface} {'enable' if enabled else 'disable'}"], message=t(message, interface=interface),
        )

    # --- Management path ----------------------------------------------------------

    def read_management_path(self, session: transport.SshSession) -> dict:
        """VLAN carrying the session address (``show management``), else the OOBM port (2930M/3810M)."""
        target = ipv4_or_none(session.switch.get("ip"))
        path = {"gateway": None, "management_ip": target, "management_interface": None, "management_vlan": None}
        management = parse_management(self._show(session, "show management"))
        path["gateway"] = management["gateway"]
        name = next((row["vlan_name"] for row in management["vlans"] if target and row["ip"] == target), None)
        if name is not None:
            vlan = next(
                (row["id"] for row in self.read_vlans(session) if (row["name"] or "").casefold() == name.casefold()),
                None,
            )
            if vlan is not None:
                path.update(management_interface=f"vlan{vlan}", management_vlan=vlan)
        elif target is not None:
            try:
                oobm = parse_oobm_ip(self._show(session, "show oobm ip detail"))
            except SwitchConnectionError:  # switches without an OOBM port reject the command
                oobm = {"gateway": None, "addresses": []}
            if target in oobm["addresses"]:
                path.update(gateway=oobm["gateway"], management_interface="oobm")
                return path
        if path["gateway"] is None:
            # With 'ip routing' the default gateway is a static default route.
            route_out, _status = self._optional(session, "show ip route")
            path["gateway"] = parse_default_route(route_out or "")
        return path

    def lookup_arp(self, session: transport.SshSession, ip: str) -> str | None:
        ip = str(ipaddress.IPv4Address(ip))
        output = self._show(session, f"show arp | include {ip}", allow_empty=True)
        mac = next((mac for mac, address in parse_arp(output).items() if address == ip), None)
        return clients.format_mac_address(mac) if mac else None

    def lookup_mac_port(self, session: transport.SshSession, mac: str) -> str | None:
        normalized = clients.normalize_mac_address(mac)
        if not normalized:
            return None
        output = self._show(session, f"show mac-address {normalized[:6]}-{normalized[6:]}", allow_empty=True)
        return parse_mac_address_port(output, normalized)

    # --- VLAN administration -------------------------------------------------------------------

    def read_vlan_constraints(self, session: transport.SshSession) -> vlanlib.VlanConstraints:
        rows = self.read_vlans(session)
        header = parse_vlans_header(session.cache.get("vlans_output") or "")
        ids_by_name = {}
        for row in rows:
            ids_by_name.setdefault((row["name"] or "").casefold(), row["id"])
        protected = {1: vlanlib.DEFAULT_REASON}
        for key, reason in (("primary", vlanlib.PRIMARY_REASON), ("management", vlanlib.MANAGEMENT_REASON)):
            vlan_id = ids_by_name.get(header[key].casefold()) if header[key] else None
            if vlan_id is not None:
                protected.setdefault(vlan_id, reason)
        try:
            config = self._running_config(session, fresh=True)
        except SwitchConnectionError:
            l3 = None
        else:
            l3 = frozenset(vlan for vlan, entry in config.vlans.items() if entry.get("ip"))
        return vlanlib.VlanConstraints(protected=protected, l3_interfaces=l3, max_vlans=header["max_vlans"])

    def plan_vlan_create(self, session: transport.SshSession, vlan_id: int, name: str | None) -> ChangePlan:
        line = f'vlan {vlan_id} name "{name}"' if name else f"vlan {vlan_id}"
        return cli_plan([line], message=vlanlib.success_message("create", vlan_id))

    def plan_vlan_rename(self, session: transport.SshSession, vlan_id: int, name: str) -> ChangePlan:
        return cli_plan([f'vlan {vlan_id} name "{name}"'], message=vlanlib.success_message("rename", vlan_id))

    def plan_vlan_delete(self, session: transport.SshSession, vlan_id: int) -> ChangePlan:
        return cli_plan([f"no vlan {vlan_id}"], message=vlanlib.success_message("delete", vlan_id))

    def plan_vlan_voice(self, session: transport.SshSession, vlan_id: int, voice: bool) -> ChangePlan:
        """Mark/unmark the VLAN as voice VLAN."""
        vlan_id = validate_vlan_id(vlan_id)
        return cli_plan([f"vlan {vlan_id}", "voice" if voice else "no voice", "exit"])

    def plan_save_config(self, session: transport.SshSession) -> ChangePlan:
        """``write memory``; every output without an error line counts as saved."""
        timeout = max(session.conn.read_timeout_override or 0, transport.SAVE_CONFIG_MIN_TIMEOUT_SECONDS)
        step = CliCommand("write memory", timeout=int(timeout))
        return ChangePlan(lines=(step.command,), steps=(step,), persistent=True, message=t("Konfiguration gespeichert"))

    # --- Port actions -----------------------------------------------

    def plan_port_bounce(self, session: transport.SshSession, interface: str) -> ChangePlan:
        """``interface P disable``, pause, ``interface P enable`` as two configuration blocks."""
        interface = self.validate_interface(interface)
        down, up = (f"interface {interface} disable",), (f"interface {interface} enable",)
        return ChangePlan(lines=down + up, steps=(CliLines(down), Pause(PORT_ACTION_PAUSE_SECONDS), CliLines(up)))

    def plan_poe_cycle(self, session: transport.SshSession, interface: str) -> ChangePlan:
        """No native power cycle: PoE off, pause, on; priority and allocation read before are re-applied."""
        interface = self.validate_interface(interface)
        poe = parse_poe_port(self._show(session, f"show power-over-ethernet {interface}"))
        if poe["enabled"] is False:
            raise InvalidInputError(t(POE_CYCLE_OFF, interface=interface))
        off = (f"no interface {interface} power-over-ethernet",)
        on = [f"interface {interface} power-over-ethernet"]
        if poe["priority"]:
            on.append(f"interface {interface} power-over-ethernet {poe['priority']}")
        if poe["allocate_by"] in ("class", "value"):
            on.append(f"interface {interface} poe-allocate-by {poe['allocate_by']}")
            if poe["allocate_by"] == "value" and poe["value_watts"] is not None:
                on.append(f"interface {interface} poe-value {poe['value_watts']}")
        return ChangePlan(
            lines=off + tuple(on), steps=(CliLines(off), Pause(PORT_ACTION_PAUSE_SECONDS), CliLines(tuple(on))),
        )

    def plan_errdisable_recover(self, session: transport.SshSession, interface: str) -> ChangePlan:
        """Clear an intrusion flag (port security) and enable the port again."""
        interface = self.validate_interface(interface)
        brief = [row for row in self._brief(session) if row["port"] == interface]
        config = self._running_config(session, fresh=True)
        disabled = bool(brief) and (
            brief[0]["intrusion"] or (brief[0]["enabled"] is False and not config.interface(interface)["disabled"])
        )
        if not disabled:
            raise InvalidInputError(t(NOT_ERRDISABLED))
        lines = [f"port-security {interface} clear-intrusion-flag"] if brief[0]["intrusion"] else []
        return cli_plan([*lines, f"interface {interface} enable"])

    # --- Configuration files, restore, reload -----------------
    # ``transfer_method = "sftp"`` and ``sftp_port_22_only`` come from ``AossDeviceMixin``.

    def _show_config(self, session: transport.SshSession, command: str) -> str:
        """Full configuration with at least the save timeout; the ``Running/Startup configuration:``
        header is dropped, so a backup is a loadable configuration file."""
        conn = session.conn
        previous = conn.read_timeout_override
        conn.read_timeout_override = max(previous or 0, transport.SAVE_CONFIG_MIN_TIMEOUT_SECONDS)
        try:
            output = self._show(session, command)
        finally:
            conn.read_timeout_override = previous
        return re.sub(r"\A\s*(?:Running|Startup) configuration:\s*\n", "", output, flags=re.IGNORECASE).lstrip("\n")

    def read_running_config(self, session: transport.SshSession) -> str:
        return self._show_config(session, "show running-config")

    def read_startup_config(self, session: transport.SshSession) -> str:
        return self._show_config(session, "show config")

    def plan_reload(self, session: transport.SshSession) -> ChangePlan:
        """``reload``: the save question is answered "n", the reboot question "y"; the session drops."""
        step = CliCommand(
            "reload", prompts=(SAVE_NO, REBOOT_YES), timeout=RELOAD_TIMEOUT_SECONDS, expect_disconnect=True,
        )
        return ChangePlan(lines=(step.command,), steps=(step,), reloads=True)

    def plan_config_restore(self, session: transport.SshSession, transfer: TransferLocation) -> ChangePlan:
        """``copy sftp startup-config {user}@{host} {file}``; after "Device will be rebooted…" → ``y``
        the switch restarts by itself (no separate reload step)."""
        from ...transfer import location_secrets

        step = CliCommand(
            f"copy sftp startup-config {transfer.username}@{transfer.host} {transfer.filename}",
            prompts=(HOST_KEY_YES, (r"(?i)password:", transfer.password), SAVE_NO, REBOOT_YES),
            timeout=COPY_TIMEOUT_SECONDS,
            expect_disconnect=True,
        )
        line = f"copy sftp startup-config {REDACTED}@{transfer.host} {transfer.filename}"
        return ChangePlan(lines=(line,), steps=(step,), reloads=True, secrets=location_secrets(transfer))

    # --- Port security ---------------------------------------------

    def read_port_security(self, session: transport.SshSession) -> dict:
        config = self._security(session)
        ports = [row["port"] for row in self._brief(session)]
        ports += sorted(set(self._running_config(session).lag_members.values()))
        return {"global": config.global_settings(), "ports": {port: config.port(port) for port in ports}}

    def plan_port_security(
        self, session: transport.SshSession, interface: str, change: SecurityChange, detail: dict,
    ) -> ChangePlan:
        interface = self.validate_interface(interface)
        config = self._security(session)
        lines = l2.port_security_lines(
            interface, change, config, detail.get("mode"), set(self._running_config(session).vlans),
        )
        return cli_plan(lines) if lines else ChangePlan(lines=(), steps=())

    def plan_security_global(self, session: transport.SshSession, change: SecurityGlobalChange) -> ChangePlan:
        config = self._security(session, fresh=True)
        lines = l2.security_global_lines(change, config, set(self._running_config(session).vlans))
        return cli_plan(lines) if lines else ChangePlan(lines=(), steps=())

    # --- Link aggregation -------------------------------------------

    max_lag_id = 60

    def lag_interface_name(self, lag_id: int) -> str:
        return f"Trk{int(lag_id)}"

    def read_lags(self, session: transport.SshSession) -> list[dict]:
        """``show trunks`` (members, type) and ``show lacp`` (LACP mode and member state)."""
        trunks = l2.parse_trunks(self._show(session, "show trunks", allow_empty=True))
        lacp = {}
        if any(kind.casefold() == "lacp" for _lag, kind in trunks.values()):
            lacp = l2.parse_lacp(self._optional(session, "show lacp")[0] or "")
        links = {}
        if any(kind.casefold() != "lacp" for _lag, kind in trunks.values()):
            brief_out, _status = self._optional(session, "show interfaces brief")
            links = {row["port"]: row["link"] for row in parse_interfaces_brief(brief_out or "")}
        lags: dict[str, dict] = {}
        for port, (name, kind) in sorted(trunks.items(), key=lambda item: l2.port_sort_key(item[0])):
            lag = lags.setdefault(name, {
                "id": int(name[3:]), "interface": name, "mode": "static", "members": [], "status": "down",
            })
            if kind.casefold() == "lacp":
                row = lacp.get(port)
                passive = row is not None and row["enabled"] == "passive"
                lag["mode"] = "lacp_passive" if passive else "lacp_active"
                state = l2.lacp_member_state(row)
            else:
                state = {"up": "bundled", "down": "down"}.get(links.get(port))
            lag["members"].append({"interface": port, "state": state})
            if state == "bundled":
                lag["status"] = "up"
        return [lags[name] for name in sorted(lags, key=lambda name: int(name[3:]))]

    def _lag_id(self, lag_id: int) -> int:
        lag_id = int(lag_id)
        if not 1 <= lag_id <= self.max_lag_id:
            raise InvalidInputError(t("LAG-ID außerhalb des gültigen Bereichs 1-{max}: {value}",
                                      max=self.max_lag_id, value=lag_id))
        return lag_id

    def _member_lines(self, lag_id: int, mode: str, members) -> list[str]:
        if mode not in l2.LAG_TYPES:
            raise InvalidInputError(t(UNSUPPORTED_VALUE, value=mode))
        ports = l2.compact_ports(self.validate_interface(member) for member in members)
        lines = [f"trunk {ports} trk{lag_id} {l2.LAG_TYPES[mode]}"]
        if mode == "lacp_passive":
            lines.append(f"interface {ports} lacp passive")
        return lines

    def _lag(self, session: transport.SshSession, lag_id: int) -> dict:
        lag = next((lag for lag in self.read_lags(session) if lag["id"] == lag_id), None)
        if lag is None:
            raise InvalidInputError(t("LAG {lag} existiert auf dem Switch nicht.", lag=lag_id))
        return lag

    def plan_lag_create(
        self, session: transport.SshSession, lag_id: int, mode: str, members: tuple[str, ...],
    ) -> ChangePlan:
        """``trunk {ports} trkN trunk|lacp``; members take over the VLAN/STP settings of ``TrkN``."""
        return cli_plan(self._member_lines(self._lag_id(lag_id), mode, members))

    def plan_lag_update(
        self, session: transport.SshSession, lag_id: int, add: tuple[str, ...], remove: tuple[str, ...],
    ) -> ChangePlan:
        lag = self._lag(session, self._lag_id(lag_id))
        lines = self._member_lines(lag["id"], lag["mode"] or "static", add) if add else []
        if remove:
            lines.append(f"no trunk {l2.compact_ports(self.validate_interface(member) for member in remove)}")
        return cli_plan(lines) if lines else ChangePlan(lines=(), steps=())

    def plan_lag_delete(self, session: transport.SshSession, lag_id: int) -> ChangePlan:
        """The LAG disappears with its last member."""
        lag = self._lag(session, self._lag_id(lag_id))
        return cli_plan([f"no trunk {l2.compact_ports(member['interface'] for member in lag['members'])}"])

    # --- Spanning tree ----------------------------------------------

    def read_stp(self, session: transport.SshSession) -> dict:
        stp = l2.parse_stp_config(self._security(session))
        output, _status = self._optional(session, "show spanning-tree")
        instance = 0 if stp["mode"] == "mstp" else None
        return {
            "mode": stp["mode"],
            "priority": l2.stp_priorities(stp),
            "mst": l2.stp_mst(stp) if stp["mode"] == "mstp" else None,
            "roots": l2.parse_stp_root(output or "", instance),
            "ports": l2.parse_stp_ports(output or "", instance),
        }

    def plan_stp_mode(self, session: transport.SshSession, mode: str) -> ChangePlan:
        if mode not in l2.STP_MODES:
            raise InvalidInputError(t(UNSUPPORTED_VALUE, value=mode))
        stp = l2.parse_stp_config(self._security(session, fresh=True))
        return cli_plan([*([] if stp["enabled"] else ["spanning-tree"]), f"spanning-tree mode {l2.STP_MODES[mode]}"])

    def plan_stp_priority(
        self, session: transport.SshSession, priority: int, vlans: tuple[int, ...] | None, instance: int | None,
    ) -> ChangePlan:
        """Absolute priorities become AOS-S multipliers (32768 -> 8)."""
        multiplier = bridge_multiplier(priority)
        if instance is not None:
            instance = int(instance)
            if instance == 0:
                return cli_plan([f"spanning-tree priority {multiplier}"])
            return cli_plan([f"spanning-tree instance {instance} priority {multiplier}"])
        if not vlans:
            raise InvalidInputError(t("Bitte entweder VLANs oder eine Instanz angeben."))
        stp = l2.parse_stp_config(self._security(session, fresh=True))
        lines = []
        for vlan in sorted({validate_vlan_id(vlan) for vlan in vlans}):
            if vlan not in stp["rpvst_vlans"]:
                lines.append(f"spanning-tree vlan {vlan}")
            lines.append(f"spanning-tree vlan {vlan} priority {multiplier}")
        return cli_plan(lines)

    def plan_stp_mst(
        self, session: transport.SshSession, name: str, revision: int,
        instances: tuple[tuple[int, tuple[int, ...]], ...],
    ) -> ChangePlan:
        stp = l2.parse_stp_config(self._security(session, fresh=True))
        lines = l2.mst_lines(name, revision, instances, stp)
        return cli_plan(lines) if lines else ChangePlan(lines=(), steps=())

    def plan_stp_port(
        self, session: transport.SshSession, interface: str, instance_or_vlan: int | None, cost: int | None,
        priority: int | None,
    ) -> ChangePlan:
        interface = self.validate_interface(interface)
        if cost is not None and not 1 <= int(cost) <= 200000000:
            raise InvalidInputError(t(UNSUPPORTED_VALUE, value=cost))
        multiplier = port_multiplier(priority) if priority is not None else None
        mode = l2.parse_stp_config(self._security(session, fresh=True))["mode"]
        if mode == "rapid_pvst" and instance_or_vlan is not None:
            prefix = f"spanning-tree vlan {validate_vlan_id(instance_or_vlan)} {interface}"
        elif mode == "mstp" and instance_or_vlan:
            prefix = f"spanning-tree instance {int(instance_or_vlan)} {interface}"
        else:
            prefix = f"spanning-tree {interface}"
        lines = []
        if cost is not None:
            lines.append(f"{prefix} path-cost {int(cost)}")
        if multiplier is not None:
            lines.append(f"{prefix} priority {multiplier}")
        return cli_plan(lines) if lines else ChangePlan(lines=(), steps=())


def _description(value: str) -> str:
    text = sanitize_description(value, DESCRIPTION_MAX_LENGTH)
    if '"' in text:
        raise InvalidInputError(t("Die Description darf keine Anführungszeichen enthalten."))
    return text


def _require_vlans(vlans, existing: list[int] | None) -> None:
    """Port writes never create VLANs: every target VLAN must already exist (checked before the first write)."""
    known = set(existing or ())
    for vlan in sorted(set(vlans)):
        if vlan not in known:
            raise InvalidInputError(t("VLAN {vlan} existiert auf dem Switch nicht.", vlan=vlan))


def vlan_commands(interface: str, change: PortChange, state: dict) -> list[str]:
    """Membership commands for the requested access/trunk state (never the word ``trunk``).

    The voice VLAN of an access port is a tagged membership (``vlan V tagged P``); it is kept
    when only the data VLAN changes and removed with ``voice_vlan=0``.
    """
    untagged = list(state.get("untagged") or ())
    tagged = set(state.get("tagged") or ())
    current_mode = state.get("mode")
    mode = change.mode
    trunk_fields = change.native_vlan is not None or change.trunk_allowed_vlans is not None
    if mode is None:
        if change.access_vlan is not None or change.voice_vlan is not None:
            if current_mode == "trunk":
                raise InvalidInputError(t(
                    "Ein Access-VLAN kann nur im Access-Modus gesetzt werden." if change.access_vlan is not None
                    else VOICE_ACCESS_ONLY
                ))
            mode = "access"
        elif trunk_fields:
            if current_mode != "trunk":
                raise InvalidInputError(t("Native-VLAN und erlaubte VLANs können nur im Trunk-Modus gesetzt werden."))
            mode = "trunk"
        else:
            return []
    existing = state.get("existing_vlans")

    if mode == "access":
        vlan = change.access_vlan if change.access_vlan is not None else (untagged[0] if untagged else None)
        if vlan is None:
            raise InvalidInputError(t("Für den Access-Modus wird ein Access-VLAN benötigt."))
        vlan = validate_vlan_id(vlan)
        voice = state.get("voice_vlan") if change.voice_vlan is None else (change.voice_vlan or None)
        if voice is not None:
            voice = validate_vlan_id(voice)
            if voice == vlan:
                raise InvalidInputError(t(VOICE_EQUALS_DATA))
        _require_vlans([vlan, *([voice] if voice else [])], existing)
        commands = [] if vlan in untagged else [f"vlan {vlan} untagged {interface}"]
        if voice is not None and voice not in tagged:
            commands.append(f"vlan {voice} tagged {interface}")
        # 'vlan N untagged' also converts a tagged membership in N; all other tags are removed.
        commands.extend(f"no vlan {other} tagged {interface}" for other in sorted(tagged - {vlan, voice}))
        return commands

    if change.voice_vlan:
        raise InvalidInputError(t(VOICE_ACCESS_ONLY))

    native = validate_vlan_id(change.native_vlan) if change.native_vlan is not None else (
        untagged[0] if untagged else None
    )
    selection = change.trunk_allowed_vlans
    if selection is None:
        wanted = set(tagged)
    elif selection == "all":
        wanted = set(existing or ())
    elif selection == "none":
        wanted = set()
    else:
        wanted = {validate_vlan_id(vlan) for vlan in selection}
    wanted.discard(native)
    _require_vlans([*wanted, *([native] if change.native_vlan is not None else [])], existing)
    commands = []
    if change.native_vlan is not None and native not in untagged:
        commands.append(f"vlan {native} untagged {interface}")
    commands.extend(f"vlan {vlan} tagged {interface}" for vlan in sorted(wanted - tagged))
    commands.extend(f"no vlan {vlan} tagged {interface}" for vlan in sorted(tagged - wanted - {native}))
    return commands
