"""AOS-S port security, link aggregation and spanning tree.

Everything is read from the running configuration, where AOS-S prints the global
one-liners (``port-security 5 …``, ``spanning-tree 5 bpdu-protection``, ``trunk 1-2 trk1 lacp``)
and per-interface blocks (``interface 5`` / ``rate-limit bcast in percent 10``). Writes use the
same global one-liners. Also holds the interface-name helpers shared by the driver and its mixins.
"""

import re

from ...i18n import t
from ..errors import InvalidInputError
from ..validation import format_vlan_list, validate_vlan_id
from .aruba_aoscx_l2 import UNSUPPORTED_VALUE
from .cli import expand_port_list
from .plans import SecurityChange, SecurityGlobalChange

PORT_SECURITY_TRUNK = "Port-Security ist nur an Access-Ports möglich."
SHARED_UNAUTH_VLAN = "AOS-S verwendet ein gemeinsames VLAN für Gäste und fehlgeschlagene Anmeldungen."
UNKNOWN_UNICAST_SHUTDOWN = "AOS-S kann einen Port nur bei Broadcast- oder Multicast-Stürmen abschalten."
MULTI_HOST_DOT1X_ONLY = "Multi-Host ist bei AOS-S nur mit 802.1X ohne MAB möglich."
MISSING_VLAN = "VLAN {vlan} existiert auf dem Switch nicht."

# No silent "protect"; restrict = alarm (intruders are always blocked), shutdown = disable the port.
VIOLATIONS = {"restrict": "send-alarm", "shutdown": "send-disable"}
STICKY_MAX_MACS = 8  # learn-mode static
LIMITED_MAX_MACS = 64  # learn-mode limited-continuous
MULTI_AUTH_CLIENT_LIMIT = 32
# field -> (rate-limit keyword, fault-finder keyword or None)
STORM = {
    "broadcast": ("bcast", "broadcast-storm"),
    "multicast": ("mcast", "multicast-storm"),
    "unknown_unicast": ("unknown-unicast", None),
}
LAG_TYPES = {"static": "trunk", "lacp_active": "lacp", "lacp_passive": "lacp"}
STP_MODES = {"rapid_pvst": "rapid-pvst", "mstp": "mstp"}
DEFAULT_PRIORITY = 32768
DOT1X_ACTIVE = "aaa port-access authenticator active"
DOT1X_RADIUS = "aaa authentication port-access eap-radius"
_MST_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,32}")
_INTERFACE_RE = re.compile(r"^(?:(?:\d{1,2}/)?[A-Z]?\d{1,3}|Trk\d{1,3})$")
_LAG_RE = re.compile(r"^trk\d{1,3}$", re.IGNORECASE)
_PORT_ITEM = re.compile(r"^(.*?)(\d+)$")


# --- Interface names -------------------------------------------------------------------


def canonical_interface(name: str | None) -> str:
    """``trk1`` -> ``Trk1``, ``a1`` -> ``A1``; other text is only stripped/upper-cased."""
    text = (name or "").strip()
    if _LAG_RE.fullmatch(text):
        return "Trk" + text[3:]
    return text.upper()


def is_valid_interface(name: str) -> bool:
    return bool(_INTERFACE_RE.fullmatch(name))


def port_list(text: str) -> list[str] | None:
    """Canonical ports of an AOS-S port list (``1-4,7``, ``trk1``); None when it is not a port list."""
    try:
        ports = [canonical_interface(port) for port in expand_port_list(text)]
    except ValueError:
        return None
    return ports if ports and all(is_valid_interface(port) for port in ports) else None


def port_sort_key(port: str):
    match = _PORT_ITEM.match(port)
    return (match.group(1), int(match.group(2))) if match else (port, 0)


def compact_ports(ports) -> str:
    """``["1", "2", "5"]`` -> ``1-2,5``; ranges only within one prefix (``A1-A4``, ``1/1-1/4``)."""
    items = sorted({canonical_interface(port) for port in ports}, key=port_sort_key)
    groups: list[list] = []
    for port in items:
        prefix, number = port_sort_key(port)
        if groups and groups[-1][0] == prefix and groups[-1][2] == number - 1 and _PORT_ITEM.match(port):
            groups[-1][2] = number
        else:
            groups.append([prefix, number, number, port])
    return ",".join(
        group[3] if group[1] == group[2] else f"{group[0]}{group[1]}-{group[0]}{group[2]}" for group in groups
    )


# --- Running configuration -------------------------------------------------------------------


def config_blocks(text: str) -> tuple[list[str], dict[str, list[str]]]:
    """Top-level lines (block headers excluded) and the lines of every ``interface X`` block."""
    top: list[str] = []
    interfaces: dict[str, list[str]] = {}
    current: list[str] | None = None
    for raw in (text or "").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith(";"):
            continue
        if not raw[:1].isspace():
            current = None
            if match := re.fullmatch(r"interface (\S+)", stripped):
                current = interfaces.setdefault(canonical_interface(match.group(1)), [])
            elif not re.fullmatch(r"vlan \d{1,4}", stripped):
                top.append(stripped)
            continue
        if current is not None and stripped != "exit":
            current.append(stripped)
    return top, interfaces


def vlan_set(text: str) -> set[int]:
    """VLAN list such as ``10,20-30`` or ``10 20-30``."""
    vlans: set[int] = set()
    for item in re.findall(r"\d+(?:-\d+)?", text or ""):
        first, _sep, last = item.partition("-")
        vlans.update(vlan for vlan in range(int(first), int(last or first) + 1) if 1 <= vlan <= 4094)
    return vlans


def _pairs(tokens: list[str]) -> dict[str, str]:
    return {tokens[index]: tokens[index + 1] for index in range(len(tokens) - 1)}


class SecurityConfig:
    """Security, LAG and spanning-tree settings parsed from the running configuration."""

    def __init__(self, text: str):
        self.top, self.interfaces = config_blocks(text)
        self.port_security: dict[str, dict] = {}
        self.dot1x_ports: set[str] = set()
        self.mab_ports: set[str] = set()
        self.client_limit: dict[str, int] = {}
        self.addr_limit: dict[str, int] = {}
        self.unauth_vid: dict[str, int] = {}
        self.stp_flags: dict[str, set[str]] = {}
        self.stp_port_values: dict[str, dict[str, int]] = {}
        self.fault_finder: dict[str, set[str]] = {}  # port -> {"broadcast-storm", ...} with warn-and-disable
        self.dhcp_trust: set[str] = set()
        self.arp_trust: set[str] = set()
        self.source_lockdown: set[str] = set()
        self.dhcp_snooping = False
        self.dhcp_vlans: set[int] = set()
        self.arp_protect = False
        self.arp_vlans: set[int] = set()
        self.dot1x_active = DOT1X_ACTIVE in self.top
        self.eap_radius = any(line.startswith(DOT1X_RADIUS) for line in self.top)
        for line in self.top:
            self._top_line(line)
        for port, lines in self.interfaces.items():
            if "dhcp-snooping trust" in lines:
                self.dhcp_trust.add(port)
            if "arp-protect trust" in lines:
                self.arp_trust.add(port)

    def _top_line(self, line: str) -> None:
        tokens = line.split()
        if match := re.fullmatch(r"port-security (\S+) (.+)", line):
            ports = port_list(match.group(1))
            values = _pairs(match.group(2).split())
            for port in ports or ():
                entry = self.port_security.setdefault(port, {})
                if "learn-mode" in values:
                    entry["learn_mode"] = values["learn-mode"]
                if values.get("address-limit", "").isdigit():
                    entry["address_limit"] = int(values["address-limit"])
                if "action" in values:
                    entry["action"] = values["action"]
        elif match := re.fullmatch(r"aaa port-access (authenticator|mac-based) (\S+)(?: (.+))?", line):
            ports = port_list(match.group(2))
            if not ports:
                return
            dot1x = match.group(1) == "authenticator"
            values = _pairs((match.group(3) or "").split())
            for port in ports:
                if match.group(3) is None:
                    (self.dot1x_ports if dot1x else self.mab_ports).add(port)
                limit = values.get("client-limit" if dot1x else "addr-limit", "")
                if limit.isdigit():
                    (self.client_limit if dot1x else self.addr_limit)[port] = int(limit)
                if values.get("unauth-vid", "").isdigit():
                    self.unauth_vid[port] = int(values["unauth-vid"])
        elif len(tokens) >= 3 and tokens[0] == "spanning-tree" and (ports := port_list(tokens[1])):
            values = _pairs(tokens[2:])
            for port in ports:
                self.stp_flags.setdefault(port, set()).update(tokens[2:])
                for key in ("path-cost", "priority"):
                    if values.get(key, "").isdigit():
                        self.stp_port_values.setdefault(port, {})[key] = int(values[key])
        elif match := re.fullmatch(r"fault-finder (broadcast-storm|multicast-storm) (\S+) .*\bwarn-and-disable\b.*", line):
            for port in port_list(match.group(2)) or ():
                self.fault_finder.setdefault(port, set()).add(match.group(1))
        elif line == "dhcp-snooping":
            self.dhcp_snooping = True
        elif match := re.fullmatch(r"dhcp-snooping vlan (.+)", line):
            self.dhcp_vlans |= vlan_set(match.group(1))
        elif match := re.fullmatch(r"dhcp-snooping trust (\S+)", line):
            self.dhcp_trust.update(port_list(match.group(1)) or ())
        elif line == "arp-protect":
            self.arp_protect = True
        elif match := re.fullmatch(r"arp-protect vlan (.+)", line):
            self.arp_vlans |= vlan_set(match.group(1))
        elif match := re.fullmatch(r"arp-protect trust (\S+)", line):
            self.arp_trust.update(port_list(match.group(1)) or ())
        elif match := re.fullmatch(r"ip source-lockdown (\S+)", line):
            self.source_lockdown.update(port_list(match.group(1)) or ())

    # --- Per-port views -------------------------------------------------------------------

    def storm_levels(self, port: str) -> dict[str, float | None]:
        levels = dict.fromkeys(STORM)
        keywords = {keyword: field for field, (keyword, _ff) in STORM.items()}
        for line in self.interfaces.get(port, []):
            match = re.fullmatch(r"rate-limit (bcast|mcast|unknown-unicast) in percent (\d+(?:\.\d+)?)", line)
            if match:
                levels[keywords[match.group(1)]] = float(match.group(2))
        return levels

    def port(self, port: str) -> dict:
        """Port security data model of one port."""
        security = self.port_security.get(port, {})
        learn = security.get("learn_mode")
        enabled = learn in ("static", "configured", "limited-continuous")
        dot1x, mab = port in self.dot1x_ports, port in self.mab_ports
        mode = "dot1x_mab" if dot1x and mab else "dot1x" if dot1x else "mab" if mab else "off"
        limit = self.client_limit.get(port) if dot1x else self.addr_limit.get(port)
        if mode == "off":
            host_mode = None
        elif limit is None:
            host_mode = "multi_host" if dot1x and not mab else None
        else:
            host_mode = "single" if limit == 1 else "multi_auth"
        vid = self.unauth_vid.get(port) if mode != "off" else None
        flags = self.stp_flags.get(port, set())
        levels = self.storm_levels(port)
        if self.fault_finder.get(port):
            action = "shutdown"
        elif any(value is not None for value in levels.values()):
            action = "drop"
        else:
            action = None
        return {
            "port_security": {
                "enabled": enabled,
                "max_macs": security.get("address_limit", 1) if enabled else None,
                "sticky": learn == "static",
                "violation": ("shutdown" if security.get("action") == "send-disable" else "restrict") if enabled
                else None,
                "violation_count": None,
                "secure_macs": None,
            },
            "dot1x": {
                "mode": mode,
                "host_mode": host_mode,
                # One unauth-vid for guests and failed authentications.
                "guest_vlan": vid,
                "auth_fail_vlan": vid,
                "status": None,
            },
            "stp_guard": {
                "bpdu_guard": "bpdu-protection" in flags,
                "root_guard": "root-guard" in flags,
                "loop_guard": "loop-guard" in flags,
            },
            "storm_control": {**levels, "action": action},
            "dhcp_snooping_trust": port in self.dhcp_trust,
            "arp_inspection_trust": port in self.arp_trust,
            "ip_source_guard": port in self.source_lockdown,
        }

    def global_settings(self) -> dict:
        return {
            "dhcp_snooping": {"enabled": self.dhcp_snooping, "vlans": sorted(self.dhcp_vlans)},
            "arp_inspection": {"vlans": sorted(self.arp_vlans)},
            "dot1x": {"enabled": self.dot1x_active},
        }


# --- Port security writes -------------------------------------------------------------


def _unsupported(value) -> InvalidInputError:
    return InvalidInputError(t(UNSUPPORTED_VALUE, value=value))


def _flag(value: bool | None, line: str) -> list[str]:
    if value is None:
        return []
    return [line if value else f"no {line}"]


def _require_vlan(vlan: int, existing_vlans: set[int]) -> int:
    vlan = validate_vlan_id(vlan)
    if vlan not in existing_vlans:
        raise InvalidInputError(t(MISSING_VLAN, vlan=vlan))
    return vlan


def _port_security_lines(port: str, change, current: dict, mode: str | None) -> list[str]:
    if change.enabled and mode == "trunk":
        raise InvalidInputError(t(PORT_SECURITY_TRUNK))
    if not change.enabled:
        return [f"port-security {port} learn-mode continuous"]
    if change.violation is not None and change.violation not in VIOLATIONS:
        raise _unsupported(change.violation)
    enabled = current.get("learn_mode") in ("static", "configured", "limited-continuous")
    sticky = change.sticky if change.sticky is not None else (enabled and current.get("learn_mode") == "static")
    limit = change.max_macs or (current.get("address_limit") if enabled else None) or 1
    if not 1 <= limit <= (STICKY_MAX_MACS if sticky else LIMITED_MAX_MACS):
        raise _unsupported(limit)
    action = VIOLATIONS[change.violation] if change.violation else current.get("action")
    line = f"port-security {port} learn-mode {'static' if sticky else 'limited-continuous'} address-limit {limit}"
    return [line + (f" action {action}" if action else "")]


def _dot1x_lines(port: str, change, config: SecurityConfig, existing_vlans: set[int]) -> list[str]:
    has_dot1x, has_mab = port in config.dot1x_ports, port in config.mab_ports
    if change.mode == "off":
        return [
            *([f"no aaa port-access authenticator {port}"] if has_dot1x else []),
            *([f"no aaa port-access mac-based {port}"] if has_mab else []),
        ]
    if change.mode not in ("dot1x", "mab", "dot1x_mab"):
        raise _unsupported(change.mode)
    dot1x, mab = change.mode in ("dot1x", "dot1x_mab"), change.mode in ("mab", "dot1x_mab")
    lines = []
    if dot1x and not has_dot1x:
        lines.append(f"aaa port-access authenticator {port}")
    if mab and not has_mab:
        lines.append(f"aaa port-access mac-based {port}")
    if has_dot1x and not dot1x:
        lines.append(f"no aaa port-access authenticator {port}")
    if has_mab and not mab:
        lines.append(f"no aaa port-access mac-based {port}")
    if dot1x and mab:
        lines.append(f"aaa port-access {port} auth-order authenticator mac-based")
    host = change.host_mode
    if host in ("single", "multi_auth"):
        limit = 1 if host == "single" else MULTI_AUTH_CLIENT_LIMIT
        if dot1x:
            lines.append(f"aaa port-access authenticator {port} client-limit {limit}")
        if mab:
            lines.append(f"aaa port-access mac-based {port} addr-limit {limit}")
    elif host == "multi_host":
        if mab:
            raise InvalidInputError(t(MULTI_HOST_DOT1X_ONLY))
        lines.append(f"no aaa port-access authenticator {port} client-limit")
    elif host is not None:
        raise _unsupported(host)
    guest, fail = change.guest_vlan, change.auth_fail_vlan
    current = config.unauth_vid.get(port)
    # The auth-fail VLAN must equal the guest VLAN (or be left empty).
    reference = guest if guest is not None else (current or fail)
    if fail and fail != reference:
        raise InvalidInputError(t(SHARED_UNAUTH_VLAN))
    vid = guest if guest is not None else fail
    if vid:
        vid = _require_vlan(vid, existing_vlans)
        lines += [f"aaa port-access authenticator {port} unauth-vid {vid}"] if dot1x else []
        lines += [f"aaa port-access mac-based {port} unauth-vid {vid}"] if mab else []
    elif vid == 0 and current is not None:
        lines += [f"no aaa port-access authenticator {port} unauth-vid"] if dot1x else []
        lines += [f"no aaa port-access mac-based {port} unauth-vid"] if mab else []
    return lines


def _storm_lines(port: str, change, config: SecurityConfig) -> list[str]:
    if change.action not in (None, "drop", "shutdown"):
        raise _unsupported(change.action)
    if change.action == "shutdown" and change.unknown_unicast:
        raise InvalidInputError(t(UNKNOWN_UNICAST_SHUTDOWN))
    current = config.storm_levels(port)
    configured = config.fault_finder.get(port, set())
    lines = []
    for field, (keyword, _ff) in STORM.items():
        value = getattr(change, field)
        if value is None:
            continue
        if value == 0:
            lines.append(f"no interface {port} rate-limit {keyword} in")
        elif 0 < value <= 100 and float(value).is_integer():
            lines.append(f"interface {port} rate-limit {keyword} in percent {int(value)}")
        else:
            raise _unsupported(value)
    action = change.action or ("shutdown" if configured else "drop")
    # "shutdown" = fault-finder warn-and-disable (broadcast/multicast only; 0 s = until re-enabled).
    for field in ("broadcast", "multicast"):
        _keyword, ff = STORM[field]
        value = getattr(change, field)
        level = value if value is not None else current[field]
        if action == "shutdown" and level:
            if ff not in configured or value is not None:
                lines.append(f"fault-finder {ff} {port} action warn-and-disable 0 percent {int(level)}")
        elif ff in configured:
            lines.append(f"no fault-finder {ff} {port}")
    return lines


def port_security_lines(
    port: str, change: SecurityChange, config: SecurityConfig, mode: str | None, existing_vlans: set[int],
) -> list[str]:
    """Global one-liners for one port."""
    lines: list[str] = []
    if change.port_security is not None:
        lines += _port_security_lines(port, change.port_security, config.port_security.get(port, {}), mode)
    if change.dot1x is not None:
        lines += _dot1x_lines(port, change.dot1x, config, existing_vlans)
    guard = change.stp_guard
    if guard is not None:
        lines += _flag(guard.bpdu_guard, f"spanning-tree {port} bpdu-protection")
        lines += _flag(guard.root_guard, f"spanning-tree {port} root-guard")
        lines += _flag(guard.loop_guard, f"spanning-tree {port} loop-guard")
    if change.storm_control is not None:
        lines += _storm_lines(port, change.storm_control, config)
    lines += _flag(change.dhcp_snooping_trust, f"dhcp-snooping trust {port}")
    lines += _flag(change.arp_inspection_trust, f"arp-protect trust {port}")
    lines += _flag(change.ip_source_guard, f"ip source-lockdown {port}")
    return lines


def security_global_lines(change: SecurityGlobalChange, config: SecurityConfig, existing_vlans: set[int]) -> list[str]:
    """DHCP snooping, ARP protection (VLAN lists replace the configured ones) and 802.1X."""
    lines = []
    if change.dhcp_snooping_enabled is not None:
        lines.append("dhcp-snooping" if change.dhcp_snooping_enabled else "no dhcp-snooping")
    for wanted, configured, keyword in (
        (change.dhcp_snooping_vlans, config.dhcp_vlans, "dhcp-snooping"),
        (change.arp_inspection_vlans, config.arp_vlans, "arp-protect"),
    ):
        if wanted is None:
            continue
        wanted = {_require_vlan(vlan, existing_vlans) for vlan in wanted}
        added, removed = sorted(wanted - configured), sorted(configured - wanted)
        if keyword == "arp-protect" and added and not config.arp_protect:
            lines.append("arp-protect")
        if added:
            lines.append(f"{keyword} vlan {format_vlan_list(tuple(added))}")
        if removed:
            lines.append(f"no {keyword} vlan {format_vlan_list(tuple(removed))}")
    if change.dot1x_enabled is not None:
        if change.dot1x_enabled:
            lines += ([] if config.eap_radius else [DOT1X_RADIUS]) + [DOT1X_ACTIVE]
        else:
            lines.append(f"no {DOT1X_ACTIVE}")
    return lines


# --- Link aggregation ---------------------------------------------------------------------


def parse_trunks(output: str) -> dict[str, tuple[str, str]]:
    """``show trunks``: member port -> (``TrkN``, type ``Trunk``/``LACP``)."""
    members = {}
    for line in (output or "").splitlines():
        match = re.match(r"^\s*(\S+)\s*\|.*\|\s*(Trk\d+)\s+(\S+)", line, re.IGNORECASE)
        if match:
            port = canonical_interface(match.group(1))
            if is_valid_interface(port):
                members[port] = (canonical_interface(match.group(2)), match.group(3))
    return members


def parse_lacp(output: str) -> dict[str, dict]:
    """``show lacp``: ``A1 Active Trk1 Up Yes Success 0 250`` -> port -> {enabled, status, lacp_status}."""
    rows = {}
    for line in (output or "").splitlines():
        match = re.match(r"^\s*(\S+)\s+(Active|Passive)\s+(Trk\d+)\s+(Up|Down)\s+\S+\s+(\S+)", line, re.IGNORECASE)
        if match:
            rows[canonical_interface(match.group(1))] = {
                "enabled": match.group(2).casefold(), "status": match.group(4).casefold(),
                "lacp_status": match.group(5).casefold(),
            }
    return rows


def lacp_member_state(row: dict | None) -> str | None:
    if row is None:
        return None
    if row["status"] == "down":
        return "down"
    return {"success": "bundled", "standby": "standby"}.get(row["lacp_status"], "suspended")


# --- Spanning tree ------------------------------------------------------------------------


def parse_stp_config(config: SecurityConfig) -> dict:
    """Mode, priorities (absolute) and the MST region from the global ``spanning-tree`` lines."""
    result = {
        "enabled": "spanning-tree" in config.top,
        "mode": "mstp",
        "cist_priority": None,
        "instance_priority": {},
        "vlan_priority": {},
        "rpvst_vlans": set(),
        "name": None,
        "revision": None,
        "instances": {},
    }
    for line in config.top:
        if match := re.fullmatch(r"spanning-tree mode (\S+)", line):
            result["mode"] = {"rapid-pvst": "rapid_pvst", "mstp": "mstp"}.get(match.group(1))
        elif match := re.fullmatch(r"spanning-tree priority (\d+)", line):
            result["cist_priority"] = int(match.group(1)) * 4096
        elif match := re.fullmatch(r"spanning-tree instance (\d+) priority (\d+)", line):
            result["instance_priority"][int(match.group(1))] = int(match.group(2)) * 4096
        elif match := re.fullmatch(r"spanning-tree instance (\d+) vlan (.+)", line):
            result["instances"].setdefault(int(match.group(1)), set()).update(vlan_set(match.group(2)))
        elif match := re.fullmatch(r"spanning-tree config-name (.+)", line):
            result["name"] = match.group(1).strip().strip('"')
        elif match := re.fullmatch(r"spanning-tree config-revision (\d+)", line):
            result["revision"] = int(match.group(1))
        elif match := re.fullmatch(r"spanning-tree vlan (\S+) priority (\d+)", line):
            for vlan in vlan_set(match.group(1)):
                result["vlan_priority"][vlan] = int(match.group(2)) * 4096
        elif match := re.fullmatch(r"spanning-tree vlan ([\d,-]+)", line):
            result["rpvst_vlans"] |= vlan_set(match.group(1))
    return result


def stp_priorities(stp: dict) -> list[dict]:
    if stp["mode"] == "rapid_pvst":
        vlans = sorted(stp["rpvst_vlans"] | set(stp["vlan_priority"]))
        return [{"vlan": vlan, "priority": stp["vlan_priority"].get(vlan, DEFAULT_PRIORITY)} for vlan in vlans]
    instances = sorted({0} | set(stp["instances"]) | set(stp["instance_priority"]))
    return [
        {
            "instance": instance,
            "priority": (stp["cist_priority"] if instance == 0 else stp["instance_priority"].get(instance))
            or DEFAULT_PRIORITY,
        }
        for instance in instances
    ]


def stp_mst(stp: dict) -> dict:
    return {
        "name": stp["name"],
        "revision": stp["revision"] or 0,
        "instances": [
            {"id": instance, "vlans": format_vlan_list(tuple(sorted(vlans)))}
            for instance, vlans in sorted(stp["instances"].items())
        ],
    }


def _field(output: str, label: str) -> str | None:
    match = re.search(rf"^\s*{label}\s*:\s*(.*?)\s*$", output or "", re.MULTILINE | re.IGNORECASE)
    return (match.group(1) or None) if match else None


def parse_stp_root(output: str, instance: int | None) -> list[dict]:
    """CST root of ``show spanning-tree`` (``CST Root MAC Address``, ``… Priority``, ``… Path Cost``, ``… Port``)."""
    mac = _field(output, "CST Root MAC Address")
    if mac is None:
        return []
    priority = _field(output, "CST Root Priority")
    cost = _field(output, "CST Root Path Cost")
    port = _field(output, "CST Root Port")
    port = canonical_interface(port) if port and is_valid_interface(canonical_interface(port)) else None
    cost = int(cost) if cost and cost.isdigit() else None
    return [{
        "vlan_or_instance": instance,
        "root_bridge": f"{priority} {mac}" if priority else mac,
        "root_port": port,
        "root_cost": cost,
        "is_root": port is None and cost == 0,
    }]


def parse_stp_ports(output: str, instance: int | None) -> list[dict]:
    """``show spanning-tree`` port rows ``49 SFP+SR | 2000 128 Root Forwarding 001122-334455``."""
    ports = []
    for line in (output or "").splitlines():
        match = re.match(r"^\s*(\S+)\s+\S+\s*\|\s*(\d+|Auto)\s+(\d+)\s+(\S+)\s+(\S+)", line, re.IGNORECASE)
        if not match:
            continue
        port = canonical_interface(match.group(1))
        if not is_valid_interface(port):
            continue
        ports.append({
            "interface": port,
            "instance_or_vlan": instance,
            "cost": int(match.group(2)) if match.group(2).isdigit() else None,
            "priority": int(match.group(3)),
            "role": match.group(4).casefold(),
            "state": match.group(5).casefold(),
        })
    return ports


def mst_lines(name: str, revision: int, instances, stp: dict) -> list[str]:
    """Region name/revision and the complete instance mapping (unlisted instances are removed)."""
    if not _MST_NAME_RE.fullmatch(name or ""):
        raise _unsupported(name)
    revision = int(revision)
    if not 0 <= revision <= 65535:
        raise _unsupported(revision)
    wanted = {int(instance): {validate_vlan_id(vlan) for vlan in vlans} for instance, vlans in instances}
    for instance in wanted:
        if not 1 <= instance <= 64:
            raise _unsupported(instance)
    configured = stp["instances"]
    lines = []
    if stp["name"] != name:
        lines.append(f'spanning-tree config-name "{name}"')
    if stp["revision"] != revision:
        lines.append(f"spanning-tree config-revision {revision}")
    lines += [f"no spanning-tree instance {instance}" for instance in sorted(configured) if instance not in wanted]
    for instance, vlans in sorted(wanted.items()):
        have = configured.get(instance, set())
        removed, added = sorted(have - vlans), sorted(vlans - have)
        if removed:
            lines.append(f"no spanning-tree instance {instance} vlan {format_vlan_list(tuple(removed))}")
        if added:
            lines.append(f"spanning-tree instance {instance} vlan {format_vlan_list(tuple(added))}")
    return lines

