"""Netgear running-configuration model, port security, link aggregation and spanning tree:
parsers and command lines without device access.

Two 802.1X command families exist: M4250/M4350 (firmware 13.x/14.x, "AV") use the
authentication manager (``authentication port-control``, ``mab``, ``authentication host-mode``),
M4300/M5300/M7100 the legacy ``dot1x port-control`` commands. The running configuration
omits default settings, so absent lines mean "default".
"""

import re
from dataclasses import dataclass

from ...i18n import t
from ..errors import InvalidInputError
from ..validation import format_vlan_list, parse_vlan_list, validate_vlan_id, vlan_ranges
from .cli import parse_key_values
from .plans import SecurityChange, SecurityGlobalChange

UNSUPPORTED_VALUE = "Diese Einstellung wird vom Switch nicht unterstützt: {value}"
PORT_SECURITY_TRUNK = "Port-Security ist nur an Access-Ports möglich."
GUARDS_EXCLUSIVE = "Root Guard und Loop Guard schließen sich an einem Port aus."
MULTI_HOST_MAB = "Multi-Host ist bei diesem Switch nur mit 802.1X ohne MAB möglich."
MAX_MST_INSTANCES = "Diese Plattform unterstützt höchstens {count} MST-Instanzen."

FAMILY_AV = "av"  # M4250/M4350: authentication manager
FAMILY_LEGACY = "legacy"  # M4300/M5300/M7100: dot1x port-control

VLAN_COMMAND_MAX_LENGTH = 200
PORT_SECURITY_MAX_DYNAMIC = 4096
STORM_KEYWORDS = {"broadcast": "broadcast", "multicast": "multicast", "unknown_unicast": "unicast"}
AV_HOST_MODES = {"single": "single-host", "multi_auth": "multi-auth", "multi_host": "multi-host"}
STP_MODES = {"stp": "stp", "rstp": "rstp", "mstp": "mst"}
_STP_MODE_NAMES = {"stp": "stp", "rstp": "rstp", "mst": "mstp", "pvst": "pvst", "rapid-pvst": "rapid_pvst"}
DEFAULT_STP_PRIORITY = 32768
MAX_MST_INSTANCE_COUNT = 4
_MST_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,32}")
LAG_RE = re.compile(r"^(?:lag (\d+)|0/3/(\d+))$")
_PORT_ROW_RE = re.compile(r"^\s*(\d+/\d+(?:/\d+)?|lag \d+)\s+(\S+)")
_PORT_NAME_RE = re.compile(r"^(?:\d+/\d+(?:/\d+)?|lag \d+)$", re.IGNORECASE)


def _unsupported(value) -> InvalidInputError:
    return InvalidInputError(t(UNSUPPORTED_VALUE, value=value))


# --- Interface names ---------------------------------------------------------------------


def normalize_interface(name: str) -> str:
    return re.sub(r"\s+", " ", (name or "").strip()).casefold()


def interface_aliases(name: str) -> list[str]:
    """Keys under which the running configuration may list an interface (``lag N`` and ``0/3/N`` for LAGs)."""
    key = normalize_interface(name)
    match = LAG_RE.match(key)
    if not match:
        return [key]
    number = match.group(1) or match.group(2)
    return [key] + [alias for alias in (f"lag {number}", f"0/3/{number}") if alias != key]


def lag_number(name: str) -> int | None:
    match = LAG_RE.match(normalize_interface(name))
    return int(match.group(1) or match.group(2)) if match else None


# --- Running configuration ---------------------------------------------------------------


@dataclass
class NetgearConfig:
    """``top``: lines outside interface blocks; ``interfaces``: interface key -> stripped block lines."""

    top: list[str]
    interfaces: dict[str, list[str]]

    def block(self, name: str) -> list[str]:
        return next((self.interfaces[key] for key in interface_aliases(name) if key in self.interfaces), [])


def parse_config(output: str | None) -> NetgearConfig:
    top: list[str] = []
    blocks: dict[str, list[str]] = {}
    current = None
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("!"):
            continue
        match = re.fullmatch(r"interface\s+(.+)", line, re.IGNORECASE)
        if match:
            current = blocks.setdefault(normalize_interface(match.group(1)), [])
            continue
        if current is None:
            top.append(line)
        elif line.casefold() == "exit":
            current = None
        else:
            current.append(line)
    return NetgearConfig(top, blocks)


def _int_after(lines: list[str], prefix: str) -> int | None:
    pattern = re.compile(rf"{re.escape(prefix)} (\d+)")
    return next((int(m.group(1)) for m in map(pattern.fullmatch, lines) if m), None)


def _rest_after(lines: list[str], prefix: str) -> str | None:
    pattern = re.compile(rf"{re.escape(prefix)} (.+)")
    return next((m.group(1).strip() for m in map(pattern.fullmatch, lines) if m), None)


def _vlans(text: str) -> set[int]:
    try:
        selection = parse_vlan_list(re.sub(r"\s+", "", text))
    except InvalidInputError:
        return set()
    return set(selection) if isinstance(selection, tuple) else set()


def _vlans_after(lines: list[str], prefix: str) -> set[int]:
    pattern = re.compile(rf"{re.escape(prefix)} (\S+)")
    found: set[int] = set()
    for match in map(pattern.fullmatch, lines):
        if match:
            found |= _vlans(match.group(1))
    return found


def vlan_list_lines(prefix: str, vlans, continuation_prefix: str | None = None) -> list[str]:
    """``<prefix><list>`` lines of at most 200 characters; later lines use ``continuation_prefix``."""
    lines = []
    current_prefix = prefix
    chunk = ""
    for item in vlan_ranges(tuple(sorted(vlans))):
        candidate = f"{chunk},{item}" if chunk else item
        if chunk and len(current_prefix) + len(candidate) > VLAN_COMMAND_MAX_LENGTH:
            lines.append(current_prefix + chunk)
            current_prefix = continuation_prefix or prefix
            chunk = item
        else:
            chunk = candidate
    if chunk:
        lines.append(current_prefix + chunk)
    return lines


def _flag(value: bool | None, line: str, current: bool) -> list[str]:
    """``line``/``no line`` for a requested flag; nothing when unchanged or not requested."""
    if value is None or value == current:
        return []
    return [line if value else f"no {line}"]


# --- Port actions -------------------------------------------------------------------


def parse_errdisabled(output: str | None) -> dict[str, str]:
    """``show interfaces status err-disabled``: interface key -> reason."""
    reasons = {}
    for line in (output or "").splitlines():
        match = _PORT_ROW_RE.match(line)
        if match:
            reasons[normalize_interface(match.group(1))] = match.group(2)
    return reasons


# --- Port security --------------------------------------------------------------


def parse_global(config: NetgearConfig) -> dict:
    top = config.top
    return {
        "dhcp_snooping": {
            "enabled": "ip dhcp snooping" in top,
            "vlans": sorted(_vlans_after(top, "ip dhcp snooping vlan")),
        },
        "arp_inspection": {"vlans": sorted(_vlans_after(top, "ip arp inspection vlan"))},
        "dot1x": {"enabled": "dot1x system-auth-control" in top},
    }


def _dot1x_state(lines: list[str], family: str, dot1x_enabled: bool) -> dict:
    """Configured 802.1X state of a port (either command family is recognized)."""
    control = _rest_after(lines, "authentication port-control") or _rest_after(lines, "dot1x port-control")
    if control is None and dot1x_enabled:
        control = "auto"  # default port control of both families
    bypass = "mab" in lines or "dot1x mac-auth-bypass" in lines
    order = (_rest_after(lines, "authentication order") or "").split()
    if control in (None, "force-authorized", "force-unauthorized"):
        mode = "off"
    elif bypass:
        mode = "mab" if order == ["mab"] else "dot1x_mab"
    else:
        mode = "dot1x"
    host_mode = None
    if mode != "off":
        if family == FAMILY_AV:
            word = _rest_after(lines, "authentication host-mode") or "multi-host"
            host_mode = {value: key for key, value in AV_HOST_MODES.items()}.get(word)
            host_mode = host_mode or ("multi_domain" if word.startswith("multi-domain") else None)
        elif control == "mac-based":
            host_mode = "single" if _int_after(lines, "dot1x max-users") == 1 else "multi_auth"
        elif control == "auto":
            host_mode = "multi_host"
    guest = (_int_after(lines, "authentication event no-response action authorize vlan")
             or _int_after(lines, "dot1x guest-vlan"))
    fail = (_int_after(lines, "authentication event fail action authorize vlan")
            or _int_after(lines, "dot1x unauthenticated-vlan"))
    return {"mode": mode, "host_mode": host_mode, "guest_vlan": guest, "auth_fail_vlan": fail,
            "control": control, "bypass": bypass}


def _storm_state(lines: list[str]) -> dict:
    storm = {}
    shutdown = False
    for field, keyword in STORM_KEYWORDS.items():
        level = _int_after(lines, f"storm-control {keyword} level")
        storm[field] = float(level) if level is not None else None
        shutdown = shutdown or f"storm-control {keyword} action shutdown" in lines
    configured = any(value is not None for value in storm.values())
    return {**storm, "action": "shutdown" if shutdown else "drop" if configured else None}


def parse_port(lines: list[str], family: str, dot1x_enabled: bool) -> dict:
    """Security settings of one interface block."""
    enabled = "port-security" in lines
    if "port-security violation shutdown" in lines:
        violation = "shutdown"
    elif "snmp-server enable traps violation" in lines:
        violation = "restrict"
    else:
        violation = "protect" if enabled else None
    dot1x = _dot1x_state(lines, family, dot1x_enabled)
    return {
        "port_security": {
            "enabled": enabled,
            "max_macs": _int_after(lines, "port-security max-dynamic"),
            "sticky": "port-security mac-address sticky" in lines,
            "violation": violation,
            "violation_count": None,
            "secure_macs": None,
        },
        "dot1x": {key: dot1x[key] for key in ("mode", "host_mode", "guest_vlan", "auth_fail_vlan")} | {"status": None},
        # BPDU guard exists only globally (edge ports); per port it is unknown.
        "stp_guard": {
            "bpdu_guard": None,
            "root_guard": "spanning-tree guard root" in lines,
            "loop_guard": "spanning-tree guard loop" in lines,
        },
        "storm_control": _storm_state(lines),
        "dhcp_snooping_trust": "ip dhcp snooping trust" in lines,
        "arp_inspection_trust": "ip arp inspection trust" in lines,
        "ip_source_guard": any(line.startswith("ip verify source") for line in lines),
    }


def _port_security_lines(change, lines: list[str], top: list[str], mode: str | None) -> tuple[list[str], list[str]]:
    before: list[str] = []
    result: list[str] = []
    if change.enabled and mode == "trunk":
        raise InvalidInputError(t(PORT_SECURITY_TRUNK))
    if not change.enabled:
        return before, (["no port-security"] if "port-security" in lines else [])
    if "port-security" not in top:
        before.append("port-security")  # global enable, required
    result.append("port-security")
    if change.max_macs is not None:
        if not 1 <= int(change.max_macs) <= PORT_SECURITY_MAX_DYNAMIC:
            raise _unsupported(change.max_macs)
        result.append(f"port-security max-dynamic {int(change.max_macs)}")
    if change.sticky is not None:
        result.append("port-security mac-address sticky" if change.sticky else "no port-security mac-address sticky")
    shutdown = "port-security violation shutdown" in lines
    traps = "snmp-server enable traps violation" in lines
    if change.violation == "shutdown":
        result.append("port-security violation shutdown")
    elif change.violation in ("protect", "restrict"):
        if shutdown:
            result.append("no port-security violation shutdown")
        if change.violation == "restrict":
            result.append("snmp-server enable traps violation")
        elif traps:
            result.append("no snmp-server enable traps violation")
    elif change.violation is not None:
        raise _unsupported(change.violation)
    return before, result


def _dot1x_lines(change, lines: list[str], family: str, dot1x_enabled: bool) -> list[str]:
    current = _dot1x_state(lines, family, dot1x_enabled)
    result: list[str] = []
    if change.mode not in ("off", "dot1x", "mab", "dot1x_mab"):
        raise _unsupported(change.mode)
    if change.host_mode is not None and change.host_mode not in AV_HOST_MODES:
        raise _unsupported(change.host_mode)
    mab = change.mode in ("mab", "dot1x_mab")
    order = {"dot1x": "dot1x", "mab": "mab", "dot1x_mab": "dot1x mab"}.get(change.mode)
    if family == FAMILY_AV:
        if change.mode == "off":
            result.append("authentication port-control force-authorized")
        else:
            result.append("authentication port-control auto")
            result.append("mab" if mab else "no mab")
            result.append(f"authentication order {order}")
            if change.host_mode is not None:
                result.append(f"authentication host-mode {AV_HOST_MODES[change.host_mode]}")
        guest_prefix = "authentication event no-response action authorize vlan"
        fail_prefix = "authentication event fail action authorize vlan"
    else:
        if change.mode == "off":
            result.append("dot1x port-control force-authorized")
        else:
            host = change.host_mode
            if host == "multi_host" and mab:
                raise InvalidInputError(t(MULTI_HOST_MAB))
            if host == "multi_host":
                control = "auto"
            elif host is not None or mab:
                control = "mac-based"
            else:
                control = current["control"] if current["control"] in ("auto", "mac-based") else "auto"
            result.append(f"dot1x port-control {control}")
            if mab:
                result.append("dot1x mac-auth-bypass")
            elif current["bypass"]:
                result.append("no dot1x mac-auth-bypass")
            result.append(f"authentication order {order}")
            if host == "single":
                result.append("dot1x max-users 1")
            elif host == "multi_auth" and _int_after(lines, "dot1x max-users") is not None:
                result.append("no dot1x max-users")
        guest_prefix = "dot1x guest-vlan"
        fail_prefix = "dot1x unauthenticated-vlan"
    for wanted, configured, prefix in (
        (change.guest_vlan, current["guest_vlan"], guest_prefix),
        (change.auth_fail_vlan, current["auth_fail_vlan"], fail_prefix),
    ):
        if wanted:
            result.append(f"{prefix} {validate_vlan_id(wanted)}")
        elif wanted == 0 and configured:
            result.append(f"no {prefix}")
    return result


def _guard_lines(change, lines: list[str]) -> list[str]:
    if change.bpdu_guard is not None:
        raise _unsupported("bpdu_guard")
    if change.root_guard and change.loop_guard:
        raise InvalidInputError(t(GUARDS_EXCLUSIVE))
    root = "spanning-tree guard root" in lines
    loop = "spanning-tree guard loop" in lines
    if change.root_guard:
        return [] if root else ["spanning-tree guard root"]
    if change.loop_guard:
        return [] if loop else ["spanning-tree guard loop"]
    if (change.root_guard is False and root) or (change.loop_guard is False and loop):
        return ["no spanning-tree guard"]
    return []


def _storm_lines(change, lines: list[str]) -> list[str]:
    if change.action not in (None, "drop", "shutdown"):
        raise _unsupported(change.action)
    current = _storm_state(lines)
    result: list[str] = []
    for field, keyword in STORM_KEYWORDS.items():
        value = getattr(change, field)
        if value is not None:
            if value == 0:
                result.append(f"no storm-control {keyword}")
            elif 0 < value <= 100 and float(value).is_integer():
                result.append(f"storm-control {keyword} level {int(value)}")
            else:
                raise _unsupported(value)
        active = value > 0 if value is not None else current[field] is not None
        if change.action is None or not active:
            continue
        has_shutdown = f"storm-control {keyword} action shutdown" in lines
        if change.action == "shutdown" and not has_shutdown:
            result.append(f"storm-control {keyword} action shutdown")
        elif change.action == "drop" and has_shutdown:
            result.append(f"no storm-control {keyword} action")
    return result


def port_security_lines(
    change: SecurityChange, config: NetgearConfig, interface: str, family: str, mode: str | None,
) -> tuple[list[str], list[str]]:
    """``(global lines before the interface block, interface lines)`` for one port."""
    lines = config.block(interface)
    dot1x_enabled = "dot1x system-auth-control" in config.top
    before: list[str] = []
    result: list[str] = []
    if change.port_security is not None:
        extra, port_lines = _port_security_lines(change.port_security, lines, config.top, mode)
        before += extra
        result += port_lines
    if change.dot1x is not None:
        result += _dot1x_lines(change.dot1x, lines, family, dot1x_enabled)
    if change.stp_guard is not None:
        result += _guard_lines(change.stp_guard, lines)
    if change.storm_control is not None:
        result += _storm_lines(change.storm_control, lines)
    result += _flag(change.dhcp_snooping_trust, "ip dhcp snooping trust", "ip dhcp snooping trust" in lines)
    result += _flag(change.arp_inspection_trust, "ip arp inspection trust", "ip arp inspection trust" in lines)
    ipsg = any(line.startswith("ip verify source") for line in lines)
    result += _flag(change.ip_source_guard, "ip verify source", ipsg)
    return before, result


def security_global_lines(change: SecurityGlobalChange, config: NetgearConfig, existing_vlans: set[int]) -> list[str]:
    """DHCP snooping, ARP inspection VLANs (the lists replace the configured ones) and global 802.1X."""
    current = parse_global(config)
    lines: list[str] = []
    if change.dhcp_snooping_enabled is not None and change.dhcp_snooping_enabled != current["dhcp_snooping"]["enabled"]:
        lines.append("ip dhcp snooping" if change.dhcp_snooping_enabled else "no ip dhcp snooping")
    for wanted, configured, prefix in (
        (change.dhcp_snooping_vlans, current["dhcp_snooping"]["vlans"], "ip dhcp snooping vlan "),
        (change.arp_inspection_vlans, current["arp_inspection"]["vlans"], "ip arp inspection vlan "),
    ):
        if wanted is None:
            continue
        wanted = {validate_vlan_id(vlan) for vlan in wanted}
        missing = sorted(wanted - existing_vlans)
        if missing:
            raise InvalidInputError(t("VLAN {vlan} existiert auf dem Switch nicht.", vlan=format_vlan_list(tuple(missing))))
        lines += vlan_list_lines(f"no {prefix}", set(configured) - wanted)
        lines += vlan_list_lines(prefix, wanted - set(configured))
    if change.dot1x_enabled is not None and change.dot1x_enabled != current["dot1x"]["enabled"]:
        if change.dot1x_enabled:
            if "aaa authentication dot1x default radius" not in config.top:
                lines.append("aaa authentication dot1x default radius")
            lines.append("dot1x system-auth-control")
            if "authentication enable" not in config.top:
                lines.append("authentication enable")
        else:
            lines.append("no dot1x system-auth-control")
    return lines


# --- Link aggregation --------------------------------------------------------------


def parse_lag_config(config: NetgearConfig, default_static: bool) -> dict[int, dict]:
    """LAGs with members (``addport``), non-default LAG blocks or a configured name.

    ``port-channel static`` = static, ``no port-channel static`` = LACP, absent = platform default.
    LACP members with ``lacp actor admin state passive`` are passive.
    """
    lags: dict[int, dict] = {}

    def lag(number: int) -> dict:
        return lags.setdefault(number, {"id": number, "members": [], "static": None, "passive": []})

    for key, lines in config.interfaces.items():
        number = lag_number(key)
        if number is not None:
            if lines:
                entry = lag(number)
                if "port-channel static" in lines:
                    entry["static"] = True
                elif "no port-channel static" in lines:
                    entry["static"] = False
            continue
        for line in lines:
            match = re.fullmatch(r"addport (lag \d+|0/3/\d+)", line, re.IGNORECASE)
            if match:
                entry = lag(lag_number(match.group(1)))
                entry["members"].append(key)
                entry["passive"].append("lacp actor admin state passive" in lines)
    for line in config.top:
        match = re.fullmatch(r"port-channel (?:name )?lag (\d+)(?: \S.*)?", line)
        if match:
            lag(int(match.group(1)))
    for entry in lags.values():
        static = default_static if entry["static"] is None else entry["static"]
        if static:
            entry["mode"] = "static"
        else:
            passive = entry["passive"]
            entry["mode"] = "lacp_passive" if passive and all(passive) else "lacp_active"
    return lags


def parse_port_channel(output: str | None) -> tuple[str | None, dict[str, str]]:
    """``show port-channel lag N``: link state ("up"/"down"/None) and member key -> "bundled" | "down"."""
    values = {key.casefold(): value for key, value in parse_key_values(output or "").items()}
    link = (values.get("link state") or "").casefold()
    states = {}
    for match in re.finditer(r"(?m)^\s*(\d+/\d+(?:/\d+)?)\s+\S+\s+\S+\s+(True|False)\s*$", output or ""):
        states[normalize_interface(match.group(1))] = "bundled" if match.group(2) == "True" else "down"
    return ("up" if link == "up" else "down" if link == "down" else None), states


# --- Spanning tree -----------------------------------------------------------------


def parse_stp_config(config: NetgearConfig) -> dict:
    top = config.top
    mode_word = _rest_after(top, "spanning-tree mode")
    stp = {
        "enabled": "no spanning-tree" not in top,
        "mode": _STP_MODE_NAMES.get(mode_word or "rstp"),
        "priority": {},
        "name": _rest_after(top, "spanning-tree configuration name"),
        "revision": _int_after(top, "spanning-tree configuration revision"),
        "instances": {},
        "ports": {},
    }
    for line in top:
        if match := re.fullmatch(r"spanning-tree mst priority (\d+) (\d+)", line):
            stp["priority"][int(match.group(1))] = int(match.group(2))
        elif match := re.fullmatch(r"spanning-tree mst instance (\d+)", line):
            stp["instances"].setdefault(int(match.group(1)), set())
        elif match := re.fullmatch(r"spanning-tree mst vlan (\d+) (\S+)", line):
            stp["instances"].setdefault(int(match.group(1)), set()).update(_vlans(match.group(2)))
    for key, lines in config.interfaces.items():
        for line in lines:
            match = re.fullmatch(r"spanning-tree mst (\d+) (cost|port-priority) (\d+)", line)
            if match:
                port = stp["ports"].setdefault((key, int(match.group(1))), {"cost": None, "priority": None})
                port["cost" if match.group(2) == "cost" else "priority"] = int(match.group(3))
    if stp["name"] and len(stp["name"]) >= 2 and stp["name"][0] == stp["name"][-1] == '"':
        stp["name"] = stp["name"][1:-1]
    return stp


def stp_priorities(stp: dict) -> list[dict]:
    instances = sorted({0} | set(stp["instances"]) | set(stp["priority"]))
    return [{"instance": instance, "priority": stp["priority"].get(instance, DEFAULT_STP_PRIORITY)}
            for instance in instances]


def stp_mst(stp: dict) -> dict:
    return {
        "name": stp["name"],
        "revision": stp["revision"] if stp["revision"] is not None else 0,
        "instances": [{"id": instance, "vlans": format_vlan_list(tuple(sorted(vlans)))}
                      for instance, vlans in sorted(stp["instances"].items())],
    }


def parse_stp_root(output: str | None) -> list[dict]:
    """``show spanning-tree``: CIST root (Designated Root, Root Path Cost, Root Port Identifier)."""
    values = {key.casefold(): value for key, value in parse_key_values(output or "").items()}
    root = values.get("designated root")
    if not root:
        return []
    port = values.get("root port identifier") or ""
    cost = values.get("root path cost") or ""
    bridge = values.get("bridge identifier")
    no_port = not port or re.fullmatch(r"[0:]+", port) is not None
    return [{
        "vlan_or_instance": 0,
        "root_bridge": root,
        "root_port": None if no_port else port,
        "root_cost": int(cost) if cost.isdigit() else None,
        "is_root": (root == bridge) if bridge else no_port,
    }]


def parse_stp_ports(rows: list[dict[str, str]] | None, stp: dict) -> list[dict]:
    """Rows of ``show spanning-tree mst port summary 0 active`` (dashed table) plus configured cost/priority."""
    ports = []
    seen = set()
    for row in rows or []:
        interface = re.sub(r"\s+", " ", next(
            (value for name, value in row.items() if name.startswith(("interface", "intf"))), "",
        ))
        if not _PORT_NAME_RE.match(interface):
            continue
        key = normalize_interface(interface)
        config = stp["ports"].get((key, 0), {})
        role = next((value for name, value in row.items() if "role" in name), "") or None
        state = next((value for name, value in row.items() if name.endswith("state")), "") or None
        ports.append({"interface": interface, "instance_or_vlan": 0, "cost": config.get("cost"),
                      "priority": config.get("priority"), "role": role and role.lower(),
                      "state": state and state.lower()})
        seen.add(key)
    for (key, instance), config in sorted(stp["ports"].items()):
        if instance == 0 and key in seen:
            continue
        ports.append({"interface": key, "instance_or_vlan": instance, "cost": config["cost"],
                      "priority": config["priority"], "role": None, "state": None})
    return ports


def mst_lines(name: str, revision: int, instances, stp: dict, existing_vlans: set[int]) -> list[str]:
    """Region name/revision and the complete instance mapping (unlisted instances are removed)."""
    if not _MST_NAME_RE.fullmatch(name or ""):
        raise _unsupported(name)
    if not 0 <= int(revision) <= 65535:
        raise _unsupported(revision)
    wanted = {int(instance): {validate_vlan_id(vlan) for vlan in vlans} for instance, vlans in instances}
    if len(wanted) > MAX_MST_INSTANCE_COUNT:
        raise InvalidInputError(t(MAX_MST_INSTANCES, count=MAX_MST_INSTANCE_COUNT))
    missing = sorted(set().union(*wanted.values()) - existing_vlans) if wanted else []
    if missing:
        raise InvalidInputError(t("VLAN {vlan} existiert auf dem Switch nicht.", vlan=format_vlan_list(tuple(missing))))
    current = stp["instances"]
    lines = [f"spanning-tree configuration name {name}", f"spanning-tree configuration revision {int(revision)}"]
    for instance in sorted(set(current) - set(wanted)):
        lines.append(f"no spanning-tree mst instance {instance}")
    for instance, vlans in sorted(wanted.items()):
        configured = current.get(instance, set())
        lines += vlan_list_lines(f"no spanning-tree mst vlan {instance} ", configured - vlans)
    for instance, vlans in sorted(wanted.items()):
        configured = current.get(instance)
        if configured is None:
            lines.append(f"spanning-tree mst instance {instance}")
        lines += vlan_list_lines(f"spanning-tree mst vlan {instance} ", vlans - (configured or set()))
    return lines
