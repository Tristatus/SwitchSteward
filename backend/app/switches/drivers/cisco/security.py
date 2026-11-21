"""Cisco port security, 802.1X, STP guards, storm control and DHCP snooping/DAI/IPSG.

Configuration is read from the running configuration (the reliable source on IOS and IOS-XE);
counters and session states come from ``show port-security`` and the authentication sessions.
"""

import re

from ....i18n import t
from ...errors import InvalidInputError
from ...validation import parse_vlan_list, validate_vlan_id, vlan_ranges
from ..plans import SecurityChange, SecurityGlobalChange
from . import parsers

IBNS2_PROBE = "show running-config | include ^policy-map type control subscriber|access-session"
GLOBAL_PROBE = (
    "show running-config | include ^ip dhcp snooping|^ip arp inspection vlan|^dot1x system-auth-control"
    "|^aaa (authentication|authorization|accounting) (dot1x|network)"
)
DOT1X_AAA_LINES = (
    "aaa authentication dot1x default group radius",
    "aaa authorization network default group radius",
    "aaa accounting dot1x default start-stop group radius",
)
GUARDS_EXCLUSIVE = "Root Guard und Loop Guard schließen sich an einem Port aus."
IBNS2_FALLBACK = (
    "Ersatz-VLANs werden bei IBNS-2.0-Konfiguration über Richtlinien gesetzt und sind hier nicht einstellbar."
)
UNSUPPORTED_VALUE = "Diese Einstellung wird vom Switch nicht unterstützt: {value}"

_HOST_MODES = {"single-host": "single", "multi-auth": "multi_auth", "multi-host": "multi_host",
               "multi-domain": "multi_domain"}
_STORM_KEYWORDS = {"broadcast": "broadcast", "multicast": "multicast", "unknown_unicast": "unicast"}
_INTERFACE_LINE = re.compile(r"^interface\s+(\S+)\s*$")


# --- Running configuration --------------------------------------------------------------


def interface_blocks(config: str) -> dict[str, tuple[str, list[str]]]:
    """interface key -> (name, stripped sub-command lines) of every ``interface`` section."""
    blocks: dict[str, tuple[str, list[str]]] = {}
    current = None
    for raw in (config or "").splitlines():
        match = _INTERFACE_LINE.match(raw)
        if match:
            current = []
            blocks[parsers.interface_key(match.group(1))] = (match.group(1), current)
        elif current is not None and raw[:1] == " ":
            current.append(raw.strip())
        elif raw.strip():
            current = None
    return blocks


def _vlan_union(config: str, prefix: str) -> list[int]:
    vlans: set[int] = set()
    for match in re.finditer(rf"^{re.escape(prefix)}\s+(\S+)\s*$", config or "", re.MULTILINE):
        selection = parse_vlan_list(match.group(1))
        if isinstance(selection, tuple):
            vlans.update(selection)
    return sorted(vlans)


def parse_global(config: str) -> dict:
    return {
        "dhcp_snooping": {
            "enabled": bool(re.search(r"^ip dhcp snooping\s*$", config or "", re.MULTILINE)),
            "vlans": _vlan_union(config, "ip dhcp snooping vlan"),
        },
        "arp_inspection": {"vlans": _vlan_union(config, "ip arp inspection vlan")},
        "dot1x": {"enabled": bool(re.search(r"^dot1x system-auth-control\s*$", config or "", re.MULTILINE))},
    }


def _first(lines: list[str], pattern: str) -> re.Match | None:
    compiled = re.compile(pattern)
    return next((match for match in map(compiled.fullmatch, lines) if match), None)


def _guard(lines: list[str]) -> str | None:
    match = _first(lines, r"spanning-tree guard (root|loop)")
    return match.group(1) if match else None


def parse_port(lines: list[str]) -> dict:
    """Security settings of one interface section (``lines`` from ``interface_blocks``)."""
    has = set(lines).__contains__
    enabled = has("switchport port-security")
    maximum = _first(lines, r"switchport port-security maximum (\d+)")
    violation = _first(lines, r"switchport port-security violation (protect|restrict|shutdown)")
    control = _first(lines, r"(?:authentication|access-session) port-control (\S+)")
    dot1x = has("dot1x pae authenticator")
    mab = any(line == "mab" or line.startswith("mab ") for line in lines)
    if control is None or control.group(1) != "auto" or not (dot1x or mab):
        mode = "off"
    else:
        mode = "dot1x_mab" if dot1x and mab else "dot1x" if dot1x else "mab"
    host = _first(lines, r"(?:authentication|access-session) host-mode (\S+)")
    guest = _first(lines, r"authentication event no-response action authorize vlan (\d+)")
    fail = _first(lines, r"authentication event fail(?: retry \d+)? action authorize vlan (\d+)")
    storm = {}
    for field, keyword in _STORM_KEYWORDS.items():
        keywords = f"{keyword}|unknown-unicast" if field == "unknown_unicast" else keyword
        match = _first(lines, rf"storm-control (?:{keywords}) level ([\d.]+)(?: [\d.]+)?")
        storm[field] = float(match.group(1)) if match else None
    if has("storm-control action shutdown"):
        action = "shutdown"
    else:
        action = "drop" if any(value is not None for value in storm.values()) else None
    guard = _guard(lines)
    return {
        "port_security": {
            "enabled": enabled,
            "max_macs": int(maximum.group(1)) if maximum else (1 if enabled else None),
            "sticky": has("switchport port-security mac-address sticky"),
            "violation": violation.group(1) if violation else ("shutdown" if enabled else None),
            "violation_count": None,
            "secure_macs": None,
        },
        "dot1x": {
            "mode": mode,
            "host_mode": _HOST_MODES.get(host.group(1)) if host else ("single" if mode != "off" else None),
            "guest_vlan": int(guest.group(1)) if guest else None,
            "auth_fail_vlan": int(fail.group(1)) if fail else None,
            "status": None,
        },
        "stp_guard": {
            "bpdu_guard": has("spanning-tree bpduguard enable"),
            "root_guard": guard == "root",
            "loop_guard": guard == "loop",
        },
        "storm_control": {**storm, "action": action},
        "dhcp_snooping_trust": has("ip dhcp snooping trust"),
        "arp_inspection_trust": has("ip arp inspection trust"),
        "ip_source_guard": any(line.startswith("ip verify source") for line in lines),
    }


# --- Operational tables -----------------------------------------------------------------


def parse_port_security_summary(output: str) -> dict[str, dict]:
    """``show port-security``: interface key -> {max_macs, secure_macs, violation_count}."""
    result = {}
    for match in re.finditer(r"^\s*(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\S+", output or "", re.MULTILINE):
        name = match.group(1)
        if not parsers.INTERFACE_RE.fullmatch(name):
            continue
        result[parsers.interface_key(name)] = {
            "max_macs": int(match.group(2)),
            "secure_macs": int(match.group(3)),
            "violation_count": int(match.group(4)),
        }
    return result


def parse_session_status(output: str) -> dict[str, str]:
    """Summary of ``show authentication sessions`` / ``show access-session``: interface key -> status."""
    result = {}
    for line in (output or "").splitlines():
        columns = line.split()
        if len(columns) < 5 or not parsers.INTERFACE_RE.fullmatch(columns[0]) or not re.fullmatch(
            r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}", columns[1],
        ):
            continue
        # Interface MAC Method Domain Status... Session-ID: the status may contain blanks.
        status = " ".join(columns[4:-1]) if len(columns) > 5 else columns[4]
        result.setdefault(parsers.interface_key(columns[0]), status)
    return result


# --- Plans ------------------------------------------------------------------------------


def _percent(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".")


def _vlan_id(value: int) -> int:
    return validate_vlan_id(value)


def port_security_lines(change: SecurityChange, current: list[str], ibns2: bool, storm_types) -> list[str]:
    """Interface sub-commands of ``change``; ``current`` = the interface section as configured now."""
    lines: list[str] = []
    ps = change.port_security
    if ps is not None:
        if not ps.enabled:
            lines.append("no switchport port-security")
        else:
            lines.append("switchport port-security")
            if ps.max_macs is not None:
                lines.append(f"switchport port-security maximum {int(ps.max_macs)}")
            if ps.sticky is True:
                lines.append("switchport port-security mac-address sticky")
            elif ps.sticky is False:
                lines.append("no switchport port-security mac-address sticky")
            if ps.violation is not None:
                if ps.violation not in ("protect", "restrict", "shutdown"):
                    raise InvalidInputError(t(UNSUPPORTED_VALUE, value=ps.violation))
                lines.append(f"switchport port-security violation {ps.violation}")
    dot1x = change.dot1x
    if dot1x is not None:
        lines.extend(_dot1x_lines(dot1x, ibns2))
    guard = change.stp_guard
    if guard is not None:
        if guard.root_guard and guard.loop_guard:
            raise InvalidInputError(t(GUARDS_EXCLUSIVE))
        if guard.bpdu_guard is True:
            lines.append("spanning-tree bpduguard enable")
        elif guard.bpdu_guard is False:
            lines.append("no spanning-tree bpduguard")
        configured = _guard(current)
        if guard.root_guard:
            lines.append("spanning-tree guard root")
        elif guard.loop_guard:
            lines.append("spanning-tree guard loop")
        elif (guard.root_guard is False and configured == "root") or (guard.loop_guard is False and configured == "loop"):
            lines.append("no spanning-tree guard")
    storm = change.storm_control
    if storm is not None:
        for field, keyword in _STORM_KEYWORDS.items():
            value = getattr(storm, field)
            if value is None:
                continue
            if field not in storm_types:
                raise InvalidInputError(t(UNSUPPORTED_VALUE, value=field))
            if not 0 <= value <= 100:
                raise InvalidInputError(t(UNSUPPORTED_VALUE, value=value))
            lines.append(
                f"no storm-control {keyword} level" if value == 0
                else f"storm-control {keyword} level {_percent(value)}"
            )
        if storm.action == "shutdown":
            lines.append("storm-control action shutdown")
        elif storm.action == "drop" and "storm-control action shutdown" in current:
            lines.append("no storm-control action shutdown")
    for value, command in (
        (change.dhcp_snooping_trust, "ip dhcp snooping trust"),
        (change.arp_inspection_trust, "ip arp inspection trust"),
        (change.ip_source_guard, "ip verify source"),
    ):
        if value is True:
            lines.append(command)
        elif value is False:
            lines.append(f"no {command}")
    return lines


def _dot1x_lines(dot1x, ibns2: bool) -> list[str]:
    session_word = "access-session" if ibns2 else "authentication"
    control = f"{session_word} port-control auto"
    if dot1x.mode == "off":
        lines = [f"no {session_word} port-control", "no dot1x pae authenticator", "no mab"]
        if not ibns2:
            lines += [
                "no authentication order", "no authentication priority", "no authentication host-mode",
                "no authentication event no-response", "no authentication event fail",
            ]
        else:
            lines.append("no access-session host-mode")
        return lines
    if dot1x.mode == "dot1x":
        lines = [control, "dot1x pae authenticator", "no mab"]
        if not ibns2:
            lines.append("authentication order dot1x")
    elif dot1x.mode == "mab":
        lines = [control, "mab", "no dot1x pae authenticator"]
        if not ibns2:
            lines.append("authentication order mab")
    elif dot1x.mode == "dot1x_mab":
        lines = [control, "dot1x pae authenticator", "mab"]
        if not ibns2:
            lines += ["authentication order dot1x mab", "authentication priority dot1x mab"]
    else:
        raise InvalidInputError(t(UNSUPPORTED_VALUE, value=dot1x.mode))
    if dot1x.host_mode is not None:
        host = next((name for name, value in _HOST_MODES.items() if value == dot1x.host_mode), None)
        if host is None:
            raise InvalidInputError(t(UNSUPPORTED_VALUE, value=dot1x.host_mode))
        lines.append(f"{session_word} host-mode {host}")
    if (dot1x.guest_vlan is not None or dot1x.auth_fail_vlan is not None) and ibns2:
        raise InvalidInputError(t(IBNS2_FALLBACK))
    if dot1x.guest_vlan is not None:
        lines.append(
            f"authentication event no-response action authorize vlan {_vlan_id(dot1x.guest_vlan)}"
            if dot1x.guest_vlan else "no authentication event no-response"
        )
    if dot1x.auth_fail_vlan is not None:
        lines.append(
            f"authentication event fail action authorize vlan {_vlan_id(dot1x.auth_fail_vlan)}"
            if dot1x.auth_fail_vlan else "no authentication event fail"
        )
    return lines


def _replace_vlans(command: str, current: list[int], wanted: tuple[int, ...]) -> list[str]:
    wanted_set = {_vlan_id(vlan) for vlan in wanted}
    removed = sorted(set(current) - wanted_set)
    added = sorted(wanted_set - set(current))
    lines = []
    if removed:
        lines.append(f"no {command} {','.join(vlan_ranges(tuple(removed)))}")
    if added:
        lines.append(f"{command} {','.join(vlan_ranges(tuple(added)))}")
    return lines


def global_lines(change: SecurityGlobalChange, config: str) -> list[str]:
    """Global commands for ``change``; ``config`` = output of ``GLOBAL_PROBE``."""
    current = parse_global(config)
    lines: list[str] = []
    if change.dhcp_snooping_enabled is True:
        lines.append("ip dhcp snooping")
    elif change.dhcp_snooping_enabled is False:
        lines.append("no ip dhcp snooping")
    if change.dhcp_snooping_vlans is not None:
        lines += _replace_vlans("ip dhcp snooping vlan", current["dhcp_snooping"]["vlans"], change.dhcp_snooping_vlans)
    if change.arp_inspection_vlans is not None:
        lines += _replace_vlans("ip arp inspection vlan", current["arp_inspection"]["vlans"], change.arp_inspection_vlans)
    if change.dot1x_enabled is True:
        lines += [line for line in DOT1X_AAA_LINES if not re.search(rf"^{re.escape(line)}\s*$", config, re.MULTILINE)]
        lines.append("dot1x system-auth-control")
    elif change.dot1x_enabled is False:
        lines.append("no dot1x system-auth-control")
    return lines
