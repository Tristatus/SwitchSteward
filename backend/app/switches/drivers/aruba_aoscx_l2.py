"""AOS-CX port security, link aggregation and spanning tree: parsers and command builders.

Pure functions used by ``aruba_aoscx.ArubaAosCxDriver``. The running configuration is read
with its indentation, so that sub-contexts such as
``port-access port-security`` (with ``client-limit``/``sticky-learn``) are recognised.
"""

import re

from ...i18n import t
from ..errors import InvalidInputError
from ..validation import format_vlan_list, parse_vlan_list, validate_vlan_id
from .plans import SecurityChange, SecurityGlobalChange

UNSUPPORTED_VALUE = "Diese Einstellung wird vom Switch nicht unterstützt: {value}"
PORT_SECURITY_TRUNK = "Port-Security ist nur an Access-Ports möglich."

PORT_SECURITY = "port-access port-security"
DOT1X = "aaa authentication port-access dot1x authenticator"
MAC_AUTH = "aaa authentication port-access mac-auth"
GLOBAL_PORT_SECURITY = "port-access port-security enable"
# Fallback VLANs are port-access roles; one role per VLAN keeps ports independent.
GUEST_ROLE = "SM_GUEST_{vlan}"
AUTHFAIL_ROLE = "SM_AUTHFAIL_{vlan}"
# 6300: client-limit 0-64 (6100/6200: 0-32); "multi_auth" uses the smaller platform maximum.
PORT_SECURITY_MAX_CLIENTS = 64
MULTI_AUTH_CLIENT_LIMIT = 32
STORM_KEYWORDS = {"broadcast": "broadcast", "multicast": "multicast", "unknown_unicast": "unknown-unicast"}
VIOLATION_ACTIONS = {"restrict": "notify", "shutdown": "shutdown"}
HOST_MODES = {"multi_host": "device-mode", "multi_domain": "multi-domain"}
LAG_MODES = {"static": None, "lacp_active": "active", "lacp_passive": "passive"}
STP_MODES = {"rapid_pvst": "rpvst", "mstp": "mstp"}
DEFAULT_PRIORITY = 32768
_MST_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,32}")
_PORT_RE = re.compile(r"^(?:\d+/\d+/\d+|lag\d+)$", re.IGNORECASE)


def _unsupported(value) -> InvalidInputError:
    return InvalidInputError(t(UNSUPPORTED_VALUE, value=value))


# --- Running configuration with indentation -------------------------------------------------


def config_sections(output: str) -> list[tuple[str, list[tuple[int, str]]]]:
    """Top-level lines with their indented sub-lines ``(indent, text)`` (``exit``/``!`` dropped)."""
    sections: list[tuple[str, list[tuple[int, str]]]] = []
    for line in (output or "").splitlines():
        text = line.strip()
        if not text or text.startswith("!") or text == "exit":
            continue
        if not line[0].isspace():
            sections.append((text, []))
        elif sections:
            sections[-1][1].append((len(line) - len(line.lstrip()), text))
    return sections


def _key(name: str) -> str:
    return re.sub(r"\s+", "", name.strip().lower())


def interface_sections(sections) -> dict[str, list[tuple[int, str]]]:
    """``interface …`` sections keyed like ``interface_key`` (``lag 1`` -> ``lag1``)."""
    result: dict[str, list[tuple[int, str]]] = {}
    for header, children in sections:
        match = re.fullmatch(r"interface\s+(.+)", header)
        if match:
            result.setdefault(_key(match.group(1)), []).extend(children)
    return result


def vlan_sections(sections) -> dict[int, list[str]]:
    result: dict[int, list[str]] = {}
    for header, children in sections:
        match = re.fullmatch(r"vlan\s+(\d{1,4})", header)
        if match:
            result.setdefault(int(match.group(1)), []).extend(text for _indent, text in children)
    return result


def top_lines(sections) -> list[str]:
    return [header for header, _children in sections]


def role_vlans(sections) -> dict[str, int]:
    """``port-access role NAME`` -> its ``vlan access`` VLAN."""
    roles = {}
    for header, children in sections:
        match = re.fullmatch(r"port-access role\s+(\S+)", header)
        vlan = next((int(m.group(1)) for _i, text in children if (m := re.fullmatch(r"vlan access (\d+)", text))), None)
        if match and vlan is not None:
            roles[match.group(1)] = vlan
    return roles


def voice_vlans(sections) -> frozenset[int]:
    """VLANs marked ``voice``."""
    return frozenset(vlan for vlan, lines in vlan_sections(sections).items() if "voice" in lines)


def _direct(children) -> list[str]:
    if not children:
        return []
    level = min(indent for indent, _text in children)
    return [text for indent, text in children if indent == level]


def _subcontext(children, header: str) -> list[str] | None:
    """Lines nested below the sub-context ``header`` (None when the sub-context is absent)."""
    for index, (indent, text) in enumerate(children):
        if text == header:
            nested = []
            for sub_indent, sub_text in children[index + 1 :]:
                if sub_indent <= indent:
                    break
                nested.append(sub_text)
            return nested
    return None


def _enabled(children, header: str) -> bool | None:
    """``header enable|disable`` one-liner or ``enable``/``disable`` in the sub-context."""
    direct = _direct(children)
    if f"{header} enable" in direct:
        return True
    if f"{header} disable" in direct:
        return False
    nested = _subcontext(children, header)
    if nested is None:
        return None
    if "disable" in nested:
        return False
    return "enable" in nested or None


def _int_after(lines: list[str], prefix: str) -> int | None:
    pattern = re.compile(rf"{re.escape(prefix)} (\d+)")
    return next((int(m.group(1)) for m in map(pattern.fullmatch, lines) if m), None)


def _word_after(lines: list[str], prefix: str) -> str | None:
    pattern = re.compile(rf"{re.escape(prefix)} (\S+)")
    return next((m.group(1) for m in map(pattern.fullmatch, lines) if m), None)


# --- Port security ------------------------------------------------------------------


def parse_global(sections) -> dict:
    top = top_lines(sections)
    vlans = vlan_sections(sections)
    return {
        "dhcp_snooping": {
            "enabled": "dhcpv4-snooping" in top,
            "vlans": sorted(vlan for vlan, lines in vlans.items() if "dhcpv4-snooping" in lines),
        },
        "arp_inspection": {"vlans": sorted(vlan for vlan, lines in vlans.items() if "arp inspection" in lines)},
        "dot1x": {"enabled": f"{DOT1X} enable" in top},
    }


def parse_port(children, roles: dict[str, int]) -> dict:
    """Security settings of one interface section (``interface_sections``)."""
    direct = _direct(children)
    enabled = _enabled(children, PORT_SECURITY) is True
    nested = _subcontext(children, PORT_SECURITY) or []
    limit = _int_after(nested, "client-limit")
    dot1x = _enabled(children, DOT1X) is True
    mab = _enabled(children, MAC_AUTH) is True
    mode = "dot1x_mab" if dot1x and mab else "dot1x" if dot1x else "mab" if mab else "off"
    auth_mode = _word_after(direct, "aaa authentication port-access auth-mode")
    clients = _int_after(direct, "aaa authentication port-access client-limit")
    if mode == "off":
        host_mode = None
    elif auth_mode == "device-mode":
        host_mode = "multi_host"
    elif auth_mode == "multi-domain":
        host_mode = "multi_domain"
    elif clients is not None:
        host_mode = "single" if clients == 1 else "multi_auth"
    else:
        host_mode = None
    guest = _word_after(direct, "port-access fallback-role")
    fail = _word_after(direct, "aaa authentication port-access reject-role")
    storm = {}
    for field, keyword in STORM_KEYWORDS.items():
        match = next(
            (m for m in (re.fullmatch(rf"rate-limit {keyword} (\d+(?:\.\d+)?) percent", line) for line in direct) if m),
            None,
        )
        storm[field] = float(match.group(1)) if match else None
    return {
        "port_security": {
            "enabled": enabled,
            "max_macs": limit if limit is not None else (1 if enabled else None),
            "sticky": "sticky-learn enable" in nested,
            "violation": "shutdown" if "port-access security violation action shutdown" in direct
            else ("restrict" if enabled else None),
            "violation_count": None,
            "secure_macs": None,
        },
        "dot1x": {
            "mode": mode,
            "host_mode": host_mode,
            "guest_vlan": roles.get(guest) if guest else None,
            "auth_fail_vlan": roles.get(fail) if fail else None,
            "status": None,
        },
        "stp_guard": {
            "bpdu_guard": "spanning-tree bpdu-guard" in direct,
            "root_guard": "spanning-tree root-guard" in direct,
            "loop_guard": "spanning-tree loop-guard" in direct,
        },
        # rate-limit only polices (drops); there is no shutdown action.
        "storm_control": {**storm, "action": "drop" if any(value is not None for value in storm.values()) else None},
        "dhcp_snooping_trust": "dhcpv4-snooping trust" in direct,
        "arp_inspection_trust": "arp inspection trust" in direct,
        "ip_source_guard": "ipv4 source-lockdown" in direct,
    }


def _flag(value: bool | None, line: str) -> list[str]:
    if value is None:
        return []
    return [line if value else f"no {line}"]


def _role(name: str, vlan: int) -> list[str]:
    return [f"port-access role {name}", f"vlan access {vlan}", "exit"]


def port_security_lines(
    change: SecurityChange, children, roles: dict[str, int], *, global_port_security: bool, mode: str | None,
) -> tuple[list[str], list[str]]:
    """``(global lines before the interface, interface lines)`` for one port."""
    before: list[str] = []
    lines: list[str] = []
    direct = _direct(children)
    security = change.port_security
    if security is not None:
        if security.enabled and mode == "trunk":
            raise InvalidInputError(t(PORT_SECURITY_TRUNK))
        if not security.enabled:
            lines.append(f"{PORT_SECURITY} disable")
        else:
            if not global_port_security:
                before.append(GLOBAL_PORT_SECURITY)
            lines.append(f"{PORT_SECURITY} enable")
            sub = []
            if security.max_macs is not None:
                if not 1 <= security.max_macs <= PORT_SECURITY_MAX_CLIENTS:
                    raise _unsupported(security.max_macs)
                sub.append(f"client-limit {security.max_macs}")
            if security.sticky is not None:
                sub.append("sticky-learn enable" if security.sticky else "no sticky-learn enable")
            if sub:
                lines += [PORT_SECURITY, *sub, "exit"]
        if security.violation is not None:
            if security.violation not in VIOLATION_ACTIONS:
                raise _unsupported(security.violation)
            lines.append(f"port-access security violation action {VIOLATION_ACTIONS[security.violation]}")
    dot1x = change.dot1x
    if dot1x is not None:
        if dot1x.mode == "off":
            lines += [f"no {DOT1X}", MAC_AUTH, "disable", "exit"]
        else:
            if dot1x.mode not in ("dot1x", "mab", "dot1x_mab"):
                raise _unsupported(dot1x.mode)
            use_dot1x = dot1x.mode in ("dot1x", "dot1x_mab")
            use_mab = dot1x.mode in ("mab", "dot1x_mab")
            lines.append(f"{DOT1X} {'enable' if use_dot1x else 'disable'}")
            lines += [MAC_AUTH, "enable" if use_mab else "disable", "exit"]
            if dot1x.mode == "dot1x_mab":
                lines.append("aaa authentication port-access auth-precedence dot1x mac-auth")
            if dot1x.host_mode in ("single", "multi_auth"):
                limit = 1 if dot1x.host_mode == "single" else MULTI_AUTH_CLIENT_LIMIT
                lines += ["aaa authentication port-access auth-mode client-mode",
                          f"aaa authentication port-access client-limit {limit}"]
            elif dot1x.host_mode in HOST_MODES:
                lines.append(f"aaa authentication port-access auth-mode {HOST_MODES[dot1x.host_mode]}")
            elif dot1x.host_mode is not None:
                raise _unsupported(dot1x.host_mode)
        if dot1x.guest_vlan:
            name = GUEST_ROLE.format(vlan=validate_vlan_id(dot1x.guest_vlan))
            if roles.get(name) != dot1x.guest_vlan:
                before += _role(name, dot1x.guest_vlan)
            lines.append(f"port-access fallback-role {name}")
        elif dot1x.guest_vlan == 0:
            current = _word_after(direct, "port-access fallback-role")
            if current:
                lines.append(f"no port-access fallback-role {current}")
        if dot1x.auth_fail_vlan:
            name = AUTHFAIL_ROLE.format(vlan=validate_vlan_id(dot1x.auth_fail_vlan))
            if roles.get(name) != dot1x.auth_fail_vlan:
                before += _role(name, dot1x.auth_fail_vlan)
            lines.append(f"aaa authentication port-access reject-role {name}")
        elif dot1x.auth_fail_vlan == 0 and _word_after(direct, "aaa authentication port-access reject-role"):
            lines.append("no aaa authentication port-access reject-role")
    guard = change.stp_guard
    if guard is not None:
        lines += _flag(guard.bpdu_guard, "spanning-tree bpdu-guard")
        lines += _flag(guard.root_guard, "spanning-tree root-guard")
        lines += _flag(guard.loop_guard, "spanning-tree loop-guard")
    storm = change.storm_control
    if storm is not None:
        if storm.action not in (None, "drop"):
            raise _unsupported(storm.action)
        for field, keyword in STORM_KEYWORDS.items():
            value = getattr(storm, field)
            if value is None:
                continue
            if value == 0:
                lines.append(f"no rate-limit {keyword}")
            elif 1 <= value <= 100 and float(value).is_integer():
                lines.append(f"rate-limit {keyword} {int(value)} percent")
            else:
                raise _unsupported(value)
    lines += _flag(change.dhcp_snooping_trust, "dhcpv4-snooping trust")
    lines += _flag(change.arp_inspection_trust, "arp inspection trust")
    lines += _flag(change.ip_source_guard, "ipv4 source-lockdown")
    return before, lines


def security_global_lines(change: SecurityGlobalChange, current: dict, existing_vlans: set[int]) -> list[str]:
    """Global DHCP snooping, ARP inspection (per VLAN, the lists replace the configured ones) and 802.1X."""
    lines = []
    if change.dhcp_snooping_enabled is not None:
        lines.append("dhcpv4-snooping" if change.dhcp_snooping_enabled else "no dhcpv4-snooping")
    for wanted, configured, line in (
        (change.dhcp_snooping_vlans, current["dhcp_snooping"]["vlans"], "dhcpv4-snooping"),
        (change.arp_inspection_vlans, current["arp_inspection"]["vlans"], "arp inspection"),
    ):
        if wanted is None:
            continue
        wanted = {validate_vlan_id(vlan) for vlan in wanted}
        missing = sorted(wanted - existing_vlans)
        if missing:
            raise InvalidInputError(t("VLAN {vlan} existiert auf dem Switch nicht.", vlan=missing[0]))
        for vlan in sorted(wanted ^ set(configured)):
            lines += [f"vlan {vlan}", line if vlan in wanted else f"no {line}", "exit"]
    if change.dot1x_enabled is not None:
        state = "enable" if change.dot1x_enabled else "disable"
        lines += [f"{DOT1X} {state}", MAC_AUTH, state, "exit"]
    return lines


# --- Link aggregation ------------------------------------------------------------------


def parse_lag_config(sections) -> list[dict]:
    """LAGs from ``interface lag N`` sections and the members' ``lag N`` lines."""
    interfaces = interface_sections(sections)
    lags: dict[int, dict] = {}
    for key, children in interfaces.items():
        match = re.fullmatch(r"lag(\d+)", key)
        if match:
            direct = _direct(children)
            lacp = _word_after(direct, "lacp mode")
            mode = {"active": "lacp_active", "passive": "lacp_passive"}.get(lacp, "static")
            lags[int(match.group(1))] = {"id": int(match.group(1)), "mode": mode, "members": []}
    for key, children in interfaces.items():
        lag_id = _int_after(_direct(children), "lag")
        if lag_id is not None and _PORT_RE.match(key):
            lags.setdefault(lag_id, {"id": lag_id, "mode": None, "members": []})["members"].append(key)
    return [lags[lag_id] for lag_id in sorted(lags)]


def parse_lacp_interfaces(output: str) -> dict[str, str | None]:
    """``show lacp interfaces``: member key -> "bundled" | "down" | None (forwarding state)."""
    states = {}
    for line in (output or "").splitlines():
        tokens = line.split()
        if len(tokens) < 3 or not re.fullmatch(r"\d+/\d+/\d+", tokens[0]) or not tokens[1].lower().startswith("lag"):
            continue
        forwarding = tokens[-1].lower()
        states[_key(tokens[0])] = {"up": "bundled", "down": "down", "blocked": "standby"}.get(forwarding)
    return states


def vlan_lines(children) -> list[str]:
    """VLAN configuration lines of a port (carried over to a new LAG)."""
    return [
        text for text in _direct(children)
        if re.match(r"^vlan (?:access|trunk native|trunk allowed) \S", text)
    ]


# --- Spanning tree ---------------------------------------------------------------------


def _id_set(text: str) -> set[int]:
    """Instance/VLAN id list such as ``0,1-3`` (instance 0 allowed)."""
    ids: set[int] = set()
    for item in re.findall(r"\d+(?:-\d+)?", text or ""):
        first, _sep, last = item.partition("-")
        ids.update(range(int(first), int(last or first) + 1))
    return ids


def _vlan_set(text: str) -> set[int]:
    try:
        selection = parse_vlan_list(text.replace(" ", ""))
    except InvalidInputError:
        return set()
    return set(selection) if isinstance(selection, tuple) else set()


def parse_stp_config(sections) -> dict:
    """Mode, priorities and MST region from the global ``spanning-tree`` lines (priorities absolute)."""
    top = top_lines(sections)
    mode_word = _word_after(top, "spanning-tree mode")
    config = {
        "mode": {"rpvst": "rapid_pvst", "mstp": "mstp"}.get(mode_word or "mstp"),
        "cist_priority": None,
        "instance_priority": {},
        "vlan_priority": {},
        "rpvst_vlans": set(),
        "name": _word_after(top, "spanning-tree config-name"),
        "revision": _int_after(top, "spanning-tree config-revision"),
        "instances": {},
    }
    for line in top:
        if match := re.fullmatch(r"spanning-tree priority (\d+)", line):
            config["cist_priority"] = int(match.group(1)) * 4096
        elif match := re.fullmatch(r"spanning-tree instance (\d+) priority (\d+)", line):
            config["instance_priority"][int(match.group(1))] = int(match.group(2)) * 4096
        elif match := re.fullmatch(r"spanning-tree instance (\d+) vlan (\S+)", line):
            config["instances"].setdefault(int(match.group(1)), set()).update(_vlan_set(match.group(2)))
        elif match := re.fullmatch(r"spanning-tree vlan (\S+) priority (\d+)", line):
            for vlan in _vlan_set(match.group(1)):
                config["vlan_priority"][vlan] = int(match.group(2)) * 4096
        elif match := re.fullmatch(r"spanning-tree vlan (\S+)", line):
            config["rpvst_vlans"].update(_vlan_set(match.group(1)))
    if config["name"]:
        config["name"] = config["name"].strip('"')
    return config


def parse_stp_summary(output: str) -> dict:
    """``show spanning-tree summary root``: protocol and the root table."""
    protocol = re.search(r"^\s*Protocol\s*:\s*(\S+)", output or "", re.MULTILINE)
    root_for = re.search(r"^\s*Root bridge for[^:]*:\s*(.*?)\s*$", output or "", re.MULTILINE)
    is_root_for = _id_set(root_for.group(1)) if root_for else None
    roots = []
    for match in re.finditer(
        r"^\s*(\d+)\s+(\d+)\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(\S+)\s*$",
        output or "", re.MULTILINE,
    ):
        port = None if match.group(5).lower() == "n/a" else match.group(5)
        ident, cost = int(match.group(1)), int(match.group(4))
        roots.append({
            "vlan_or_instance": ident,
            "root_bridge": f"{match.group(2)} {match.group(3).lower()}",
            "root_port": port,
            "root_cost": cost,
            "is_root": ident in is_root_for if is_root_for is not None else (port is None and cost == 0),
        })
    mode = {"mstp": "mstp", "rpvst": "rapid_pvst", "rapid-pvst": "rapid_pvst"}.get(
        protocol.group(1).lower(), None,
    ) if protocol else None
    return {"mode": mode, "roots": roots}


def parse_stp_ports(output: str, default_instance: int | None) -> list[dict]:
    """``show spanning-tree``: ``Port Role State Cost Priority`` rows per instance/VLAN section."""
    ports = []
    current = default_instance
    for line in (output or "").splitlines():
        header = re.match(r"^\s*(?:MST|VLAN|Instance ID\s*:?)\s*(\d+)\b", line)
        if header:
            current = int(header.group(1))
            continue
        tokens = line.split()
        if len(tokens) < 5 or not _PORT_RE.match(tokens[0]) or not tokens[3].isdigit() or not tokens[4].isdigit():
            continue
        ports.append({
            "interface": tokens[0],
            "instance_or_vlan": current,
            "cost": int(tokens[3]),
            "priority": int(tokens[4]),
            "role": tokens[1].lower(),
            "state": tokens[2].lower(),
        })
    return ports


def stp_priorities(config: dict, mode: str | None) -> list[dict]:
    if mode == "rapid_pvst":
        vlans = sorted(config["rpvst_vlans"] | set(config["vlan_priority"]))
        return [{"vlan": vlan, "priority": config["vlan_priority"].get(vlan, DEFAULT_PRIORITY)} for vlan in vlans]
    instances = sorted({0} | set(config["instances"]) | set(config["instance_priority"]))
    return [
        {
            "instance": instance,
            "priority": (config["cist_priority"] if instance == 0 else config["instance_priority"].get(instance))
            or DEFAULT_PRIORITY,
        }
        for instance in instances
    ]


def stp_mst(config: dict) -> dict:
    return {
        "name": config["name"],
        "revision": config["revision"] if config["revision"] is not None else 0,
        "instances": [
            {"id": instance, "vlans": format_vlan_list(tuple(sorted(vlans)))}
            for instance, vlans in sorted(config["instances"].items())
        ],
    }


def bridge_multiplier(priority: int) -> int:
    """Absolute bridge priority (0–61440, step 4096) -> AOS-CX multiplier 0–15."""
    priority = int(priority)
    if not 0 <= priority <= 61440 or priority % 4096:
        raise InvalidInputError(t("Die Priorität muss ein Vielfaches von 4096 sein."))
    return priority // 4096


def port_multiplier(priority: int) -> int:
    """Absolute port priority (0–240, step 16) -> AOS-CX multiplier 0–15."""
    priority = int(priority)
    if not 0 <= priority <= 240 or priority % 16:
        raise InvalidInputError(t("Die Port-Priorität muss ein Vielfaches von 16 sein."))
    return priority // 16


def mst_lines(name: str, revision: int, instances, configured: dict[int, set[int]], current: dict) -> list[str]:
    """Region name/revision and the complete instance mapping (unlisted instances are removed)."""
    if not _MST_NAME_RE.fullmatch(name or ""):
        raise _unsupported(name)
    revision = int(revision)
    if not 0 <= revision <= 65535:
        raise _unsupported(revision)
    wanted = {int(instance): {validate_vlan_id(vlan) for vlan in vlans} for instance, vlans in instances}
    lines = []
    if current.get("name") != name:
        lines.append(f"spanning-tree config-name {name}")
    if current.get("revision") != revision:
        lines.append(f"spanning-tree config-revision {revision}")
    for instance in sorted(configured):
        if instance not in wanted:
            lines.append(f"no spanning-tree instance {instance}")
    for instance, vlans in sorted(wanted.items()):
        have = configured.get(instance, set())
        removed, added = sorted(have - vlans), sorted(vlans - have)
        if removed:
            lines.append(f"no spanning-tree instance {instance} vlan {format_vlan_list(tuple(removed))}")
        if added:
            lines.append(f"spanning-tree instance {instance} vlan {format_vlan_list(tuple(added))}")
    return lines
