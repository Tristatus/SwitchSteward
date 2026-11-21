"""Parsers for the Cisco device settings, firmware and diagnostics reads.

All functions are pure: they take raw IOS output and never return secrets (keys and
passwords are only reported as ``key_configured``/presence flags).
"""

import ipaddress
import re

from ..cli import parse_fixed_table

# Groups/maps SwitchSteward creates; reads map them back to the generic values.
RADIUS_GROUP = "SM-RADIUS"
TACACS_GROUP = "SM-TACACS"
TRUST_COS_POLICY = "SM-TRUST-COS"
UNTRUST_POLICY = "SM-UNTRUST"
# ``any`` in ACL entries (address 0.0.0.0, prefix length 0).
ANY_ADDRESS = str(ipaddress.IPv4Address(0))

# IOS prints well-known ports as names in ACLs (``eq www``); map them back to numbers.
PORT_NAMES = {
    "bgp": 179, "biff": 512, "bootpc": 68, "bootps": 67, "chargen": 19, "cmd": 514, "daytime": 13,
    "discard": 9, "dnsix": 195, "domain": 53, "echo": 7, "exec": 512, "finger": 79, "ftp": 21,
    "ftp-data": 20, "gopher": 70, "hostname": 101, "ident": 113, "irc": 194, "isakmp": 500,
    "klogin": 543, "kshell": 544, "login": 513, "lpd": 515, "mobile-ip": 434, "msrpc": 135,
    "nameserver": 42, "netbios-dgm": 138, "netbios-ns": 137, "netbios-ss": 139, "nntp": 119,
    "non500-isakmp": 4500, "ntp": 123, "pim-auto-rp": 496, "pop2": 109, "pop3": 110, "rip": 520,
    "smtp": 25, "snmp": 161, "snmptrap": 162, "sunrpc": 111, "syslog": 514, "tacacs": 49,
    "talk": 517, "telnet": 23, "tftp": 69, "time": 37, "uucp": 540, "who": 513, "whois": 43,
    "www": 80, "xdmcp": 177,
}
SYSLOG_LEVELS = {
    "emergencies": 0, "alerts": 1, "critical": 2, "errors": 3, "warnings": 4,
    "notifications": 5, "informational": 6, "debugging": 7,
}
IOS_DEFAULT_TRAP_LEVEL = 6
# Long interface names as ``show interfaces`` prints them -> short names of ``show interfaces status``.
_SHORT_PREFIXES = (
    ("TwentyFiveGigE", "Twe"), ("TwoGigabitEthernet", "Tw"), ("FiveGigabitEthernet", "Fi"),
    ("TenGigabitEthernet", "Te"), ("FortyGigabitEthernet", "Fo"), ("HundredGigE", "Hu"),
    ("AppGigabitEthernet", "Ap"), ("GigabitEthernet", "Gi"), ("FastEthernet", "Fa"), ("Port-channel", "Po"),
)


def short_interface_name(name: str) -> str:
    for long_name, short in _SHORT_PREFIXES:
        if name.startswith(long_name):
            return short + name[len(long_name):]
    return name


# --- Running configuration ---------------------------------------------------------------


def config_sections(running: str) -> list[tuple[str, list[str]]]:
    """Top-level lines of a running configuration with their (stripped) sub-mode lines.

    Banner bodies (``banner motd ^C`` … ``^C``) become the sub-lines of their banner line.
    """
    sections: list[tuple[str, list[str]]] = []
    lines = (running or "").splitlines()
    index = 0
    while index < len(lines):
        line = lines[index].rstrip()
        index += 1
        if not line.strip() or line.strip() == "!":
            continue
        banner = re.match(r"^banner\s+\S+\s+\^C(.*)$", line)
        if banner:
            body: list[str] = []
            rest = banner.group(1)
            if "^C" in rest:
                text = rest.split("^C", 1)[0]
                sections.append((line.split("^C", 1)[0].rstrip(), [text] if text else []))
                continue
            if rest:
                body.append(rest)
            while index < len(lines):
                text = lines[index].rstrip("\r")
                index += 1
                if "^C" in text:
                    before = text.split("^C", 1)[0]
                    if before:
                        body.append(before)
                    break
                body.append(text)
            sections.append((line.split("^C", 1)[0].rstrip(), body))
            continue
        if line[0] in " \t":
            if sections:
                sections[-1][1].append(line.strip())
            continue
        sections.append((line, []))
    return sections


def _globals(sections) -> list[str]:
    return [header for header, _ in sections]


def _ipv4(value: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        return None


def _mask_length(mask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def _wildcard_length(wildcard: str) -> int | None:
    """Prefix length of a wildcard mask (``0.0.0.255`` -> 24, ``0.0.0.0`` -> 32)."""
    try:
        inverted = int(ipaddress.IPv4Address(wildcard)) ^ 0xFFFFFFFF
        return ipaddress.IPv4Network(f"0.0.0.0/{ipaddress.IPv4Address(inverted)}").prefixlen
    except ValueError:
        return None


def parse_identity(sections) -> dict:
    identity = {"hostname": None, "banner": None, "snmp_location": None, "snmp_contact": None}
    for header, body in sections:
        if match := re.match(r"^hostname\s+(\S+)$", header):
            identity["hostname"] = match.group(1)
        elif re.match(r"^banner\s+motd\b", header):
            identity["banner"] = "\n".join(body)
        elif match := re.match(r"^snmp-server location\s+(.+)$", header):
            identity["snmp_location"] = match.group(1).strip()
        elif match := re.match(r"^snmp-server contact\s+(.+)$", header):
            identity["snmp_contact"] = match.group(1).strip()
    return identity


def parse_services(sections) -> dict:
    """NTP/time zone/DNS/syslog with the exact removal command of every configured entry."""
    ntp: dict[str, str] = {}
    dns: dict[str, str] = {}
    syslog: dict[str, str] = {}
    timezone = None
    domain = None
    trap = IOS_DEFAULT_TRAP_LEVEL
    for line in _globals(sections):
        if match := re.match(r"^ntp server\s+(?:vrf\s+(\S+)\s+)?(\S+)", line):
            vrf = f"vrf {match.group(1)} " if match.group(1) else ""
            ntp[match.group(2)] = f"no ntp server {vrf}{match.group(2)}"
        elif match := re.match(r"^clock timezone\s+(\S+)\s+(-?\d+)(?:\s+(\d+))?", line):
            hours = int(match.group(2))
            minutes = int(match.group(3) or 0)
            sign = -1 if match.group(2).startswith("-") else 1
            timezone = {"name": match.group(1), "offset_minutes": hours * 60 + sign * minutes}
        elif match := re.match(r"^ip name-server\s+(?:vrf\s+(\S+)\s+)?(.+)$", line):
            vrf = f"vrf {match.group(1)} " if match.group(1) else ""
            for server in match.group(2).split():
                dns[server] = f"no ip name-server {vrf}{server}"
        elif match := re.match(r"^ip domain([ -])name\s+(\S+)$", line):
            domain = match.group(2)
        elif match := re.match(r"^logging host\s+(\S+)(.*)$", line):
            host = match.group(1)
            if host != "ipv6":
                syslog[host] = f"no logging host {host}{_vrf_suffix(match.group(2))}"
        elif match := re.match(r"^logging\s+(\d+\.\d+\.\d+\.\d+)\s*$", line):
            syslog[match.group(1)] = f"no logging {match.group(1)}"
        elif match := re.match(r"^logging trap\s+(\S+)$", line):
            value = match.group(1)
            trap = int(value) if value.isdigit() else SYSLOG_LEVELS.get(value, IOS_DEFAULT_TRAP_LEVEL)
    return {
        "ntp_servers": list(ntp), "timezone": timezone, "dns_servers": list(dns), "domain_name": domain,
        "syslog": [{"host": host, "severity": trap} for host in syslog],
        "_ntp_remove": ntp, "_dns_remove": dns, "_syslog_remove": syslog, "_trap": trap,
    }


def _vrf_suffix(rest: str) -> str:
    match = re.search(r"\bvrf\s+(\S+)", rest or "")
    return f" vrf {match.group(1)}" if match else ""


def management_vrf(sections, switch_ip: str) -> str | None:
    """VRF of the interface that carries ``switch_ip`` (9300 out-of-band ``Mgmt-vrf``), else None."""
    for header, body in sections:
        if not header.startswith("interface "):
            continue
        if any(re.match(rf"^ip address {re.escape(switch_ip)}\s", line) for line in body):
            for line in body:
                if match := re.match(r"^(?:vrf forwarding|ip vrf forwarding)\s+(\S+)$", line):
                    return match.group(1)
    return None


def parse_snmp_users(output: str | None) -> list[dict]:
    """``show snmp user`` blocks -> [{name, auth, priv, group}] (auth/priv lowercase ids or None)."""
    users = []
    current: dict | None = None
    for line in (output or "").splitlines():
        if match := re.match(r"^\s*User name:\s*(\S+)", line):
            current = {"name": match.group(1), "auth": None, "priv": None, "group": None}
            users.append(current)
        elif current is None:
            continue
        elif match := re.match(r"^\s*Authentication Protocol:\s*(\S+)", line):
            current["auth"] = {"SHA": "sha", "SHA-256": "sha256", "SHA256": "sha256"}.get(match.group(1).upper())
        elif match := re.match(r"^\s*Privacy Protocol:\s*(\S+)", line):
            current["priv"] = "aes128" if match.group(1).upper() in {"AES128", "AES"} else None
        elif match := re.match(r"^\s*Group-name:\s*(\S+)", line):
            current["group"] = match.group(1)
    return users


def snmp_group_access(sections) -> dict[str, str]:
    """Group name -> "rw" when it has a write view, else "ro"."""
    groups: dict[str, str] = {}
    for line in _globals(sections):
        if match := re.match(r"^snmp-server group\s+(\S+)\s+v3\s+\S+(.*)$", line):
            access = "rw" if re.search(r"\bwrite\s+\S+", match.group(2)) else "ro"
            groups[match.group(1)] = "rw" if groups.get(match.group(1)) == "rw" else access
    return groups


def snmp_views(sections) -> set[str]:
    return {match.group(1) for line in _globals(sections) if (match := re.match(r"^snmp-server view\s+(\S+)", line))}


def parse_aaa(sections) -> dict:
    """RADIUS/TACACS servers (``name`` = server block name, None for legacy host lines) and the login order."""
    radius: list[dict] = []
    tacacs: list[dict] = []
    groups: dict[str, list[str]] = {}
    login_order = None
    new_model = False
    for header, body in sections:
        if match := re.match(r"^radius server\s+(\S+)$", header):
            server = {"name": match.group(1), "host": None, "auth_port": 1812, "acct_port": 1813,
                      "key_configured": any(line.startswith("key ") for line in body)}
            for line in body:
                if address := re.match(r"^address ipv4\s+(\S+)(.*)$", line):
                    server["host"] = address.group(1)
                    if auth := re.search(r"auth-port\s+(\d+)", address.group(2)):
                        server["auth_port"] = int(auth.group(1))
                    if acct := re.search(r"acct-port\s+(\d+)", address.group(2)):
                        server["acct_port"] = int(acct.group(1))
            radius.append(server)
        elif match := re.match(r"^radius-server host\s+(\S+)(.*)$", header):
            rest = match.group(2)
            auth = re.search(r"auth-port\s+(\d+)", rest)
            acct = re.search(r"acct-port\s+(\d+)", rest)
            radius.append({
                "name": None, "host": match.group(1), "auth_port": int(auth.group(1)) if auth else 1645,
                "acct_port": int(acct.group(1)) if acct else 1646, "key_configured": " key " in f"{rest} ",
            })
        elif match := re.match(r"^tacacs server\s+(\S+)$", header):
            server = {"name": match.group(1), "host": None, "port": 49,
                      "key_configured": any(line.startswith("key ") for line in body)}
            for line in body:
                if address := re.match(r"^address ipv4\s+(\S+)", line):
                    server["host"] = address.group(1)
                elif port := re.match(r"^port\s+(\d+)", line):
                    server["port"] = int(port.group(1))
            tacacs.append(server)
        elif match := re.match(r"^tacacs-server host\s+(\S+)(.*)$", header):
            port = re.search(r"\bport\s+(\d+)", match.group(2))
            tacacs.append({"name": None, "host": match.group(1), "port": int(port.group(1)) if port else 49,
                           "key_configured": " key " in f"{match.group(2)} "})
        elif match := re.match(r"^aaa group server (?:radius|tacacs\+)\s+(\S+)$", header):
            groups[match.group(1)] = [
                server.group(1) for line in body if (server := re.match(r"^server name\s+(\S+)$", line))
            ]
        elif header == "aaa new-model":
            new_model = True
        elif match := re.match(r"^aaa authentication login default\s+(.+)$", header):
            login_order = login_methods(match.group(1))
    return {
        "radius": radius, "tacacs": tacacs, "groups": groups, "new_model": new_model,
        "login_order": login_order if login_order is not None else ["local"],
    }


def login_methods(text: str) -> list[str]:
    methods: list[str] = []
    tokens = text.split()
    index = 0
    while index < len(tokens):
        word = tokens[index]
        if word == "group" and index + 1 < len(tokens):
            group = tokens[index + 1]
            index += 2
            if group in {"radius", RADIUS_GROUP}:
                methods.append("radius")
            elif group in {"tacacs+", TACACS_GROUP}:
                methods.append("tacacs")
            continue
        if word in {"local", "local-case"}:
            methods.append("local")
        index += 1
    return list(dict.fromkeys(methods))


def parse_users(sections) -> list[dict]:
    users: dict[str, dict] = {}
    for line in _globals(sections):
        if match := re.match(r"^username\s+(\S+)(.*)$", line):
            privilege = re.search(r"\bprivilege\s+(\d+)", match.group(2))
            level = int(privilege.group(1)) if privilege else 1
            users[match.group(1)] = {"name": match.group(1), "privilege": "admin" if level == 15 else "read_only"}
    return list(users.values())


def parse_ssh(sections, show_ip_ssh: str | None, http_status: str | None) -> dict:
    ssh = {"version": None, "timeout_seconds": None, "telnet_enabled": None, "web_enabled": None}
    if show_ip_ssh and (match := re.search(r"SSH Enabled - version\s+(\S+)", show_ip_ssh)):
        ssh["version"] = match.group(1)
    vty = [body for header, body in sections if re.match(r"^line vty\b", header)]
    if vty:
        body = vty[0]
        timeout = next((re.match(r"^exec-timeout\s+(\d+)(?:\s+(\d+))?", line) for line in body
                        if line.startswith("exec-timeout")), None)
        # IOS default: 10 minutes (the line is not shown then).
        ssh["timeout_seconds"] = int(timeout.group(1)) * 60 + int(timeout.group(2) or 0) if timeout else 600
        transports = [line.split()[2:] for line in body if line.startswith("transport input")]
        if transports:
            ssh["telnet_enabled"] = any("telnet" in words or "all" in words for words in transports)
    if http_status:
        states = re.findall(r"HTTP (?:secure )?server status:\s*(\w+)", http_status, re.IGNORECASE)
        if states:
            ssh["web_enabled"] = any(state.lower() == "enabled" for state in states)
    return ssh


def parse_l3(sections) -> dict:
    svis = []
    routes = []
    routing = False
    default_gateway_l2 = None
    for header, body in sections:
        if match := re.match(r"^interface Vlan(\d+)$", header):
            svi = {"vlan": int(match.group(1)), "address": None, "prefix_length": None, "dhcp_relay": [],
                   "enabled": "shutdown" not in body}
            for line in body:
                if (address := re.match(r"^ip address\s+(\S+)\s+(\S+)$", line)) and svi["address"] is None:
                    svi["address"] = address.group(1)
                    svi["prefix_length"] = _mask_length(address.group(2))
                elif helper := re.match(r"^ip helper-address\s+(\S+)$", line):
                    svi["dhcp_relay"].append(helper.group(1))
            svis.append(svi)
        elif header == "ip routing":
            routing = True
        elif match := re.match(r"^ip default-gateway\s+(\S+)", header):
            default_gateway_l2 = match.group(1)
        elif match := re.match(r"^ip route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(.+)$", header):
            tokens = match.group(3).split()
            hop_index = next((index for index, token in enumerate(tokens) if _ipv4(token)), None)
            if hop_index is None:
                continue
            following = tokens[hop_index + 1] if hop_index + 1 < len(tokens) else ""
            routes.append({
                "prefix": match.group(1), "prefix_length": _mask_length(match.group(2)),
                "next_hop": tokens[hop_index], "distance": int(following) if following.isdigit() else 1,
            })
    default_route = next((route["next_hop"] for route in routes if route["prefix_length"] == 0), None)
    return {
        "svis": svis,
        "default_gateway": default_route if routing else default_gateway_l2 or default_route,
        "routes": routes,
        "routing_enabled": routing,
    }


def _address(tokens: list[str], index: int, standard: bool = False) -> tuple[str | None, int | None, int]:
    """(address, prefix length, next index) of ``any`` / ``host X`` / ``X wildcard`` at ``index``."""
    if index >= len(tokens):
        return None, None, index
    word = tokens[index]
    if word == "any":
        return ANY_ADDRESS, 0, index + 1
    if word == "host" and index + 1 < len(tokens):
        return tokens[index + 1], 32, index + 2
    address = word.rstrip(",")
    if index + 1 < len(tokens) and _ipv4(tokens[index + 1]):
        return address, _wildcard_length(tokens[index + 1]), index + 2
    if standard and tokens[index + 1:index + 3] == ["wildcard", "bits"] and index + 3 < len(tokens):
        return address, _wildcard_length(tokens[index + 3]), index + 4
    return address, 32, index + 1


def _port(token: str) -> int | None:
    if token.isdigit():
        return int(token)
    return PORT_NAMES.get(token)


def parse_access_lists(output: str) -> list[dict]:
    """``show ip access-lists`` -> [{name, type, entries}] (IPv4 standard/extended only)."""
    acls = []
    current = None
    for line in (output or "").splitlines():
        if match := re.match(r"^(Standard|Extended) IP access list\s+(\S+)", line):
            current = {"name": match.group(2), "type": match.group(1).lower(), "entries": []}
            acls.append(current)
            continue
        if not line.startswith((" ", "\t")):
            current = None
            continue
        if current is None:
            continue
        text = re.sub(r"\s*\(\d+ matches?\)\s*$", "", line.strip())
        tokens = text.replace(",", " ").split() if current["type"] == "standard" else text.split()
        if len(tokens) < 3 or not tokens[0].isdigit() or tokens[1] not in {"permit", "deny"}:
            continue
        entry = {"seq": int(tokens[0]), "action": tokens[1], "protocol": "ip", "src": None, "src_len": None,
                 "dst": None, "dst_len": None, "dst_port_op": None, "dst_port": None, "dst_port_end": None}
        if current["type"] == "standard":
            entry["src"], entry["src_len"], _ = _address(tokens, 2, standard=True)
        else:
            entry["protocol"] = tokens[2]
            entry["src"], entry["src_len"], index = _address(tokens, 3)
            index = _skip_port(tokens, index)
            entry["dst"], entry["dst_len"], index = _address(tokens, index)
            if index < len(tokens) and tokens[index] == "eq" and index + 1 < len(tokens):
                entry["dst_port_op"], entry["dst_port"] = "eq", _port(tokens[index + 1])
            elif index < len(tokens) and tokens[index] == "range" and index + 2 < len(tokens):
                entry["dst_port_op"] = "range"
                entry["dst_port"], entry["dst_port_end"] = _port(tokens[index + 1]), _port(tokens[index + 2])
        current["entries"].append(entry)
    return acls


def _skip_port(tokens: list[str], index: int) -> int:
    """Skip a source-port match (not part of the data model)."""
    if index < len(tokens):
        if tokens[index] in {"eq", "gt", "lt", "neq"}:
            return index + 2
        if tokens[index] == "range":
            return index + 3
    return index


def parse_acl_bindings(sections) -> dict[str, list[dict]]:
    """ACL name -> [{interface, direction}] from ``ip access-group`` lines of interface sections."""
    bindings: dict[str, list[dict]] = {}
    for header, body in sections:
        if not header.startswith("interface "):
            continue
        interface = header.split(None, 1)[1]
        for line in body:
            if match := re.match(r"^ip access-group\s+(\S+)\s+(in|out)$", line):
                bindings.setdefault(match.group(1), []).append({"interface": interface, "direction": match.group(2)})
    return bindings


def interface_bodies(sections) -> dict[str, list[str]]:
    return {header.split(None, 1)[1]: body for header, body in sections if header.startswith("interface ")}


def parse_qos(sections, physical, mqc: bool) -> dict:
    """Per-port trust (IOS MLS lines or XE service policies) and the voice preset (``auto qos voip``)."""
    ports: dict[str, dict] = {}
    voice: dict[str, bool] = {}
    for interface, body in interface_bodies(sections).items():
        if not physical(interface):
            continue
        name = short_interface_name(interface)
        if mqc:
            policy = next((match.group(1) for line in body
                           if (match := re.match(r"^service-policy input\s+(\S+)$", line))), None)
            trust = {None: "dscp", TRUST_COS_POLICY: "cos", UNTRUST_POLICY: "none"}.get(policy)
        else:
            match = next((re.match(r"^mls qos trust\s+(cos|dscp)$", line) for line in body
                          if line.startswith("mls qos trust ")), None)
            trust = match.group(1) if match else "none"
        ports[name] = {"trust": trust}
        voice[name] = any(line.startswith("auto qos voip") for line in body)
    return {"ports": ports, "voice_preset": voice}


# --- Firmware ------------------------------------------------------------------------------


def parse_install_mode(version: str) -> bool | None:
    """XE ``show version`` switch table column ``Mode``; classic IOS has no install mode (False)."""
    modes = re.findall(r"^\*?\s*\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+(INSTALL|BUNDLE)\s*$", version or "", re.MULTILINE)
    if modes:
        return modes[0] == "INSTALL"
    if re.search(r"IOS[ -]XE", version or ""):
        return None
    return False


def parse_boot(output: str) -> list[str]:
    """Boot images of the next reload (last ``BOOT variable``/``BOOT path-list`` line)."""
    values = re.findall(r"^\s*BOOT (?:variable|path-list)\s*[=:]\s*(.*?)\s*$", output or "", re.MULTILINE)
    if not values:
        return []
    return [item.strip() for item in re.split(r"[;,]", values[-1]) if item.strip()]


def parse_dir(output: str) -> tuple[list[str], int | None]:
    """Files of ``dir flash:`` and the free bytes from the summary line."""
    files = [
        match.group(1) for line in (output or "").splitlines()
        if (match := re.match(r"^\s*\d+\s+-r\S*\s+\d+\s+.*?\s(\S+)\s*$", line))
    ]
    free = re.search(r"\(\s*(\d+)\s+bytes free\s*\)", output or "")
    return files, int(free.group(1)) if free else None


# --- Diagnostics ---------------------------------------------------------------------------


def parse_counters(output: str) -> list[dict]:
    """``show interfaces`` -> counters per interface (short names)."""
    rows = []
    current = None
    for line in (output or "").splitlines():
        if match := re.match(r"^(\S+) is (?:up|down|administratively down)", line):
            current = {"interface": short_interface_name(match.group(1)), "in_octets": None, "out_octets": None,
                       "in_errors": None, "out_errors": None, "crc": None, "drops_in": None,
                       "drops_out": None, "collisions": None}
            rows.append(current)
            continue
        if current is None:
            continue
        if match := re.search(r"(\d+) packets input, (\d+) bytes", line):
            current["in_octets"] = int(match.group(2))
        if match := re.search(r"(\d+) packets output, (\d+) bytes", line):
            current["out_octets"] = int(match.group(2))
        if match := re.search(r"(\d+) input errors, (\d+) CRC", line):
            current["in_errors"], current["crc"] = int(match.group(1)), int(match.group(2))
        if match := re.search(r"(\d+) output errors, (\d+) collisions", line):
            current["out_errors"], current["collisions"] = int(match.group(1)), int(match.group(2))
        if match := re.search(r"Input queue: \d+/\d+/(\d+)/\d+", line):
            current["drops_in"] = int(match.group(1))
        if match := re.search(r"Total output drops: (\d+)", line):
            current["drops_out"] = int(match.group(1))
    return rows


def _float(token: str) -> float | None:
    try:
        return float(token)
    except ValueError:
        return None


def parse_transceivers(output: str) -> list[dict]:
    """``show interfaces transceiver`` table; alarm flags (``++ + - --``) set ``alarm``."""
    rows = []
    for line in (output or "").splitlines():
        tokens = line.split()
        if len(tokens) < 6 or not re.match(r"^[A-Za-z]+\d+(/\d+)+$", tokens[0]):
            continue
        values = []
        alarm = False
        for token in tokens[1:]:
            if token in {"++", "+", "-", "--"}:
                alarm = True
                continue
            if token.upper() in {"N/A", "NA"}:
                values.append(None)
                continue
            value = _float(token)
            if value is None:
                break
            values.append(value)
        if len(values) < 5:
            continue
        rows.append({
            "interface": tokens[0], "type": None, "temperature_c": values[0], "voltage_v": values[1],
            "tx_power_dbm": values[3], "rx_power_dbm": values[4], "alarm": alarm,
        })
    return rows


def parse_log(output: str, lines: int) -> list[str]:
    """Buffered log lines (after the ``Log Buffer`` header), the last ``lines`` in device order."""
    text = output or ""
    match = re.search(r"^Log Buffer[^\n]*\n", text, re.MULTILINE)
    body = text[match.end():] if match else text
    entries = [line.rstrip() for line in body.splitlines() if line.strip()]
    return entries[-lines:] if lines > 0 else []


def parse_environment(output: str) -> dict:
    temperatures: list[dict] = []
    fans: list[dict] = []
    supplies: list[dict] = []
    text = output or ""
    value = re.search(r"Temperature Value:\s*(-?\d+)", text)
    for line in text.splitlines():
        stripped = line.strip()
        if match := re.match(r"^(.*?\bTEMPERATURE) is (.+)$", stripped, re.IGNORECASE):
            temperatures.append({"sensor": match.group(1).strip(": "), "status": match.group(2).strip(),
                                 "celsius": float(value.group(1)) if value else None})
        elif match := re.match(r"^(\d+)\s+(.+?)\s+(-?\d+(?:\.\d+)?)\s+Celsius\s+(\S+)", stripped):
            temperatures.append({"sensor": f"{match.group(1)} {match.group(2)}", "celsius": float(match.group(3)),
                                 "status": match.group(4)})
        elif match := re.match(r"^(.*?\bFAN\b.*?) is (.+)$", stripped, re.IGNORECASE):
            fans.append({"name": match.group(1).strip(": "), "status": match.group(2).strip()})
        elif match := re.match(r"^(\d+)\s+(\d+)\s+\d+\s+(\S+)\s+\S+.*to.*$", stripped):
            fans.append({"name": f"Switch {match.group(1)} FAN {match.group(2)}", "status": match.group(3)})
    table = parse_fixed_table(text, r"^\s*SW\s+PID\s+Serial#", ("SW", "PID", "Serial#", "Status", "Sys Pwr",
                                                                 "PoE Pwr", "Watts"))
    for row in table or []:
        if not re.match(r"^\d+[A-Z]$", row["SW"]):
            continue
        if row["PID"].lower().startswith("not present"):
            supplies.append({"name": row["SW"], "status": "Not Present", "watts": None})
            continue
        supplies.append({"name": f"{row['SW']} {row['PID']}".strip(), "status": row["Status"] or None,
                         "watts": int(row["Watts"]) if row["Watts"].isdigit() else None})
    return {"temperatures": temperatures, "fans": fans, "power_supplies": supplies}


def parse_cable_test(output: str) -> dict:
    """``show cable-diagnostics tdr interface X`` -> {status, pairs}."""
    pairs = []
    for line in (output or "").splitlines():
        match = re.search(r"Pair\s+([A-D])\s+(.*?)\s+Pair\s+[A-D]\s+(.+?)\s*$", line)
        if not match:
            continue
        length = re.match(r"^(\d+)\s*(?:\+/-)?", match.group(2).strip())
        pairs.append({"pair": match.group(1), "status": match.group(3),
                      "length_m": int(length.group(1)) if length else None})
    running = re.search(r"in ?progress|not completed", output or "", re.IGNORECASE)
    if running or not pairs:
        return {"status": "running", "pairs": pairs}
    return {"status": "done", "pairs": pairs}
