"""Netgear device settings, firmware and diagnostics.

Mixed into ``NetgearDriver``; uses only ``self`` methods of the driver (``_show``, ``_optional``,
``_running_text``, ``_model``, ``_family``, ``read_interfaces``, ``_existing_vlans``,
``validate_interface``, ``is_physical_interface``, ``plan_reload``) and shared helpers (no import
of ``netgear.py``). Plans read the device first so that lists replace the configured state and
the preview shows only real changes.

Netgear specifics:

- Privileged-EXEC-only commands (``hostname``, ``ip ssh``/``telnet``/``http`` server switches,
  ``sshcon timeout``, ``copy``, ``boot system``, ``cablestatus``, ``clear counters``) are exec
  steps; ``vlan routing`` runs in the ``vlan database`` sub-mode (Netgear ``execute_plan``).
- Interactive configuration commands (``radius server key`` asks for the secret twice,
  ``username … password`` for the password twice) run as exec steps inside ``configure`` …
  ``exit``; their answers are secrets and never shown (``lines`` show ``REDACTED``).
- Time: M4250/M4350 (firmware 13/14, "AV") use NTP, the other families SNTP (max. 3 servers).
- SNMPv3: 12.x/AV only offer SHA-512 (``auth-sha512``) and AES-128; M5300/M7100 (11.0)
  bind SNMPv3 to local users (``username snmpv3 …``, SHA/DES): the authentication key is the
  user's login password, AES-128 is refused.
- ACLs: only named extended ACLs exist; a standard entry is ``permit|deny ip {src} {wild}
  any``; ``read_device_config`` reports an ACL as ``standard`` when all entries have that form.
- QoS: ``classofservice trust`` per port; the voice preset is ``auto-voip protocol-based``.
- Firmware: two slots ``image1``/``image2``; staging copies per SFTP (port 22) into the
  non-active slot, activation sets it with ``boot system``. No checksum command, no free-space
  read (``free_bytes`` None).
- Cable test: ``cablestatus {if}`` runs the test and prints the result in one command. The
  ``cable-test`` operation runs it (the link drops briefly); ``execute_plan`` keeps the parsed
  result in a process-wide store (10 minutes, per switch and port) that ``read_cable_test``
  returns. A read never starts the test itself (reads are allowed for viewers).
"""

import ipaddress
import math
import re
import threading
import time

from ...i18n import t
from .. import transport
from ..errors import InvalidInputError, append_warning
from ..features import selected_profile, supported
from ..validation import (
    validate_acl_name,
    validate_banner,
    validate_choice,
    validate_host,
    validate_hostname,
    validate_ipv4,
    validate_ipv4_prefix,
    validate_secret,
    validate_snmp_text,
    validate_username,
    validate_vlan_id,
)
from .cli import parse_key_values
from .netgear_l2 import FAMILY_AV, normalize_interface
from .plans import (
    REDACTED,
    AaaChange,
    AclEntry,
    ChangePlan,
    CliCommand,
    CliLines,
    FirmwareImage,
    IdentityChange,
    ServicesChange,
    SnmpUserChange,
    TransferLocation,
    combine_plans,
)

DEVICE_FEATURES = {
    "device_identity": supported(),
    "device_services": supported(),
    "device_snmp": supported(),
    "device_aaa": supported(("radius", "tacacs", "login_order")),
    "device_users": supported(),
    "device_ssh": supported(("timeout", "telnet", "web")),
    "device_l3": supported(("svi", "gateway", "dhcp_relay", "static_routes")),
    "acl": supported(("port_in", "port_out", "vlan_in", "vlan_out")),
    "qos": supported(("none", "cos", "dscp")),
    "qos_voice": supported(),
    "firmware": supported(),
    "diag_counters": supported(),
    "diag_transceivers": supported(),
    "cable_test": supported(),
    "device_log": supported(),
    "environment": supported(),
}

FIRMWARE_TIMEOUT_SECONDS = 3600
SLOTS = ("image1", "image2")
NETGEAR_MAX_FILENAME = 31
SNMP_TEXT_MAX_LENGTH = 31  # sysname/location/contact: 1-31 characters
SNTP_MAX_SERVERS = 3
NTP_MAX_SERVERS = 4
RADIUS_KEY_RE = re.compile(r"^[A-Za-z0-9]{1,16}$")
SYSLOG_PORT = 514
MAX_COUNTER_PORTS = 64
CABLE_RESULT_SECONDS = 600
SSH_TIMEOUT_MAX_MINUTES = 160
SEVERITY_NUMBER = {"emergency": 0, "emergencies": 0, "alert": 1, "alerts": 1, "critical": 2, "error": 3,
                   "errors": 3, "warning": 4, "warnings": 4, "notice": 5, "notification": 5, "notifications": 5,
                   "info": 6, "informational": 6, "debug": 7, "debugging": 7}
TRUST_KEYWORDS = {"none": "untrusted", "cos": "dot1p", "dscp": "ip-dscp"}
TRUST_BY_KEYWORD = {value: key for key, value in TRUST_KEYWORDS.items()}
LOGIN_LIST = "networkList"  # default login list of telnet/SSH
SNMP_VIEW = "SWM_ALL"
PORT_NAMES = {"www": 80, "http": 80, "https": 443, "ssh": 22, "telnet": 23, "domain": 53, "snmp": 161,
              "ftp": 21, "tftp": 69, "bootps": 67, "bootpc": 68, "ntp": 123, "syslog": 514, "smtp": 25}

YES_NO = r"\(y/n\)"
YES_NO_LONG = r"(?i)\(yes/no\)"
PASSWORD_PROMPT = r"(?i)password:\s*$"  # noqa: S105 - prompt regex, not a password
SECRET_PROMPT = r"(?i)(secret|key|password)[^:]*:\s*$"  # noqa: S105 - prompt regex, not a password
ANY_ADDRESS = "0.0.0.0"  # noqa: S104 - network operand "any", not a bind address

_BLOCK_RE = re.compile(r"^(interface\s|line\s|ip access-list\s|tacacs-server host\s|vlan database$)", re.IGNORECASE)
_VLAN_IF_RE = re.compile(r"^vlan\s*(\d{1,4})$", re.IGNORECASE)
_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_M71_RE = re.compile(r"\bM(?:5300|7100)\b", re.IGNORECASE)

# (switch id, interface key) -> (monotonic time, parsed result); filled by ``execute_plan``.
_CABLE_RESULTS: dict[tuple, tuple[float, dict]] = {}
_CABLE_LOCK = threading.Lock()


def _no_change() -> InvalidInputError:
    return InvalidInputError(t("Keine Änderung nötig."))


def _transfer_secrets(transfer: TransferLocation) -> tuple[str, ...]:
    # Imported here: ``app.transfer`` imports ``drivers.plans`` (and with it this package).
    from ...transfer import location_secrets

    return location_secrets(transfer)


def _unquote(value: str) -> str:
    value = value.strip()
    return value[1:-1] if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'" else value


def _int(text: str | None) -> int | None:
    match = re.search(r"-?\d+", (text or "").replace(",", ""))
    return int(match.group(0)) if match else None


def _float(text: str | None) -> float | None:
    match = re.search(r"-?\d+(?:\.\d+)?", text or "")
    return float(match.group(0)) if match else None


def _short_text(value: str) -> str:
    text = validate_snmp_text(value)
    if len(text) > SNMP_TEXT_MAX_LENGTH:
        raise InvalidInputError(t("Der Text darf auf dieser Plattform höchstens {limit} Zeichen haben.",
                                  limit=SNMP_TEXT_MAX_LENGTH))
    return text


def _mask(prefix_length: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_length}").netmask)


def _wildcard(prefix_length: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_length}").hostmask)


def _prefix_length(mask: str, *, wildcard: bool = False) -> int | None:
    try:
        value = int(ipaddress.IPv4Address(mask))
    except ValueError:
        return None
    if wildcard:
        value ^= 0xFFFFFFFF
    length = bin(value).count("1")
    return length if value == (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF else None


def _vlan_interface(name: str) -> int | None:
    match = _VLAN_IF_RE.match((name or "").strip())
    return int(match.group(1)) if match else None


# --- Parsers ---------------------------------------------------------------------------------


def config_sections(text: str | None) -> tuple[list[str], list[tuple[str, list[str]]]]:
    """Running configuration: global lines and blocks (header, body) closed by ``exit``."""
    top: list[str] = []
    blocks: list[tuple[str, list[str]]] = []
    current: list[str] | None = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("!"):
            continue
        if current is not None:
            if line.casefold() == "exit":
                current = None
            else:
                current.append(line)
            continue
        if _BLOCK_RE.match(line):
            current = []
            blocks.append((line, current))
        elif line.casefold() not in ("configure", "exit"):
            top.append(line)
    return top, blocks


def _block(blocks, header_re: str) -> list[tuple[re.Match, list[str]]]:
    pattern = re.compile(header_re, re.IGNORECASE)
    return [(match, body) for header, body in blocks if (match := pattern.fullmatch(header))]


def parse_identity(sysinfo: str, top: list[str]) -> dict:
    values = parse_key_values(sysinfo)
    banner = next((_unquote(match.group(1)) for line in top
                   if (match := re.fullmatch(r"set clibanner (.+)", line, re.IGNORECASE))), None)
    return {
        "hostname": values.get("System Name") or None,
        "banner": banner or None,
        "snmp_location": values.get("System Location") or None,
        "snmp_contact": values.get("System Contact") or None,
    }


def parse_time_servers(output: str) -> list[str]:
    """``show sntp server`` / ``show ntp servers``: every ``… Address ….. {host}`` field."""
    pattern = re.compile(r"^\s*(?:Server\s+)?(?:Host\s+)?Address\s*\.{2,}:?\s*(\S+)\s*$", re.IGNORECASE)
    return list(dict.fromkeys(match.group(1) for line in (output or "").splitlines()
                              if (match := pattern.match(line))))


def parse_clock(output: str) -> dict:
    """``show clock``: ``15:02:09 (UTC+0:00) …`` or ``15:02:09 CET(UTC+1:00) …`` (zone acronym before)."""
    match = re.search(r"(?:\b([A-Za-z]{1,6})\s*)?\((?:UTC|GMT)?([+-])(\d{1,2}):(\d{2})\)", output or "")
    if not match:
        return {"name": None, "offset_minutes": None}
    minutes = int(match.group(3)) * 60 + int(match.group(4))
    return {"name": match.group(1) or None, "offset_minutes": -minutes if match.group(2) == "-" else minutes}


def parse_hosts(output: str) -> dict:
    """``show hosts``: name servers, default domain and lookup state."""
    values = parse_key_values(output)
    servers = next((value for key, value in values.items() if key.casefold().startswith("name servers")), "")
    domain = next((value for key, value in values.items() if key.casefold().startswith("default domain")), "")
    lookup = next((value for key, value in values.items() if key.casefold().startswith("domain name lookup")), "")
    domain = domain.strip()
    return {
        "dns_servers": [server for server in servers.split() if re.fullmatch(_IPV4, server)],
        "domain_name": None if not domain or "not" in domain.casefold() else domain,
        "lookup": lookup.strip().casefold() != "disabled",
    }


def parse_logging_hosts(output: str) -> list[dict]:
    """``show logging hosts``: Index, IP Address/Hostname, Severity, Port, Status, Mode."""
    rows = []
    for line in (output or "").splitlines():
        match = re.match(r"^\s*(\d+)\s+(\S+)\s+([A-Za-z]+|\d)\s+(\d+)\b", line)
        if not match:
            continue
        severity = match.group(3).casefold()
        rows.append({
            "index": int(match.group(1)),
            "host": match.group(2),
            "severity": int(severity) if severity.isdigit() else SEVERITY_NUMBER.get(severity),
            "port": int(match.group(4)),
        })
    return rows


def _table_rows(output: str) -> list[list[str]]:
    """Rows below the dashed separator, columns split at two or more blanks."""
    lines = (output or "").splitlines()
    start = next((index for index, line in enumerate(lines) if re.fullmatch(r"\s*-{3,}[-\s]*", line)), None)
    if start is None:
        return []
    return [re.split(r"\s{2,}", line.strip()) for line in lines[start + 1:] if line.strip()]


def parse_users(output: str) -> list[dict]:
    """``show users``: User Name, Access Mode (Read/Write | Read Only) [, SNMPv3 columns (M5300/M7100)]."""
    users = []
    for row in _table_rows(output):
        if len(row) < 2 or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", row[0]):
            continue
        users.append({
            "name": row[0],
            "privilege": "admin" if "write" in row[1].casefold() else "read_only",
            "_snmp_access": row[2] if len(row) > 2 else None,
            "_snmp_auth": row[3] if len(row) > 3 else None,
            "_snmp_priv": row[4] if len(row) > 4 else None,
        })
    return users


def parse_snmp_users(top: list[str]) -> list[dict]:
    """``snmp-server user``/``group`` lines of the running configuration (12.x/AV)."""
    writers = {"DefaultWrite"}
    for line in top:
        match = re.fullmatch(r'snmp-server group "?([^"\s]+)"? v3 \S+ (.*)', line, re.IGNORECASE)
        if match and re.search(r"\bwrite\b", match.group(2)):
            writers.add(match.group(1))
    users = []
    for line in top:
        match = re.fullmatch(r'snmp-server user "?([^"\s]+)"? "?([^"\s]+)"?(.*)', line, re.IGNORECASE)
        if not match:
            continue
        rest = match.group(3).casefold()
        users.append({
            "name": match.group(1),
            "auth": None,  # SHA-512 is not one of the reported values (sha, sha256)
            "priv": "aes128" if "priv-aes" in rest else None,
            "access": "rw" if match.group(2) in writers else "ro",
            "_group": match.group(2),
        })
    return users


def parse_m71_snmp_users(users: list[dict]) -> list[dict]:
    result = []
    for user in users:
        auth = (user["_snmp_auth"] or "").casefold()
        if auth not in ("sha", "md5"):
            continue
        result.append({
            "name": user["name"],
            "auth": "sha" if auth == "sha" else None,
            "priv": None,
            "access": "rw" if "write" in (user["_snmp_access"] or "").casefold() else "ro",
        })
    return result


def parse_aaa(top: list[str], blocks) -> dict:
    servers: dict[str, dict] = {}
    for line in top:
        match = re.fullmatch(r"radius server host (auth|acct) (\S+)(.*)", line, re.IGNORECASE)
        if match:
            entry = servers.setdefault(match.group(2), {"host": match.group(2), "auth_port": None,
                                                        "acct_port": None, "key_configured": False,
                                                        "_acct_key": False})
            port = re.search(r"\bport (\d+)", match.group(3))
            if match.group(1).casefold() == "auth":
                entry["auth_port"] = int(port.group(1)) if port else 1812
            else:
                entry["acct_port"] = int(port.group(1)) if port else 1813
            continue
        match = re.fullmatch(r"radius server key (auth|acct) (\S+).*", line, re.IGNORECASE)
        if match and match.group(2) in servers:
            servers[match.group(2)]["key_configured" if match.group(1).casefold() == "auth" else "_acct_key"] = True
    tacacs = []
    for match, body in _block(blocks, r"tacacs-server host (\S+)"):
        port = next((int(m.group(1)) for line in body if (m := re.fullmatch(r"port (\d+)", line))), 49)
        tacacs.append({"host": match.group(1), "port": port,
                       "key_configured": any(line.startswith("key") for line in body)})
    order = ["local"]
    for line in top:
        match = re.fullmatch(rf'aaa authentication login "?{LOGIN_LIST}"? (.+)', line, re.IGNORECASE)
        if match:
            methods = [method.casefold() for method in match.group(1).split()]
            order = [method for method in methods if method in ("local", "radius", "tacacs")]
    return {"radius": [server for server in servers.values() if server["auth_port"] is not None],
            "tacacs": tacacs, "login_order": order}


def _enabled(values: dict, *prefixes: str) -> bool | None:
    for key, value in values.items():
        if any(key.casefold().startswith(prefix.casefold()) for prefix in prefixes):
            return value.strip().casefold() in ("enabled", "enable", "true", "yes")
    return None


def parse_ssh(ssh: str, telnet: str | None, http: str | None) -> dict:
    values = parse_key_values(ssh)
    level = next((value for key, value in values.items() if key.casefold().startswith("protocol level")), "")
    timeout = next((value for key, value in values.items() if key.casefold().startswith("ssh timeout")), None)
    minutes = _int(timeout)
    web = None
    if http:
        http_values = parse_key_values(http)
        plain, secure = _enabled(http_values, "HTTP Mode (Unsecure)"), _enabled(http_values, "HTTP Mode (Secure)")
        web = None if plain is None and secure is None else bool(plain or secure)
    return {
        "version": (_int(level) and str(_int(level))) or None,
        "timeout_seconds": minutes * 60 if minutes is not None else None,
        "telnet_enabled": _enabled(parse_key_values(telnet), "Remote Connection Login Mode", "Telnet") if telnet
        else None,
        "web_enabled": web,
    }


def parse_ip_vlan(output: str) -> list[dict]:
    """``show ip vlan``: VLAN ID, Logical Interface, IP Address, Subnet Mask."""
    rows = []
    for line in (output or "").splitlines():
        match = re.match(rf"^\s*(\d{{1,4}})\s+(\S+)\s+({_IPV4})\s+({_IPV4})\s*$", line)
        if match:
            rows.append({"vlan": int(match.group(1)), "logical": match.group(2), "address": match.group(3),
                         "prefix_length": _prefix_length(match.group(4))})
    return rows


def parse_l3(top: list[str], blocks, ip_vlan: list[dict]) -> dict:
    routed = {int(match.group(1)) for _match, body in _block(blocks, r"vlan database")
              for line in body if (match := re.match(r"vlan routing (\d+)", line))}
    helpers: dict[str, list[str]] = {}
    configured: dict[int, tuple[str, int]] = {}
    for match, body in _block(blocks, r"interface (.+)"):
        key = normalize_interface(match.group(1))
        helpers[key] = [m.group(1) for line in body if (m := re.fullmatch(rf"ip helper-address ({_IPV4}).*", line))]
        vlan = _vlan_interface(match.group(1))
        address = next((m for line in body if (m := re.fullmatch(rf"ip address ({_IPV4}) ({_IPV4})", line))), None)
        if vlan is not None and address:
            configured[vlan] = (address.group(1), _prefix_length(address.group(2)))
    svis = {}
    for row in ip_vlan:
        svis[row["vlan"]] = {"vlan": row["vlan"], "address": row["address"], "prefix_length": row["prefix_length"],
                             "dhcp_relay": helpers.get(f"vlan {row['vlan']}") or helpers.get(
                                 normalize_interface(row["logical"]), []),
                             "enabled": True, "_logical": row["logical"]}
    for vlan in sorted(routed | set(configured)):
        if vlan not in svis:
            address, length = configured.get(vlan, (None, None))
            svis[vlan] = {"vlan": vlan, "address": address, "prefix_length": length,
                          "dhcp_relay": helpers.get(f"vlan {vlan}", []), "enabled": True, "_logical": None}
    gateway = None
    routes = []
    for line in top:
        match = re.fullmatch(rf"ip default-gateway ({_IPV4})", line)
        if match:
            gateway = match.group(1)
            continue
        match = re.fullmatch(rf"ip route default ({_IPV4})(?: (\d+))?", line)
        if match:
            gateway = gateway or match.group(1)
            routes.append({"prefix": ANY_ADDRESS, "prefix_length": 0, "next_hop": match.group(1),
                           "distance": int(match.group(2)) if match.group(2) else None})
            continue
        match = re.fullmatch(rf"ip route ({_IPV4}) ({_IPV4}) ({_IPV4})(?: (\d+))?", line)
        if match:
            routes.append({"prefix": match.group(1), "prefix_length": _prefix_length(match.group(2)),
                           "next_hop": match.group(3), "distance": int(match.group(4)) if match.group(4) else None})
    return {"svis": [svis[vlan] for vlan in sorted(svis)], "default_gateway": gateway, "routes": routes,
            "routing_enabled": "ip routing" in top, "_routed": routed}


def _acl_address(tokens: list[str], index: int) -> tuple[str | None, int, int]:
    """(address, prefix length, next index); ``any`` -> (None, 0)."""
    word = tokens[index].casefold() if index < len(tokens) else "any"
    if word == "any":
        return None, 0, index + 1
    if word == "host" and index + 1 < len(tokens):
        return tokens[index + 1], 32, index + 2
    if index + 1 < len(tokens) and re.fullmatch(_IPV4, tokens[index + 1]):
        return tokens[index], _prefix_length(tokens[index + 1], wildcard=True) or 0, index + 2
    return tokens[index], 32, index + 1


def _port(text: str) -> int | None:
    return int(text) if text.isdigit() else PORT_NAMES.get(text.casefold())


def parse_acl_entry(line: str, position: int) -> dict | None:
    tokens = line.split()
    seq = None
    if tokens and tokens[0].isdigit():
        seq, tokens = int(tokens[0]), tokens[1:]
    if len(tokens) < 2 or tokens[0].casefold() not in ("permit", "deny"):
        return None
    protocol = tokens[1].casefold()
    protocol = "ip" if protocol == "every" else protocol
    if protocol not in ("ip", "tcp", "udp", "icmp"):
        return None
    src, src_len, index = _acl_address(tokens, 2)
    dst, dst_len, index = _acl_address(tokens, index) if index < len(tokens) else (None, 0, index)
    op = port = end = None
    if index < len(tokens) and tokens[index] in ("eq", "range") and index + 1 < len(tokens):
        op, port = tokens[index], _port(tokens[index + 1])
        if op == "range" and index + 2 < len(tokens):
            end = _port(tokens[index + 2])
    return {"seq": seq if seq is not None else position, "action": tokens[0].casefold(), "protocol": protocol,
            "src": src or ANY_ADDRESS, "src_len": src_len, "dst": dst, "dst_len": dst_len if dst else None,
            "dst_port_op": op, "dst_port": port, "dst_port_end": end}


def parse_acls(top: list[str], blocks) -> list[dict]:
    acls = []
    for match, body in _block(blocks, r"ip access-list (.+)"):
        entries = [entry for position, line in enumerate(body, 1) if (entry := parse_acl_entry(line, position))]
        standard = all(entry["protocol"] == "ip" and entry["dst"] is None and entry["dst_port_op"] is None
                       for entry in entries)
        acls.append({"name": _unquote(match.group(1)), "type": "standard" if standard else "extended",
                     "entries": entries, "bindings": []})
    by_name = {acl["name"]: acl for acl in acls}
    for match, body in _block(blocks, r"interface (.+)"):
        for line in body:
            bound = re.fullmatch(r'ip access-group "?([^"\s]+)"? (in|out)\b.*', line)
            if bound and bound.group(1) in by_name:
                by_name[bound.group(1)]["bindings"].append({"interface": match.group(1).strip(),
                                                            "direction": bound.group(2)})
    for line in top:
        bound = re.fullmatch(r'ip access-group "?([^"\s]+)"? vlan (\d+) (in|out)\b.*', line)
        if bound and bound.group(1) in by_name:
            by_name[bound.group(1)]["bindings"].append({"interface": f"vlan {bound.group(2)}",
                                                        "direction": bound.group(3)})
    return acls


def parse_qos(top: list[str], blocks, ports: list[str]) -> dict:
    default = "cos"
    for line in top:
        match = re.fullmatch(r"classofservice trust (\S+)", line)
        if match:
            default = TRUST_BY_KEYWORD.get(match.group(1))
    bodies = {normalize_interface(match.group(1)): body for match, body in _block(blocks, r"interface (.+)")}
    trust, voice = {}, {}
    for port in ports:
        body = bodies.get(normalize_interface(port), [])
        value = default
        for line in body:
            match = re.fullmatch(r"classofservice trust (\S+)", line)
            if match:
                value = TRUST_BY_KEYWORD.get(match.group(1))
        trust[port] = {"trust": value}
        voice[port] = "auto-voip protocol-based" in body
    return {"ports": trust, "voice_preset": voice}


def parse_bootvar(output: str) -> dict:
    """``show bootvar``: per unit image1/image2 versions, current-active, next-active (unit 1)."""
    for line in (output or "").splitlines():
        tokens = line.split()
        if len(tokens) >= 3 and tokens[0].isdigit() and tokens[-1] in SLOTS and tokens[-2] in SLOTS:
            versions = tokens[1:-2]
            return {"versions": dict(zip(SLOTS, versions + [None] * (2 - len(versions)), strict=False)),
                    "active": tokens[-2], "next": tokens[-1]}
    return {"versions": {}, "active": None, "next": None}


_COUNTER_KEYS = {
    "in_octets": ("Total Packets Received (Octets)", "Bytes Received"),
    "out_octets": ("Total Packets Transmitted (Octets)", "Bytes Transmitted"),
    "in_errors": ("Total Packets Received with MAC Errors", "Packets Received With Error"),
    "out_errors": ("Total Transmit Errors", "Transmit Packet Errors"),
    "crc": ("FCS Errors",),
    "drops_in": ("Total Received Packets Not Forwarded", "Receive Packets Discarded"),
    "drops_out": ("Total Transmit Packets Discarded", "Transmit Packets Discarded"),
}
_COLLISION_KEYS = ("Single Collision Frames", "Multiple Collision Frames", "Excessive Collision Frames",
                   "Total Collision Frames")


def parse_counters(output: str, interface: str) -> dict:
    """``show interface ethernet {if}`` (detail) or ``show interface {if}`` (summary)."""
    values = parse_key_values(output)
    row = {"interface": interface}
    for field, keys in _COUNTER_KEYS.items():
        row[field] = next((_int(values[key]) for key in keys if key in values), None)
    collisions = [_int(values[key]) for key in _COLLISION_KEYS if key in values]
    row["collisions"] = sum(value for value in collisions if value is not None) if collisions else None
    return row


def parse_transceivers(output: str) -> list[dict]:
    """``show fiber-ports optics all``: Port Temp Voltage Current Output Input TX-Fault LOS."""
    number = r"(-?\d+(?:\.\d+)?|N/A|-+)"
    pattern = re.compile(rf"^\s*(\d+/\d+(?:/\d+)?)\s+{number}\s+{number}\s+{number}\s+{number}\s+{number}"
                         r"\s+(\S+)\s+(\S+)\s*$")
    rows = []
    for line in (output or "").splitlines():
        match = pattern.match(line)
        if not match:
            continue
        alarms = [label for label, value in (("TX Fault", match.group(7)), ("LOS", match.group(8)))
                  if value.casefold() == "yes"]
        rows.append({"interface": match.group(1), "type": None, "temperature_c": _float(match.group(2)),
                     "voltage_v": _float(match.group(3)), "tx_power_dbm": _float(match.group(5)),
                     "rx_power_dbm": _float(match.group(6)), "alarm": ", ".join(alarms) or None})
    return rows


def parse_log(output: str) -> list[str]:
    """``show logging buffered``: the log entries (``<pri> date …``); else every non-empty line."""
    lines = [line.rstrip() for line in (output or "").splitlines() if line.strip()]
    entries = [line for line in lines if re.match(r"^\s*<\d+>", line)]
    return entries or lines


def parse_environment(output: str) -> dict:
    """``show environment``: temperature sensors, fans and power supplies (unit tables)."""
    result = {"temperatures": [], "fans": [], "power_supplies": []}
    section = None
    for line in (output or "").splitlines():
        lowered = line.casefold()
        if lowered.startswith("unit"):
            section = ("temperatures" if "sensor" in lowered else "fans" if "fan" in lowered
                       else "power_supplies" if "power" in lowered else None)
            continue
        if section == "temperatures":
            match = re.match(r"^\s*\d+\s+\d+\s+(.+?)\s+(-?\d+(?:\.\d+)?)\s+(\S.*?)\s*$", line)
            if match:
                result["temperatures"].append({"sensor": match.group(1), "celsius": float(match.group(2)),
                                               "status": match.group(3)})
        elif section == "fans":
            match = re.match(r"^\s*\d+\s+\d+\s+(\S+)\s+(?:Fixed|Removable)\s+(?:\d+|N/A)?\s*(\S.*?)\s*$", line)
            if match:
                result["fans"].append({"name": match.group(1), "status": match.group(2)})
        elif section == "power_supplies":
            match = re.match(r"^\s*\d+\s+\d+\s+(\S+)\s+(?:Fixed|Removable)\s+(\S.*?)\s*$", line)
            if match:
                result["power_supplies"].append({"name": match.group(1), "status": match.group(2), "watts": None})
    return result


def parse_cable_status(output: str) -> dict:
    """``cablestatus {if}``: ``Cable Status…… Normal``, ``Cable Length…… 3 - 5m`` (one or more blocks)."""
    statuses = re.findall(r"(?im)^\s*Cable Status\s*\.{2,}:?\s*(.+?)\s*$", output or "")
    lengths = re.findall(r"(?im)^\s*Cable Length\s*\.{2,}:?\s*(.+?)\s*$", output or "")
    pairs = []
    for index, status in enumerate(statuses):
        length = lengths[index] if index < len(lengths) else ""
        numbers = [float(value) for value in re.findall(r"\d+(?:\.\d+)?", length)]
        pairs.append({"pair": str(index + 1) if len(statuses) > 1 else "1-8",
                      "status": re.sub(r"\s+", "_", status.strip().casefold()),
                      "length_m": max(numbers) if numbers else None})
    return {"status": "done", "pairs": pairs}


# --- Plan building ---------------------------------------------------------------------------


class _Builder:
    """Ordered plan items: configuration lines, interactive configuration commands, exec commands.

    Consecutive configuration items form one block: plain lines are one ``CliLines`` step; a
    block with interactive commands runs inside ``configure`` … ``exit`` (exec steps).
    """

    def __init__(self):
        self.items: list[tuple] = []
        self.secrets: list[str] = []
        self.warnings: list[str] = []

    def line(self, shown: str, sent: str | None = None, *secrets: str) -> None:
        self.items.append(("line", (shown,), sent if sent is not None else shown, ()))
        self.secrets.extend(secret for secret in secrets if secret)

    def prompt(self, command: str, answer: str, answers: int = 2) -> None:
        """Interactive configuration command; ``answer`` (a secret) is typed ``answers`` times."""
        self.items.append(("prompt", (command,) + (REDACTED,) * answers, command, ((SECRET_PROMPT, answer),)))
        self.secrets.append(answer)

    def exec(self, command: str, prompts: tuple = ()) -> None:
        self.items.append(("exec", (command,), command, prompts))

    def __bool__(self) -> bool:
        return bool(self.items)

    def plan(self, **kwargs) -> ChangePlan:
        if not self.items:
            raise _no_change()
        shown: list[str] = []
        steps: list = []
        index = 0
        while index < len(self.items):
            kind = self.items[index][0]
            if kind == "exec":
                _kind, lines, command, prompts = self.items[index]
                shown.extend(lines)
                steps.append(CliCommand(command, prompts=prompts))
                index += 1
                continue
            end = index
            while end < len(self.items) and self.items[end][0] != "exec":
                end += 1
            block = self.items[index:end]
            index = end
            if all(item[0] == "line" for item in block):
                shown.extend(item[1][0] for item in block)
                steps.append(CliLines(tuple(item[2] for item in block)))
                continue
            shown.append("configure")
            steps.append(CliCommand("configure"))
            pending: list[str] = []
            for kind_, lines, sent, prompts in block:
                shown.extend(lines)
                if kind_ == "line":
                    pending.append(sent)
                    continue
                if pending:
                    steps.append(CliLines(tuple(pending), enter=False, exit=False))
                    pending = []
                steps.append(CliCommand(sent, prompts=prompts))
            if pending:
                steps.append(CliLines(tuple(pending), enter=False, exit=False))
            shown.append("exit")
            steps.append(CliCommand("exit"))
        return ChangePlan(lines=tuple(shown), steps=tuple(steps), secrets=tuple(dict.fromkeys(self.secrets)),
                          warnings=tuple(self.warnings) + tuple(kwargs.pop("warnings", ())), **kwargs)


def _vlan_database_plan(commands: list[str]) -> ChangePlan:
    lines = ("vlan database", *commands)
    return ChangePlan(lines=lines + ("exit",), steps=(CliLines(lines, enter=False, exit=False),))


def _acl_operand(address: str | None, prefix_length: int | None) -> str:
    if address is None or not prefix_length:
        return "any"
    network = validate_ipv4_prefix(address, prefix_length)
    if network.prefixlen == 32:
        return f"host {network.network_address}"
    return f"{network.network_address} {_wildcard(network.prefixlen)}"


def _public(value):
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items() if not key.startswith("_")}
    if isinstance(value, list):
        return [_public(item) for item in value]
    if isinstance(value, set):
        return sorted(value)
    return value


class NetgearDeviceMixin:
    """Device settings, firmware and diagnostics reads and plans of the Netgear driver."""

    # --- Shared reads ---------------------------------------------------------------------------

    def _device_sections(self, session: transport.SshSession):
        return config_sections(self._running_text(session))

    def _optional_text(self, session: transport.SshSession, command: str) -> str | None:
        output, status = self._optional(session, command)
        return output if status == "ok" else None

    def _is_av(self, session: transport.SshSession) -> bool:
        return self._family(session) == FAMILY_AV

    def _is_m71(self, session: transport.SshSession) -> bool:
        """M5300/M7100 (firmware 11.0): selected/detected model profile, else ``show version``."""
        profile = selected_profile(self, session.switch or {})
        if profile is not None:
            return profile.id.startswith(("m5300", "m7100"))
        return bool(_M71_RE.search(self._model(session) or ""))

    def _users(self, session: transport.SshSession) -> list[dict]:
        if "netgear:users" not in session.cache:
            session.cache["netgear:users"] = parse_users(self._show(session, "show users"))
        return session.cache["netgear:users"]

    def _snmp_users(self, session: transport.SshSession) -> list[dict]:
        if self._is_m71(session):
            return parse_m71_snmp_users(self._users(session))
        top, _blocks = self._device_sections(session)
        return parse_snmp_users(top)

    def _services(self, session: transport.SshSession) -> dict:
        command = "show ntp servers" if self._is_av(session) else "show sntp server"
        hosts = parse_hosts(self._optional_text(session, "show hosts") or "")
        return {
            "ntp_servers": parse_time_servers(self._optional_text(session, command) or ""),
            "timezone": parse_clock(self._optional_text(session, "show clock") or ""),
            "dns_servers": hosts["dns_servers"],
            "domain_name": hosts["domain_name"],
            "syslog": parse_logging_hosts(self._optional_text(session, "show logging hosts") or ""),
            "_lookup": hosts["lookup"],
        }

    def _l3(self, session: transport.SshSession) -> dict:
        top, blocks = self._device_sections(session)
        return parse_l3(top, blocks, parse_ip_vlan(self._optional_text(session, "show ip vlan") or ""))

    def _acls(self, session: transport.SshSession) -> list[dict]:
        return parse_acls(*self._device_sections(session))

    def _acl(self, session: transport.SshSession, name: str) -> dict:
        name = validate_acl_name(name)
        acl = next((acl for acl in self._acls(session) if acl["name"] == name), None)
        if acl is None:
            raise InvalidInputError(t("ACL {name} existiert auf dem Switch nicht.", name=name))
        return acl

    def _check_own_account(self, session: transport.SshSession, name: str | None) -> None:
        if name is not None and name == (session.credentials or {}).get("username"):
            raise InvalidInputError(t("Das Konto, mit dem SwitchSteward sich anmeldet, kann hier nicht geändert werden."))

    # --- Device settings read -----------------------------------------------------------------------------

    def read_device_config(self, session: transport.SshSession) -> dict:
        top, blocks = self._device_sections(session)
        ssh = self._optional_text(session, "show ip ssh")
        ports = [row["port"] for row in self.read_interfaces(session) if self.is_physical_interface(row["port"])]
        services = self._services(session)
        return {
            "identity": parse_identity(self._optional_text(session, "show sysinfo") or "", top),
            "services": _public({**services, "syslog": [{"host": row["host"], "severity": row["severity"]}
                                                        for row in services["syslog"]]}),
            "snmp": {"users": _public(self._snmp_users(session))},
            "aaa": _public(parse_aaa(top, blocks)),
            "users": _public(self._users(session)),
            "ssh": parse_ssh(ssh, self._optional_text(session, "show ip telnet"),
                             self._optional_text(session, "show ip http")) if ssh else None,
            "l3": _public(self._l3(session)),
            "acls": _public(parse_acls(top, blocks)),
            "qos": parse_qos(top, blocks, ports),
        }

    # --- Identity and services ----------------------------------------------------------

    def plan_device_identity(self, session: transport.SshSession, change: IdentityChange) -> ChangePlan:
        top, _blocks = self._device_sections(session)
        current = parse_identity(self._optional_text(session, "show sysinfo") or "", top)
        plan = _Builder()
        if change.banner is not None:
            if change.banner == "":
                if current["banner"] is not None:
                    plan.line("no set clibanner")
            else:
                banner = validate_banner(change.banner).strip("\n")
                if "\n" in banner:
                    raise InvalidInputError(t("Der Banner darf auf dieser Plattform nur eine Zeile haben."))
                if banner != current["banner"]:
                    plan.line(f'set clibanner "{banner}"')
        for field, keyword in (("snmp_location", "location"), ("snmp_contact", "contact")):
            value = getattr(change, field)
            if value is None:
                continue
            if value == "":
                if current[field] is not None:
                    plan.line(f"no snmp-server {keyword}")
            elif (text := _short_text(value)) != current[field]:
                plan.line(f'snmp-server {keyword} "{text}"')
        if change.hostname is not None and validate_hostname(change.hostname) != current["hostname"]:
            if len(change.hostname) > SNMP_TEXT_MAX_LENGTH:
                raise InvalidInputError(t("Der Text darf auf dieser Plattform höchstens {limit} Zeichen haben.",
                                          limit=SNMP_TEXT_MAX_LENGTH))
            plan.line(f"snmp-server sysname {change.hostname}")
            # Privileged EXEC and last: the prompt changes with the hostname (see ``_run_command``).
            plan.exec(f"hostname {change.hostname}")
        return plan.plan()

    def plan_device_services(self, session: transport.SshSession, change: ServicesChange) -> ChangePlan:
        current = self._services(session)
        plan = _Builder()
        if change.ntp_servers is not None:
            self._plan_time_servers(session, plan, current["ntp_servers"],
                                    list(dict.fromkeys(validate_host(server) for server in change.ntp_servers)))
        if change.timezone_offset_minutes is not None:
            self._plan_timezone(plan, current["timezone"], change.timezone_name, change.timezone_offset_minutes)
        if change.dns_servers is not None:
            wanted = list(dict.fromkeys(validate_ipv4(server) for server in change.dns_servers))
            for server in current["dns_servers"]:
                if server not in wanted:
                    plan.line(f"no ip name-server {server}")
            added = [server for server in wanted if server not in current["dns_servers"]]
            if added and not current["_lookup"]:
                plan.line("ip domain lookup")
            for server in added:
                plan.line(f"ip name-server {server}")
        if change.domain_name is not None:
            if change.domain_name == "":
                if current["domain_name"] is not None:
                    plan.line("no ip domain name")
            elif (domain := validate_host(change.domain_name)) != current["domain_name"]:
                plan.line(f"ip domain name {domain}")
        if change.syslog is not None:
            self._plan_syslog(plan, current["syslog"], change.syslog)
        return plan.plan()

    def _plan_time_servers(self, session, plan: _Builder, current: list[str], wanted: list[str]) -> None:
        av = self._is_av(session)
        limit = NTP_MAX_SERVERS if av else SNTP_MAX_SERVERS
        if len(wanted) > limit:
            raise InvalidInputError(t("Diese Plattform unterstützt höchstens {count} Zeitserver.", count=limit))
        for server in current:
            if server not in wanted:
                plan.line(f"no ntp server {server}" if av else f"no sntp server remove {server}")
        added = [server for server in wanted if server not in current]
        if added and not av:
            plan.line("sntp client mode unicast")
        for server in added:
            plan.line(f"ntp server {server}" if av else f"sntp server {server}")

    @staticmethod
    def _plan_timezone(plan: _Builder, current: dict, name: str | None, offset: int) -> None:
        if name is not None and not re.fullmatch(r"[A-Za-z]{1,6}", name):
            raise InvalidInputError(t("Ungültige Zeitzone: {value}", value=repr(name)))
        if not isinstance(offset, int) or not -12 * 60 <= offset <= 13 * 60 + 59:
            raise InvalidInputError(t("Ungültige Zeitzone: {value}", value=repr(offset)))
        if current["offset_minutes"] == offset and (name is None or current["name"] == name):
            return
        hours, minutes = divmod(abs(offset), 60)
        line = f"clock timezone {'-' if offset < 0 else ''}{hours}"
        if minutes:
            line += f" minutes {minutes}"
        if name:
            line += f" zone {name}"
        plan.line(line)

    @staticmethod
    def _plan_syslog(plan: _Builder, current: list[dict], targets) -> None:
        wanted: dict[str, int] = {}
        for target in targets:
            host = validate_ipv4(target.host)
            if host in wanted:
                raise InvalidInputError(t("Jeder Server darf nur einmal angegeben werden."))
            if not isinstance(target.severity, int) or not 0 <= target.severity <= 7:
                raise InvalidInputError(t("Ungültiger Wert für {label}: {value}", label="severity",
                                          value=repr(target.severity)))
            wanted[host] = target.severity
        keep = set()
        # Descending index order: a removal never renumbers an entry removed later.
        for row in sorted(current, key=lambda row: row["index"], reverse=True):
            if wanted.get(row["host"]) == row["severity"] and row["port"] == SYSLOG_PORT and row["host"] not in keep:
                keep.add(row["host"])
            else:
                plan.line(f"logging host remove {row['index']}")
        added = [host for host in wanted if host not in keep]
        for host in added:
            plan.line(f"logging host {host} ipv4 {SYSLOG_PORT} {wanted[host]}")
        if added:
            plan.line("logging syslog")

    # --- SNMPv3, AAA, users, access -----------------------------------------------------------

    def plan_snmp_user_set(self, session: transport.SshSession, user: SnmpUserChange) -> ChangePlan:
        name = validate_username(user.name)
        validate_choice(user.access, ("ro", "rw"), "SNMP")
        auth_key = validate_secret(user.auth_key)
        if self._is_m71(session):
            return self._plan_m71_snmp_user(session, name, user, auth_key)
        priv_key = None
        if user.priv is not None:
            if not user.priv_key:
                raise InvalidInputError(t("Für die Verschlüsselung ist ein Schlüssel erforderlich."))
            priv_key = validate_secret(user.priv_key)
        top, _blocks = self._device_sections(session)
        level = "priv" if priv_key else "auth"
        group = f"SWM_{user.access.upper()}_{level.upper()}"
        plan = _Builder()
        plan.warnings.append(t("Diese Plattform unterstützt für SNMPv3 nur SHA-512; der Benutzer wird mit SHA-512 "
                               "angelegt."))
        if not any(line.startswith(f"snmp-server view {SNMP_VIEW} ") for line in top):
            plan.line(f"snmp-server view {SNMP_VIEW} 1.3.6.1 included")
        if not any(re.match(rf'snmp-server group "?{group}"? ', line) for line in top):
            write = f" write {SNMP_VIEW}" if user.access == "rw" else ""
            plan.line(f"snmp-server group {group} v3 {level} read {SNMP_VIEW}{write}")
        if any(existing["name"] == name for existing in parse_snmp_users(top)):
            plan.line(f"no snmp-server user {name}")
        command = f"snmp-server user {name} {group} auth-sha512 "
        shown, sent = command + REDACTED, command + auth_key
        if priv_key:
            shown += f" priv-aes128 {REDACTED}"
            sent += f" priv-aes128 {priv_key}"
        plan.line(shown, sent, auth_key, priv_key)
        return plan.plan()

    def _plan_m71_snmp_user(self, session, name: str, user: SnmpUserChange, auth_key: str) -> ChangePlan:
        """SNMPv3 belongs to a local user; its login password is the authentication key (SHA, no AES)."""
        if user.priv is not None or user.priv_key:
            raise InvalidInputError(t("M5300/M7100 unterstützen für SNMPv3 nur SHA und DES; AES-128 ist nicht "
                                      "möglich."))
        self._check_own_account(session, name)
        local = next((entry for entry in self._users(session) if entry["name"] == name), None)
        if local is None:
            raise InvalidInputError(t("Auf M5300/M7100 ist ein SNMPv3-Benutzer ein lokaler Benutzer; bitte zuerst "
                                      "den lokalen Benutzer {name} anlegen.", name=name))
        plan = _Builder()
        plan.warnings.append(t("Auf M5300/M7100 ist der SNMPv3-Schlüssel das Anmeldepasswort des lokalen Benutzers; "
                               "es wird auf den angegebenen Schlüssel gesetzt."))
        level = 15 if local["privilege"] == "admin" else 1
        plan.prompt(f"username {name} level {level} password", auth_key)
        plan.line(f"username snmpv3 accessmode {name} {'readwrite' if user.access == 'rw' else 'readonly'}")
        plan.line(f"username snmpv3 authentication {name} sha")
        plan.line(f"username snmpv3 encryption {name} none")
        return plan.plan()

    def plan_snmp_user_delete(self, session: transport.SshSession, name: str) -> ChangePlan:
        name = validate_username(name)
        if not any(user["name"] == name for user in self._snmp_users(session)):
            raise InvalidInputError(t("SNMP-Benutzer {name} existiert auf dem Switch nicht.", name=name))
        plan = _Builder()
        if self._is_m71(session):
            plan.line(f"username snmpv3 authentication {name} none")
            plan.line(f"username snmpv3 encryption {name} none")
        else:
            plan.line(f"no snmp-server user {name}")
        return plan.plan()

    def plan_device_aaa(self, session: transport.SshSession, change: AaaChange) -> ChangePlan:
        top, blocks = self._device_sections(session)
        current = parse_aaa(top, blocks)
        plan = _Builder()
        if change.radius is not None:
            self._plan_radius(plan, current["radius"], change.radius)
        if change.tacacs is not None:
            self._plan_tacacs(plan, current["tacacs"], change.tacacs)
        if change.login_order is not None:
            order = list(dict.fromkeys(change.login_order))
            if "local" not in order:
                raise InvalidInputError(t("Die lokale Anmeldung muss als Rückfallebene erhalten bleiben."))
            if order[-1] != "local":
                raise InvalidInputError(t("Die lokale Anmeldung muss auf dieser Plattform die letzte Methode sein."))
            servers = {
                "radius": change.radius if change.radius is not None else current["radius"],
                "tacacs": change.tacacs if change.tacacs is not None else current["tacacs"],
            }
            for method in order:
                if method != "local" and not servers[method]:
                    raise InvalidInputError(t("Für die Anmeldung über {method} ist kein Server konfiguriert.",
                                              method=method))
            if order != current["login_order"]:
                plan.line(f'aaa authentication login "{LOGIN_LIST}" {" ".join(order)}')
        return plan.plan()

    @staticmethod
    def _radius_key(key: str) -> str:
        key = validate_secret(key)
        if not RADIUS_KEY_RE.fullmatch(key):
            raise InvalidInputError(t("RADIUS-Schlüssel dürfen auf dieser Plattform höchstens 16 Buchstaben und "
                                      "Ziffern haben."))
        return key

    def _plan_radius(self, plan: _Builder, configured: list[dict], wanted) -> None:
        hosts = [validate_ipv4(server.host) for server in wanted]
        if len(set(hosts)) != len(hosts):
            raise InvalidInputError(t("Jeder Server darf nur einmal angegeben werden."))
        existing = {server["host"]: server for server in configured}
        for server in configured:
            if server["host"] not in hosts:
                plan.line(f"no radius server host auth {server['host']}")
                if server["acct_port"] is not None:
                    plan.line(f"no radius server host acct {server['host']}")
        for host, server in zip(hosts, wanted, strict=True):
            old = existing.get(host)
            if old is None and not server.key:
                raise InvalidInputError(t("Für den neuen Server {host} ist ein Schlüssel erforderlich.", host=host))
            key = self._radius_key(server.key) if server.key else None
            if old is None or old["auth_port"] != server.auth_port:
                plan.line(f"radius server host auth {host} port {server.auth_port}")
            if old is None or old["acct_port"] != server.acct_port:
                plan.line(f"radius server host acct {host} port {server.acct_port}")
            if key:
                plan.prompt(f"radius server key auth {host}", key)
                plan.prompt(f"radius server key acct {host}", key)

    def _plan_tacacs(self, plan: _Builder, configured: list[dict], wanted) -> None:
        hosts = [validate_ipv4(server.host) for server in wanted]
        if len(set(hosts)) != len(hosts):
            raise InvalidInputError(t("Jeder Server darf nur einmal angegeben werden."))
        existing = {server["host"]: server for server in configured}
        for server in configured:
            if server["host"] not in hosts:
                plan.line(f"no tacacs-server host {server['host']}")
        for host, server in zip(hosts, wanted, strict=True):
            old = existing.get(host)
            if old is None and not server.key:
                raise InvalidInputError(t("Für den neuen Server {host} ist ein Schlüssel erforderlich.", host=host))
            key = validate_secret(server.key) if server.key else None
            if not (0 < int(server.port) < 65536):
                raise InvalidInputError(t("Ungültiger Wert für {label}: {value}", label="port", value=repr(server.port)))
            if old is not None and key is None and old["port"] == server.port:
                continue
            plan.line(f"tacacs-server host {host}")
            if key:
                plan.line(f"key {REDACTED}", f"key {key}", key)
            plan.line(f"port {server.port}")
            plan.line("exit")

    def plan_device_user_set(
        self, session: transport.SshSession, name: str, password: str | None, privilege: str,
    ) -> ChangePlan:
        """``username {name} level {15|1} password`` asks for the password twice (interactive)."""
        name = validate_username(name)
        self._check_own_account(session, name)
        privilege = validate_choice(privilege, ("admin", "read_only"), "Privileg")
        existing = next((user for user in self._users(session) if user["name"] == name), None)
        if password is None:
            if existing is None:
                raise InvalidInputError(t("Für einen neuen Benutzer ist ein Passwort erforderlich."))
            if existing["privilege"] == privilege:
                raise _no_change()
            raise InvalidInputError(t("Diese Plattform ändert die Berechtigung eines Benutzers nur zusammen mit dem "
                                      "Passwort."))
        password = validate_secret(password)
        plan = _Builder()
        plan.prompt(f"username {name} level {15 if privilege == 'admin' else 1} password", password)
        return plan.plan()

    def plan_device_user_delete(self, session: transport.SshSession, name: str) -> ChangePlan:
        name = validate_username(name)
        self._check_own_account(session, name)
        if not any(user["name"] == name for user in self._users(session)):
            raise InvalidInputError(t("Benutzer {name} existiert auf dem Switch nicht.", name=name))
        plan = _Builder()
        plan.line(f"no username {name}")
        return plan.plan()

    def plan_device_ssh(
        self, session: transport.SshSession, timeout_seconds: int | None, telnet_enabled: bool | None,
        web_enabled: bool | None,
    ) -> ChangePlan:
        """All switches are Privileged EXEC commands."""
        ssh = self._optional_text(session, "show ip ssh") or ""
        current = parse_ssh(ssh, self._optional_text(session, "show ip telnet"),
                            self._optional_text(session, "show ip http"))
        plan = _Builder()
        if timeout_seconds is not None:
            minutes = math.ceil(int(timeout_seconds) / 60)
            if not 1 <= minutes <= SSH_TIMEOUT_MAX_MINUTES:
                raise InvalidInputError(t("Ungültiger Wert für {label}: {value}", label="timeout",
                                          value=repr(timeout_seconds)))
            if current["timeout_seconds"] != minutes * 60:
                plan.exec(f"sshcon timeout {minutes}")
        if telnet_enabled is not None and telnet_enabled != current["telnet_enabled"]:
            plan.exec("ip telnet server enable" if telnet_enabled else "no ip telnet server enable")
        if web_enabled is not None and web_enabled != current["web_enabled"]:
            prefix = "" if web_enabled else "no "
            plan.exec(f"{prefix}ip http server")
            plan.exec(f"{prefix}ip http secure-server")
        return plan.plan()

    # --- L3 ---------------------------------------------------------------------------------

    def plan_svi_set(
        self, session: transport.SshSession, vlan: int, address: str, prefix_length: int, dhcp_relay: tuple[str, ...],
    ) -> ChangePlan:
        vlan = validate_vlan_id(vlan)
        address = validate_ipv4(address)
        try:
            network = ipaddress.IPv4Interface(f"{address}/{int(prefix_length)}").network
        except (ValueError, TypeError):
            raise InvalidInputError(t("Ungültiges IPv4-Netz: {value}", value=repr(f"{address}/{prefix_length}"))) from None
        if not 1 <= network.prefixlen <= 31:
            raise InvalidInputError(t("Ungültiges IPv4-Netz: {value}", value=repr(f"{address}/{prefix_length}")))
        relays = list(dict.fromkeys(validate_ipv4(server) for server in dhcp_relay))
        if vlan not in self._existing_vlans(session):
            raise InvalidInputError(t("VLAN {vlan} existiert auf dem Switch nicht.", vlan=vlan))
        l3 = self._l3(session)
        svi = next((svi for svi in l3["svis"] if svi["vlan"] == vlan), None)
        plans = []
        if vlan not in l3["_routed"] and svi is None:
            plans.append(_vlan_database_plan([f"vlan routing {vlan}"]))
        current_relays = svi["dhcp_relay"] if svi else []
        body = _Builder()
        if svi is None or svi["address"] != address or svi["prefix_length"] != network.prefixlen:
            body.line(f"ip address {address} {_mask(network.prefixlen)}")
        for server in current_relays:
            if server not in relays:
                body.line(f"no ip helper-address {server} dhcp")
        for server in relays:
            if server not in current_relays:
                body.line(f"ip helper-address {server} dhcp")
        if body or plans:
            interface = _Builder()
            interface.line(f"interface vlan {vlan}")
            if svi is None:
                interface.line("routing")
            interface.items.extend(body.items)
            interface.line("exit")
            if relays and set(relays) - set(current_relays):
                interface.line("ip helper enable")
            plans.append(interface.plan())
        if not plans:
            raise _no_change()
        return combine_plans(*plans)

    def plan_svi_delete(self, session: transport.SshSession, vlan: int) -> ChangePlan:
        vlan = validate_vlan_id(vlan)
        l3 = self._l3(session)
        if vlan not in l3["_routed"] and not any(svi["vlan"] == vlan for svi in l3["svis"]):
            raise InvalidInputError(t("Das VLAN-Interface {vlan} existiert auf dem Switch nicht.", vlan=vlan))
        return _vlan_database_plan([f"no vlan routing {vlan}"])

    def plan_gateway(self, session: transport.SshSession, gateway: str) -> ChangePlan:
        """``ip default-gateway`` without routing, ``ip route default`` with ``ip routing``."""
        gateway = validate_ipv4(gateway)
        l3 = self._l3(session)
        top, _blocks = self._device_sections(session)
        plan = _Builder()
        if l3["routing_enabled"]:
            defaults = [route["next_hop"] for route in l3["routes"] if route["prefix_length"] == 0]
            if defaults == [gateway]:
                raise _no_change()
            for hop in defaults:
                if hop != gateway:
                    plan.line(f"no ip route default {hop}")
            if gateway not in defaults:
                plan.line(f"ip route default {gateway}")
        else:
            current = next((match.group(1) for line in top
                            if (match := re.fullmatch(rf"ip default-gateway ({_IPV4})", line))), None)
            if current == gateway:
                raise _no_change()
            if current:
                plan.line(f"no ip default-gateway {current}")
            plan.line(f"ip default-gateway {gateway}")
        return plan.plan()

    @staticmethod
    def _route_target(prefix: str, prefix_length: int) -> str:
        network = validate_ipv4_prefix(prefix, prefix_length)
        if network.prefixlen == 0:
            return "default"
        return f"{network.network_address} {network.netmask}"

    def plan_route_add(
        self, session: transport.SshSession, prefix: str, prefix_length: int, next_hop: str, distance: int | None,
    ) -> ChangePlan:
        target = self._route_target(prefix, prefix_length)
        next_hop = validate_ipv4(next_hop)
        if distance is not None and not 1 <= int(distance) <= 255:
            raise InvalidInputError(t("Ungültiger Wert für {label}: {value}", label="distance", value=repr(distance)))
        network = validate_ipv4_prefix(prefix, prefix_length)
        for route in self._l3(session)["routes"]:
            if (route["prefix"], route["prefix_length"], route["next_hop"]) == (
                str(network.network_address), network.prefixlen, next_hop,
            ) and route["distance"] == distance:
                raise _no_change()
        plan = _Builder()
        plan.line(f"ip route {target} {next_hop}" + (f" {distance}" if distance is not None else ""))
        return plan.plan()

    def plan_route_delete(
        self, session: transport.SshSession, prefix: str, prefix_length: int, next_hop: str,
    ) -> ChangePlan:
        target = self._route_target(prefix, prefix_length)
        next_hop = validate_ipv4(next_hop)
        network = validate_ipv4_prefix(prefix, prefix_length)
        if not any((route["prefix"], route["prefix_length"], route["next_hop"])
                   == (str(network.network_address), network.prefixlen, next_hop)
                   for route in self._l3(session)["routes"]):
            raise InvalidInputError(t("Die Route existiert auf dem Switch nicht."))
        plan = _Builder()
        plan.line(f"no ip route {target} {next_hop}")
        return plan.plan()

    # --- ACLs --------------------------------------------------------------------------

    def plan_acl_create(self, session: transport.SshSession, name: str, acl_type: str) -> ChangePlan:
        """Netgear has only named extended ACLs; the type is not stored."""
        name = validate_acl_name(name)
        validate_choice(acl_type, ("standard", "extended"), "ACL")
        if any(acl["name"] == name for acl in self._acls(session)):
            raise InvalidInputError(t("ACL {name} existiert bereits.", name=name))
        plan = _Builder()
        plan.line(f"ip access-list {name}")
        plan.line("exit")
        return plan.plan()

    def plan_acl_delete(self, session: transport.SshSession, name: str) -> ChangePlan:
        acl = self._acl(session, name)
        if acl["bindings"]:
            interfaces = ", ".join(f"{binding['interface']} ({binding['direction']})" for binding in acl["bindings"])
            raise InvalidInputError(t("Die ACL ist noch an {interfaces} gebunden.", interfaces=interfaces))
        plan = _Builder()
        plan.line(f"no ip access-list {acl['name']}")
        return plan.plan()

    def plan_acl_entry_add(self, session: transport.SshSession, name: str, entry: AclEntry) -> ChangePlan:
        acl = self._acl(session, name)
        if any(existing["seq"] == entry.seq for existing in acl["entries"]):
            raise InvalidInputError(t("Der Eintrag {seq} existiert bereits.", seq=entry.seq))
        validate_choice(entry.action, ("permit", "deny"), "ACL")
        validate_choice(entry.protocol, ("ip", "tcp", "udp", "icmp"), "ACL")
        parts = [str(int(entry.seq)), entry.action, entry.protocol, _acl_operand(entry.src, entry.src_len),
                 _acl_operand(entry.dst, entry.dst_len)]
        if entry.dst_port_op is not None:
            if entry.protocol not in ("tcp", "udp"):
                raise InvalidInputError(t("Zielports gibt es nur für TCP und UDP."))
            if entry.dst_port_op == "range":
                parts += ["range", str(int(entry.dst_port)), str(int(entry.dst_port_end))]
            else:
                parts += ["eq", str(int(entry.dst_port))]
        plan = _Builder()
        plan.line(f"ip access-list {acl['name']}")
        plan.line(" ".join(parts))
        plan.line("exit")
        return plan.plan()

    def plan_acl_entry_delete(self, session: transport.SshSession, name: str, seq: int) -> ChangePlan:
        acl = self._acl(session, name)
        if not any(entry["seq"] == seq for entry in acl["entries"]):
            raise InvalidInputError(t("Der Eintrag {seq} existiert nicht.", seq=seq))
        plan = _Builder()
        plan.line(f"ip access-list {acl['name']}")
        plan.line(f"no {int(seq)}")
        plan.line("exit")
        return plan.plan()

    def _acl_binding(self, session, name: str, interface: str, direction: str, remove: bool) -> ChangePlan:
        acl = self._acl(session, name)
        direction = validate_choice(direction, ("in", "out"), "ACL")
        vlan = _vlan_interface(interface)
        target = f"vlan {validate_vlan_id(vlan)}" if vlan is not None else self.validate_interface(interface)
        bound = any(normalize_interface(binding["interface"]) == normalize_interface(target)
                    and binding["direction"] == direction for binding in acl["bindings"])
        if remove and not bound:
            raise InvalidInputError(t("Die ACL {name} ist an {interface} nicht gebunden.", name=acl["name"],
                                      interface=target))
        if not remove and bound:
            raise _no_change()
        prefix = "no " if remove else ""
        plan = _Builder()
        if vlan is not None:
            plan.line(f"{prefix}ip access-group {acl['name']} vlan {vlan} {direction}")
        else:
            plan.line(f"interface {target}")
            plan.line(f"{prefix}ip access-group {acl['name']} {direction}")
            plan.line("exit")
        return plan.plan()

    def plan_acl_bind(self, session: transport.SshSession, name: str, interface: str, direction: str) -> ChangePlan:
        return self._acl_binding(session, name, interface, direction, remove=False)

    def plan_acl_unbind(self, session: transport.SshSession, name: str, interface: str, direction: str) -> ChangePlan:
        return self._acl_binding(session, name, interface, direction, remove=True)

    # --- QoS ---------------------------------------------------------------------------

    def plan_qos_port(self, session: transport.SshSession, interface: str, trust: str | None,
                      voice_preset: bool | None) -> ChangePlan:
        interface = self.validate_interface(interface)
        plan = _Builder()
        if trust is not None:
            plan.line(f"classofservice trust {TRUST_KEYWORDS[validate_choice(trust, tuple(TRUST_KEYWORDS), 'QoS')]}")
        if voice_preset is not None:
            plan.line("auto-voip protocol-based" if voice_preset else "no auto-voip protocol-based")
        if not plan:
            raise _no_change()
        plan.items.insert(0, ("line", (f"interface {interface}",), f"interface {interface}", ()))
        plan.line("exit")
        return plan.plan()

    # --- Firmware ------------------------------------------------------------------------

    def _bootvar(self, session: transport.SshSession) -> dict:
        if "netgear:bootvar" not in session.cache:
            session.cache["netgear:bootvar"] = parse_bootvar(self._show(session, "show bootvar"))
        return session.cache["netgear:bootvar"]

    def _inactive_slot(self, session: transport.SshSession) -> str:
        active = self._bootvar(session)["active"]
        if active not in SLOTS:
            raise InvalidInputError(t("Das aktive Image des Switches konnte nicht ermittelt werden."))
        return SLOTS[1 - SLOTS.index(active)]

    def read_firmware(self, session: transport.SshSession) -> dict:
        version = parse_key_values(self._show(session, "show version")).get("Software Version") or None
        boot = self._bootvar(session)
        return {
            "running_version": version,
            "boot_images": [f"{slot} ({boot['versions'][slot]})" if boot["versions"].get(slot) else slot
                            for slot in SLOTS if slot in boot["versions"]],
            "next_boot": boot["next"],
            "install_mode": None,
            "free_bytes": None,
            "files": [],
        }

    def plan_firmware_stage(
        self, session: transport.SshSession, image: FirmwareImage, transfer: TransferLocation, firmware: dict,
    ) -> ChangePlan:
        """``copy sftp://{user}@{host}/{file} image{n}`` into the non-active slot."""
        if transfer.method != "sftp" or transfer.port != 22:
            raise InvalidInputError(t(
                "Diese Plattform lädt per SFTP nur von Port 22. Bitte den SFTP-Port in Administration → Betrieb auf 22 "
                "setzen."
            ))
        if len(transfer.filename) > NETGEAR_MAX_FILENAME:
            raise InvalidInputError(t("Der Dateiname ist für diese Plattform zu lang (höchstens {limit} Zeichen).",
                                      limit=NETGEAR_MAX_FILENAME))
        slot = self._inactive_slot(session)
        prompts = ((YES_NO_LONG, "yes"), (PASSWORD_PROMPT, transfer.password), (YES_NO, "y"))
        step = CliCommand(f"copy {transfer.url} {slot}", prompts=prompts, timeout=FIRMWARE_TIMEOUT_SECONDS,
                          success=r"(?i)completed successfully")
        return ChangePlan(lines=(f"copy {transfer.display_url} {slot}",), steps=(step,),
                          secrets=_transfer_secrets(transfer), persistent=True)

    def plan_firmware_activate(
        self, session: transport.SshSession, image: FirmwareImage, firmware: dict, reload_now: bool,
    ) -> ChangePlan:
        """``boot system image{n}`` for the non-active slot (the staged image)."""
        slot = self._inactive_slot(session)
        step = CliCommand(f"boot system {slot}", prompts=((YES_NO, "y"),))
        plan = ChangePlan(lines=(step.command,), steps=(step,), persistent=True)
        return combine_plans(plan, self.plan_reload(session)) if reload_now else plan

    # --- Diagnostics ------------------------------------------------------------------------

    def read_counters(self, session: transport.SshSession, interface: str | None) -> list[dict]:
        if interface is not None:
            ports = [self.validate_interface(interface)]
        else:
            ports = [row["port"] for row in self.read_interfaces(session) if self.is_physical_interface(row["port"])]
            if len(ports) > MAX_COUNTER_PORTS:
                append_warning(session.warnings, t("Zähler wurden nur für {count} Ports gelesen.",
                                                   count=MAX_COUNTER_PORTS))
                ports = ports[:MAX_COUNTER_PORTS]
        rows = []
        for port in ports:
            output = self._optional_text(session, f"show interface ethernet {port}")
            if output is None:
                output = self._optional_text(session, f"show interface {port}")
            if output is not None:
                rows.append(parse_counters(output, port))
        return rows

    def plan_counters_clear(self, session: transport.SshSession, interface: str) -> ChangePlan:
        interface = self.validate_interface(interface)
        step = CliCommand(f"clear counters {interface}", prompts=((YES_NO, "y"),))
        return ChangePlan(lines=(step.command,), steps=(step,), persistent=True)

    def read_transceivers(self, session: transport.SshSession) -> list[dict]:
        return parse_transceivers(self._optional_text(session, "show fiber-ports optics all") or "")

    def read_log(self, session: transport.SshSession, lines: int = 500) -> list[str]:
        return parse_log(self._show(session, "show logging buffered"))[-int(lines):]

    def read_environment(self, session: transport.SshSession) -> dict:
        return parse_environment(self._show(session, "show environment"))

    def plan_cable_test(self, session: transport.SshSession, interface: str) -> ChangePlan:
        """``cablestatus {if}`` tests and prints the result at once; ``execute_plan`` keeps the result."""
        interface = self.validate_interface(interface)
        if not self.is_physical_interface(interface):
            raise InvalidInputError(t("Ungültiger Interface-Name: {interface}", interface=interface))
        step = CliCommand(f"cablestatus {interface}", prompts=((YES_NO, "y"),), timeout=60)
        return ChangePlan(lines=(step.command,), steps=(step,), persistent=True)

    def read_cable_test(self, session: transport.SshSession, interface: str) -> dict:
        """The last result of the ``cable-test`` operation (never runs the test: it interrupts the link)."""
        key = ((session.switch or {}).get("id"), normalize_interface(self.validate_interface(interface)))
        with _CABLE_LOCK:
            stored = _CABLE_RESULTS.get(key)
        if stored is None or time.monotonic() - stored[0] > CABLE_RESULT_SECONDS:
            raise InvalidInputError(t("Für diesen Port liegt kein Kabeltest-Ergebnis vor; bitte den Kabeltest "
                                      "starten."))
        return stored[1]

    # --- Execution hooks --------------------------------------------------------------------------

    def execute_plan(self, session: transport.SshSession, plan: ChangePlan):
        result = super().execute_plan(session, plan)
        tests = [step for step in plan.steps if isinstance(step, CliCommand) and step.command.startswith("cablestatus ")]
        if tests and result["ok"]:
            key = ((session.switch or {}).get("id"), normalize_interface(tests[-1].command.split(" ", 1)[1]))
            now = time.monotonic()
            with _CABLE_LOCK:
                for old in [old for old, (stamp, _value) in _CABLE_RESULTS.items()
                            if now - stamp > CABLE_RESULT_SECONDS]:
                    del _CABLE_RESULTS[old]
                _CABLE_RESULTS[key] = (now, parse_cable_status(result["raw"]))
        return result

    def _run_command(self, conn, step: CliCommand, outputs: list[str], secrets: tuple[str, ...] = ()) -> str | None:
        """``hostname`` changes the prompt ``(name) #``: expect the new one while the command runs."""
        match = re.fullmatch(r"hostname (\S+)", step.command)
        if match:
            conn.base_prompt = f"({match.group(1)})"
        return super()._run_command(conn, step, outputs, secrets)
