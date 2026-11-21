"""Aruba AOS-S device settings, firmware and diagnostics.

Mixed into ``ArubaAossDriver``; uses only ``self`` methods of the driver (``_show``, ``_brief``,
``validate_interface``, ``is_physical_interface``, ``plan_reload``) and shared helpers (no import
of ``aruba_aoss.py``). Plans read the running configuration first so that lists replace the
configured state and the preview shows only real changes. Secrets (SNMPv3 keys, RADIUS/TACACS
keys, local passwords, transfer credentials) only go into ``steps``/``secrets``; ``lines`` show
``REDACTED``. Interactive configuration commands (``snmpv3 enable``, ``no password manager``,
RBAC users) run as exec steps inside ``configure terminal`` … ``exit``.

AOS-S specifics: one syslog severity for all targets, login methods per access type with one
primary and one secondary method, one manager and one operator password (plus optional RBAC
``local-user`` accounts), two firmware slots (``primary``/``secondary``) without checksum
command (the staged image is checked by its version in ``show flash``).
"""

import ipaddress
import re
import secrets as secrets_module

from ...i18n import t
from .. import transport
from ..errors import InvalidInputError
from ..features import supported
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
    cli_plan,
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
    "firmware": supported(),
    "diag_counters": supported(),
    "diag_transceivers": supported(),
    "cable_test": supported(),
    "device_log": supported(),
    "environment": supported(),
}

FIRMWARE_TIMEOUT_SECONDS = 3600
SLOTS = ("primary", "secondary")
SNMP_KEY_MAX_LENGTH = 32
DNS_SERVER_SLOTS = 3
# AOS-S syslog severities; numbers 0-7 map onto them (one severity for all targets).
SEVERITY_BY_NUMBER = ("major", "major", "major", "error", "warning", "info", "info", "debug")
SEVERITY_NUMBER = {"major": 2, "error": 3, "warning": 4, "info": 6, "debug": 7}
# ``console inactivity-timer`` accepts only these minute values.
INACTIVITY_MINUTES = (1, 5, 10, 15, 20, 30, 60, 120)
LOGIN_ACCESS_TYPES = ("ssh", "telnet", "web")
SLOT_PRIVILEGE = {"manager": "admin", "operator": "read_only"}
RBAC_GROUPS = {"admin": "Level-15", "read_only": "Level-1"}
SNMP_GROUPS = {"managerpriv": "rw", "managerauth": "rw", "operatorauth": "ro", "operatornoauth": "ro"}
# Interactive y/n questions of AOS-S (``[y/n]``, ``[y/n/^C]``, ``(y/n)``).
YES_NO = r"\[y/n(/\^C)?\]\??|\(y/n\)\??"
PORT_NAMES = {"www": 80, "http": 80, "https": 443, "ssh": 22, "telnet": 23, "domain": 53, "dns": 53,
              "snmp": 161, "ftp": 21, "tftp": 69, "bootps": 67, "bootpc": 68, "ntp": 123, "syslog": 514,
              "smtp": 25}

ANY_ADDRESS = "0.0.0.0"  # noqa: S104 - ACL operand "any", not a bind address
_VLAN_IF_RE = re.compile(r"^vlan\s*(\d{1,4})$", re.IGNORECASE)
_IMAGE_VERSION_RE = re.compile(r"\b([A-Z]{1,3}\.\d{2}\.\d{2}\.\d{4})\b")
_IMAGE_FILE_RE = re.compile(r"^([A-Z]{1,3})_(\d{2})_(\d{2})_(\d{4})\.swi$", re.IGNORECASE)


def _no_change() -> InvalidInputError:
    return InvalidInputError(t("Keine Änderung nötig."))


def _invalid_value(label: str, value) -> InvalidInputError:
    return InvalidInputError(t("Ungültiger Wert für {label}: {value}", label=label, value=repr(value)))


def _transfer_secrets(transfer: TransferLocation) -> tuple[str, ...]:
    # Imported here: ``app.transfer`` imports ``drivers.plans`` (and with it this package).
    from ...transfer import location_secrets

    return location_secrets(transfer)


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value


def _int(text: str | None) -> int | None:
    value = (text or "").replace(",", "").strip()
    return int(value) if value.isdigit() else None


def _number(text: str | None) -> float | None:
    match = re.search(r"-?\d+(?:\.\d+)?", text or "")
    return float(match.group(0)) if match else None


def _prefix(address: str, mask_or_len: str | None) -> tuple[str, int] | None:
    """``10.0.0.0 255.0.0.0`` / ``10.0.0.0/8`` -> (address, length)."""
    if mask_or_len is None and "/" in address:
        address, mask_or_len = address.split("/", 1)
    try:
        interface = ipaddress.IPv4Interface(f"{address}/{mask_or_len}")
    except (ValueError, TypeError):
        return None
    return str(interface.ip), interface.network.prefixlen


# --- Running configuration -------------------------------------------------------------------


def config_blocks(text: str) -> tuple[list[str], list[tuple[str, list[str]]]]:
    """(top-level lines, [(block header, indented lines)]) of ``show running-config``."""
    top: list[str] = []
    blocks: list[tuple[str, list[str]]] = []
    current: list[str] | None = None
    for raw in (text or "").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith(";") or stripped == "Running configuration:":
            continue
        if raw[:1].isspace() and current is not None:
            if stripped == "exit":
                current = None
            else:
                current.append(stripped)
            continue
        if re.fullmatch(r"vlan \d+|interface \S+", stripped) or stripped.startswith("ip access-list "):
            current = []
            blocks.append((stripped, current))
        else:
            current = None
            top.append(stripped)
    return top, blocks


def _value(top: list[str], prefix: str) -> str | None:
    for line in top:
        if line.startswith(prefix + " "):
            return _unquote(line[len(prefix) + 1:]) or None
    return None


def parse_identity(top: list[str]) -> dict:
    banner = None
    for line in top:
        match = re.match(r'^banner motd "(.*)"$', line)
        if match:
            banner = match.group(1).replace("\\n", "\n")
    return {
        "hostname": _value(top, "hostname"),
        "banner": banner,
        "snmp_location": _value(top, "snmp-server location"),
        "snmp_contact": _value(top, "snmp-server contact"),
    }


def parse_services(top: list[str]) -> dict:
    ntp = [match.group(1) for line in top if (match := re.match(r"^ntp server (\S+)", line))]
    sntp = {int(match.group(1)): match.group(2) for line in top
            if (match := re.match(r"^sntp server priority (\d) (\S+)", line))}
    dns = {int(match.group(1)): match.group(2) for line in top
           if (match := re.match(r"^ip dns server-address priority (\d) (\S+)", line))}
    offset = next((int(match.group(1)) for line in top if (match := re.match(r"^time timezone (-?\d+)$", line))), 0)
    severity = next((match.group(1).lower() for line in top
                     if (match := re.match(r"^logging severity (\S+)$", line))), None)
    hosts = [match.group(1) for line in top if (match := re.match(r"^logging (\d{1,3}(?:\.\d{1,3}){3})\b", line))]
    timesync = next((line.split()[1] for line in top if line.startswith("timesync ")), None)
    return {
        "ntp_servers": ntp or [sntp[key] for key in sorted(sntp)],
        "timezone": {"name": None, "offset_minutes": offset},
        "dns_servers": [dns[key] for key in sorted(dns)],
        "domain_name": _value(top, "ip dns domain-name"),
        "syslog": [{"host": host, "severity": SEVERITY_NUMBER.get(severity or "")} for host in hosts],
        "_ntp": ntp,
        "_sntp": sntp,
        "_dns": dns,
        "_severity": severity,
        "_timesync": timesync,
        "_ntp_enabled": "ntp enable" in top,
    }


def parse_aaa(top: list[str], radius_output: str) -> dict:
    radius = []
    seen = set()
    for line in (radius_output or "").splitlines():
        match = re.match(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\d+)\b.*?\|\s*(\S*)\s*$", line)
        if match and match.group(1) not in seen:
            seen.add(match.group(1))
            radius.append({"host": match.group(1), "auth_port": int(match.group(2)), "acct_port": int(match.group(3)),
                           "key_configured": bool(match.group(4))})
    for line in top:
        match = re.match(r"^radius-server host (\S+)(.*)$", line)
        if match and match.group(1) not in seen:
            rest = match.group(2)
            auth = re.search(r"auth-port (\d+)", rest)
            acct = re.search(r"acct-port (\d+)", rest)
            seen.add(match.group(1))
            radius.append({"host": match.group(1), "auth_port": int(auth.group(1)) if auth else 1812,
                           "acct_port": int(acct.group(1)) if acct else 1813,
                           "key_configured": bool(re.search(r"\b(encrypted-)?key\b", rest))})
    global_tacacs_key = any(re.match(r"^tacacs-server (encrypted-)?key\b", line) for line in top)
    tacacs = [
        {"host": match.group(1), "port": 49,
         "key_configured": global_tacacs_key or bool(re.search(r"\b(encrypted-)?key\b", match.group(2)))}
        for line in top if (match := re.match(r"^tacacs-server host (\S+)(.*)$", line))
    ]
    methods = {}
    for line in top:
        match = re.match(r"^aaa authentication (ssh|telnet|web|console) login (\S+)(?: (\S+))?", line)
        if match:
            methods[match.group(1)] = [m for m in (match.group(2), match.group(3)) if m and m != "none"]
    order = methods.get("ssh") or ["local"]
    return {"radius": radius, "tacacs": tacacs, "login_order": order, "_methods": methods}


def parse_users(top: list[str]) -> list[dict]:
    """Manager/operator password slots (name None when the configuration omits it) and RBAC users."""
    users = []
    for line in top:
        if match := re.match(r'^password (manager|operator)(?: user-name ("[^"]*"|\S+))?', line):
            users.append({"name": _unquote(match.group(2)) if match.group(2) else None,
                          "privilege": SLOT_PRIVILEGE[match.group(1)], "_slot": match.group(1)})
        elif match := re.match(r'^aaa authentication local-user ("[^"]*"|\S+) group ("[^"]*"|\S+)', line):
            group = _unquote(match.group(2))
            users.append({"name": _unquote(match.group(1)),
                          "privilege": "admin" if group.lower() in ("level-15", "manager") else "read_only",
                          "_slot": None})
    return users


def parse_ssh(top: list[str]) -> dict:
    minutes = next((int(match.group(1)) for line in top
                    if (match := re.match(r"^console inactivity-timer (\d+)$", line))), 0)
    web_off = "no web-management" in top or (
        "no web-management plaintext" in top and not any(line.startswith("web-management ssl") for line in top)
    )
    return {
        "version": "2",
        "timeout_seconds": minutes * 60 or None,
        "telnet_enabled": "no telnet-server" not in top,
        "web_enabled": not web_off,
    }


def parse_l3(top: list[str], blocks) -> dict:
    svis = []
    for header, lines in blocks:
        match = re.fullmatch(r"vlan (\d+)", header)
        if not match:
            continue
        addresses = []
        dhcp = False
        for line in lines:
            if line.startswith("ip address dhcp"):
                dhcp = True
            elif address := re.match(r"^ip address (\S+)(?: (\d{1,3}(?:\.\d{1,3}){3}))?$", line):
                parsed = _prefix(address.group(1), address.group(2))
                if parsed:
                    addresses.append(parsed)
        relay = [m.group(1) for line in lines if (m := re.match(r"^ip helper-address (\S+)", line))]
        vlan = int(match.group(1))
        if dhcp:
            svis.append({"vlan": vlan, "address": None, "prefix_length": None, "dhcp_relay": relay, "enabled": True})
        for address, length in addresses:
            svis.append({"vlan": vlan, "address": address, "prefix_length": length, "dhcp_relay": relay,
                         "enabled": True})
    routes = []
    for line in top:
        match = re.match(r"^ip route (\S+)(?: (\d{1,3}(?:\.\d{1,3}){3}))? (\d{1,3}(?:\.\d{1,3}){3})(.*)$", line)
        if not match:
            continue
        parsed = _prefix(match.group(1), match.group(2))
        if parsed is None:
            continue
        distance = re.search(r"distance (\d+)", match.group(4))
        routes.append({"prefix": parsed[0], "prefix_length": parsed[1], "next_hop": match.group(3),
                       "distance": int(distance.group(1)) if distance else None})
    routing = "ip routing" in top
    default_routes = [route["next_hop"] for route in routes if route["prefix_length"] == 0]
    gateway = default_routes[0] if routing and default_routes else _value(top, "ip default-gateway")
    return {"svis": svis, "default_gateway": gateway, "routes": routes, "routing_enabled": routing,
            "_ip_default_gateway": _value(top, "ip default-gateway")}


def _acl_address(tokens: list[str], index: int) -> tuple[str, int, int]:
    """(address, prefix length, next index) of ``any`` / ``host X`` / ``X WILDCARD`` / ``X/len``."""
    word = tokens[index]
    if word == "any":
        return ANY_ADDRESS, 0, index + 1
    if word == "host":
        return tokens[index + 1], 32, index + 2
    if "/" in word:
        parsed = _prefix(word, None)
        return (parsed[0], parsed[1], index + 1) if parsed else (word, 32, index + 1)
    wildcard = tokens[index + 1] if index + 1 < len(tokens) else ANY_ADDRESS
    try:
        length = 32 - bin(int(ipaddress.IPv4Address(wildcard))).count("1")
    except ValueError:
        return word, 32, index + 1
    if wildcard == "255.255.255.255":
        return ANY_ADDRESS, 0, index + 2
    return word, length, index + 2


def _port_number(text: str) -> int | None:
    return int(text) if text.isdigit() else PORT_NAMES.get(text.lower())


def parse_acl_entry(line: str, acl_type: str) -> dict | None:
    tokens = line.split()
    if len(tokens) < 3 or not tokens[0].isdigit() or tokens[1] not in ("permit", "deny"):
        return None
    entry = {"seq": int(tokens[0]), "action": tokens[1], "protocol": "ip", "src": None, "src_len": None,
             "dst": None, "dst_len": None, "dst_port_op": None, "dst_port": None, "dst_port_end": None}
    try:
        if acl_type == "standard":
            entry["src"], entry["src_len"], _ = _acl_address(tokens, 2)
            return entry
        entry["protocol"] = tokens[2]
        entry["src"], entry["src_len"], index = _acl_address(tokens, 3)
        entry["dst"], entry["dst_len"], index = _acl_address(tokens, index)
        if index < len(tokens) and tokens[index] == "eq":
            entry["dst_port_op"], entry["dst_port"] = "eq", _port_number(tokens[index + 1])
        elif index < len(tokens) and tokens[index] == "range":
            entry["dst_port_op"] = "range"
            entry["dst_port"], entry["dst_port_end"] = _port_number(tokens[index + 1]), _port_number(tokens[index + 2])
    except IndexError:
        return None
    return entry


def parse_acls(blocks) -> list[dict]:
    acls = {}
    for header, lines in blocks:
        match = re.fullmatch(r'ip access-list (standard|extended) ("[^"]*"|\S+)', header)
        if match:
            name = _unquote(match.group(2))
            entries = [entry for line in lines if (entry := parse_acl_entry(line, match.group(1)))]
            acls[name] = {"name": name, "type": match.group(1), "entries": entries, "bindings": []}
    for header, lines in blocks:
        vlan = re.fullmatch(r"vlan (\d+)", header)
        port = re.fullmatch(r"interface (\S+)", header)
        if not (vlan or port):
            continue
        for line in lines:
            bound = re.match(r'^ip access-group ("[^"]*"|\S+) (in|out|vlan)$', line)
            if not bound or _unquote(bound.group(1)) not in acls:
                continue
            word = bound.group(2)
            acls[_unquote(bound.group(1))]["bindings"].append({
                "interface": f"vlan{vlan.group(1)}" if vlan else port.group(1),
                "direction": "in" if word == "vlan" else word,
                "_form": word,
            })
    return list(acls.values())


def _public(value):
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items() if not key.startswith("_")}
    if isinstance(value, list):
        return [_public(item) for item in value]
    return value


# --- SNMPv3 and diagnostics show outputs ---------------------------------------------------------


def parse_snmp_users(users_output: str, groups_output: str) -> list[dict]:
    """``show snmpv3 user`` (name, auth, privacy) + ``show snmpv3 group`` (access by group name)."""
    groups: dict[str, list[str]] = {}
    for line in (groups_output or "").splitlines():
        match = re.match(r'^\s*("[^"]*"|\S+)\s+ver3\s+(\S+)\s*$', line, re.IGNORECASE)
        if match:
            groups.setdefault(_unquote(match.group(1)), []).append(match.group(2))
    users = []
    for line in (users_output or "").splitlines():
        match = re.match(r"^\s*(\S+)\s+(MD5|SHA\S*)\s*(.*?)\s*$", line, re.IGNORECASE)
        if not match:
            continue
        auth = match.group(2).upper()
        privacy = match.group(3).upper()
        names = groups.get(match.group(1), [])
        access = next((SNMP_GROUPS[group] for group in names if group in SNMP_GROUPS), None)
        users.append({
            "name": match.group(1),
            "auth": "sha" if auth == "SHA" else None,
            "priv": "aes128" if "AES" in privacy else None,
            "access": access,
            "_groups": names,
        })
    return users


def parse_flash(output: str) -> dict:
    slots = {}
    for line in (output or "").splitlines():
        match = re.match(r"^\s*(Primary|Secondary) Image\s*:\s*([\d,]+)?\s*(\S+)?\s*(\S+)?", line)
        if match:
            slots[match.group(1).lower()] = {"size": _int(match.group(2)), "version": match.group(4)}
    default = re.search(r"Default Boot Image\s*:\s*(\S+)", output or "")
    return {"slots": slots, "default": default.group(1).lower() if default else None}


def parse_version(output: str) -> dict:
    version = None
    for line in (output or "").splitlines():
        if "boot rom" in line.lower():
            continue
        match = _IMAGE_VERSION_RE.search(line)
        if match:
            version = match.group(1)
            break
    boot = re.search(r"Boot Image:\s*(\S+)", output or "")
    return {"version": version, "active": boot.group(1).lower() if boot else None}


_COUNTER_FIELDS = {
    "bytes rx": "in_octets", "bytes tx": "out_octets", "total rx errors": "in_errors",
    "total tx errors": "out_errors", "fcs rx": "crc", "drops rx": "drops_in", "drops tx": "drops_out",
    "collisions tx": "collisions",
}


def parse_counters(output: str) -> list[dict]:
    """``show interfaces <ports>``: one ``Port Counters for port X`` block per port."""
    rows = []
    row = None
    for line in (output or "").splitlines():
        header = re.search(r"Port Counters for port (\S+)", line)
        if header:
            row = {"interface": header.group(1), **{key: None for key in _COUNTER_FIELDS.values()}}
            rows.append(row)
            continue
        if row is None:
            continue
        for label, value in re.findall(r"([A-Za-z/ ]+?)\s*:\s*([\d,]+)", line):
            key = _COUNTER_FIELDS.get(label.strip().lower())
            if key:
                row[key] = _int(value)
    return rows


def _dbm(text: str | None) -> float | None:
    match = re.search(r"(-?\d+(?:\.\d+)?)\s*dBm", text or "", re.IGNORECASE)
    return float(match.group(1)) if match else None


def parse_transceivers(output: str) -> list[dict]:
    rows = []
    row = None
    for line in (output or "").splitlines():
        header = re.match(r"^\s*Transceiver in (\S+)", line)
        if header:
            row = {"interface": header.group(1), "type": None, "temperature_c": None, "voltage_v": None,
                   "tx_power_dbm": None, "rx_power_dbm": None, "alarm": None}
            rows.append(row)
            continue
        match = re.match(r"^\s*([A-Za-z ]+?)\s*:\s*(.*?)\s*$", line)
        if row is None or not match:
            continue
        label, value = match.group(1).lower(), match.group(2)
        if label == "type":
            row["type"] = value or None
        elif label == "temperature":
            row["temperature_c"] = _number(value)
        elif label == "voltage":
            row["voltage_v"] = _number(value)
        elif label == "tx power":
            row["tx_power_dbm"] = _dbm(value)
        elif label == "rx power":
            row["rx_power_dbm"] = _dbm(value)
        elif "alarm" in label:
            row["alarm"] = value or None
    return rows


def parse_log(output: str) -> list[str]:
    """Event lines ``I 01/09/13 16:17:07 00150 update: …`` (headers and legends dropped)."""
    return [line.rstrip() for line in (output or "").splitlines()
            if re.match(r"^[IWEMD-] \d{2}/\d{2}/\d{2} ", line)]


def parse_environment(temperature: str, fans: str, power: str) -> dict:
    temperatures = []
    for line in (temperature or "").splitlines():
        match = re.match(r"^\s*([^|\s][^|]*?)\s*\|\s*(-?\d+(?:\.\d+)?)C\b(.*)$", line)
        if match:
            over = re.search(r"\b(YES|NO)\s*$", match.group(3), re.IGNORECASE)
            status = None if not over else ("overtemp" if over.group(1).upper() == "YES" else "ok")
            temperatures.append({"sensor": match.group(1), "celsius": float(match.group(2)), "status": status})
    fan_rows = [{"name": match.group(1), "status": match.group(2)}
                for line in (fans or "").splitlines()
                if (match := re.match(r"^\s*(\S+)\s*\|\s*(.*?)\s*\|\s*\d+\s*$", line))]
    supplies = []
    for line in (power or "").splitlines():
        match = re.match(r"^\s*(\d+)\s+\S+\s+\S+\s+(Powered|Not Powered|Not Present|Failed|Fault|Aux Not Powered)"
                         r"\b(.*)$", line, re.IGNORECASE)
        if match:
            watts = re.findall(r"\b(\d+)\b", match.group(3))
            supplies.append({"name": f"PS {match.group(1)}", "status": match.group(2),
                             "watts": float(watts[-2]) if len(watts) >= 2 else None})
    return {"temperatures": temperatures, "fans": fan_rows, "power_supplies": supplies}


def parse_cable_test(output: str, interface: str) -> dict:
    pairs = []
    port = None
    for line in (output or "").splitlines():
        match = re.match(r"^\s*(?:(\S+)\s+)?(\d-\d)\s+(OK|Open|Short|Impedance mismatch|Crosstalk)\s+(\d+)\s*m\b",
                         line, re.IGNORECASE)
        if not match:
            continue
        if match.group(1):
            port = match.group(1)
        if port is not None and port.upper() == interface.upper():
            pairs.append({"pair": match.group(2), "status": match.group(3), "length_m": int(match.group(4))})
    return {"status": "done" if pairs else "running", "pairs": pairs}


# --- Plans -----------------------------------------------------------------------------------


class _Lines:
    """Displayed and sent lines in parallel; ``secret`` values only reach the sent line."""

    def __init__(self):
        self.shown: list[str] = []
        self.sent: list[str] = []
        self.secrets: list[str] = []

    def add(self, line: str, secret_line: str | None = None, *secrets: str) -> None:
        self.shown.append(line)
        self.sent.append(secret_line if secret_line is not None else line)
        self.secrets.extend(secret for secret in secrets if secret)

    def plan(self, **kwargs) -> ChangePlan:
        if not self.sent:
            raise _no_change()
        return ChangePlan(
            lines=tuple(self.shown), steps=(CliLines(tuple(self.sent)),), secrets=tuple(self.secrets), **kwargs,
        )


def _interactive(commands, after: _Lines | None = None, warnings: tuple[str, ...] = ()) -> ChangePlan:
    """Interactive configuration commands: ``configure terminal``, the prompted commands, then
    either the remaining configuration lines (leaving configuration mode) or ``exit``.

    ``commands``: (shown, sent, prompts, secrets) tuples.
    """
    steps: list = [CliCommand("configure terminal")]
    shown = ["configure terminal"]
    secrets: list[str] = []
    for shown_command, sent_command, prompts, command_secrets in commands:
        steps.append(CliCommand(sent_command, prompts=prompts))
        shown.append(shown_command)
        secrets.extend(command_secrets)
    if after is not None and after.sent:
        steps.append(CliLines(tuple(after.sent), enter=False))
        shown.extend(after.shown)
        secrets.extend(after.secrets)
    else:
        steps.append(CliCommand("exit"))
        shown.append("exit")
    return ChangePlan(lines=tuple(shown), steps=tuple(steps), secrets=tuple(dict.fromkeys(secrets)),
                      warnings=warnings)


def _acl_operand(address: str | None, prefix_length: int | None) -> str:
    if address is None or not prefix_length:
        return "any"
    network = validate_ipv4_prefix(address, prefix_length)
    return f"host {network.network_address}" if network.prefixlen == 32 else str(network)


class AossDeviceMixin:
    """Device settings, firmware and diagnostics reads and plans of the AOS-S driver."""

    transfer_method = "sftp"
    # AOS-S downloads per SFTP only from port 22.
    sftp_port_22_only = True

    # --- Shared reads ---------------------------------------------------------------------------

    def _device_running_text(self, session: transport.SshSession) -> str:
        """Full running configuration; a failed read raises (plans must not work on a guessed state)."""
        cached = session.cache.get("aoss:running-text")
        if cached is not None:
            return cached
        conn = session.conn
        previous = getattr(conn, "read_timeout_override", None)
        conn.read_timeout_override = max(previous or 0, transport.SAVE_CONFIG_MIN_TIMEOUT_SECONDS)
        try:
            output = self._show(session, "show running-config")
        finally:
            conn.read_timeout_override = previous
        session.cache["aoss:running-text"] = output
        return output

    def _device_blocks(self, session: transport.SshSession):
        return config_blocks(self._device_running_text(session))

    def _snmp_users(self, session: transport.SshSession) -> list[dict]:
        return parse_snmp_users(
            self._show(session, "show snmpv3 user", allow_empty=True),
            self._show(session, "show snmpv3 group", allow_empty=True),
        )

    def _aaa(self, session: transport.SshSession) -> dict:
        top, _blocks = self._device_blocks(session)
        return parse_aaa(top, self._show(session, "show radius", allow_empty=True))

    # --- Device settings read -----------------------------------------------------------------------------

    def read_device_config(self, session: transport.SshSession) -> dict:
        top, blocks = self._device_blocks(session)
        snmp_users, _status = self._optional(session, "show snmpv3 user")
        snmp_groups, _status = self._optional(session, "show snmpv3 group") if snmp_users is not None else (None, "")
        radius, _status = self._optional(session, "show radius")
        snmp = None if snmp_users is None else {"users": _public(parse_snmp_users(snmp_users, snmp_groups or ""))}
        aaa = parse_aaa(top, radius or "")
        return {
            "identity": parse_identity(top),
            "services": _public(parse_services(top)),
            "snmp": snmp,
            "aaa": _public(aaa),
            "users": _public(parse_users(top)),
            "ssh": parse_ssh(top),
            "l3": _public(parse_l3(top, blocks)),
            "acls": _public(parse_acls(blocks)),
            "qos": None,
        }

    # --- Identity and services ----------------------------------------------------------

    def plan_device_identity(self, session: transport.SshSession, change: IdentityChange) -> ChangePlan:
        top, _blocks = self._device_blocks(session)
        current = parse_identity(top)
        lines = _Lines()
        if change.banner is not None:
            if change.banner == "":
                if current["banner"] is not None:
                    lines.add("no banner motd")
            else:
                body = validate_banner(change.banner).rstrip("\n").split("\n")
                if body != (current["banner"] or "").rstrip("\n").split("\n"):
                    # "^" never occurs in a validated banner.
                    for line in ("banner motd ^", *body, "^"):
                        lines.add(line)
        for field, keyword in (("snmp_location", "location"), ("snmp_contact", "contact")):
            value = getattr(change, field)
            if value is None:
                continue
            if value == "":
                if current[field] is not None:
                    lines.add(f"no snmp-server {keyword}")
            elif (text := validate_snmp_text(value)) != current[field]:
                lines.add(f'snmp-server {keyword} "{text}"')
        if change.hostname is not None and validate_hostname(change.hostname) != current["hostname"]:
            # Last: the prompt changes with the hostname.
            lines.add(f'hostname "{change.hostname}"')
        return lines.plan()

    def plan_device_services(self, session: transport.SshSession, change: ServicesChange) -> ChangePlan:
        top, _blocks = self._device_blocks(session)
        current = parse_services(top)
        lines = _Lines()
        if change.ntp_servers is not None:
            self._plan_ntp(lines, current, list(dict.fromkeys(validate_host(server) for server in change.ntp_servers)))
        if change.timezone_offset_minutes is not None:
            offset = int(change.timezone_offset_minutes)
            if not -720 <= offset <= 840:
                raise _invalid_value("Zeitzone", offset)
            if offset != current["timezone"]["offset_minutes"]:
                lines.add(f"time timezone {offset}")
        if change.dns_servers is not None:
            wanted = list(dict.fromkeys(validate_ipv4(server) for server in change.dns_servers))
            if len(wanted) > DNS_SERVER_SLOTS:
                raise _invalid_value("DNS", ", ".join(wanted))
            for priority in range(1, DNS_SERVER_SLOTS + 1):
                old = current["_dns"].get(priority)
                new = wanted[priority - 1] if priority <= len(wanted) else None
                if old == new:
                    continue
                if old is not None:
                    lines.add(f"no ip dns server-address priority {priority} {old}")
                if new is not None:
                    lines.add(f"ip dns server-address priority {priority} {new}")
        if change.domain_name is not None:
            if change.domain_name == "":
                if current["domain_name"] is not None:
                    lines.add(f"no ip dns domain-name {current['domain_name']}")
            elif (domain := validate_host(change.domain_name)) != current["domain_name"]:
                lines.add(f"ip dns domain-name {domain}")
        if change.syslog is not None:
            self._plan_syslog(lines, current, change.syslog)
        return lines.plan()

    def _plan_ntp(self, lines: _Lines, current: dict, wanted: list[str]) -> None:
        if current["_sntp"]:
            # Only one time protocol is active: drop SNTP before switching to NTP.
            for priority, server in sorted(current["_sntp"].items()):
                lines.add(f"no sntp server priority {priority} {server}")
        for server in current["_ntp"]:
            if server not in wanted:
                lines.add(f"no ntp server {server}")
        added = [server for server in wanted if server not in current["_ntp"]]
        if not wanted:
            return
        if current["_timesync"] != "ntp":
            lines.add("timesync ntp")
            lines.add("ntp unicast")
        for server in added:
            lines.add(f"ntp server {server} iburst")
        if not current["_ntp_enabled"]:
            lines.add("ntp enable")

    def _plan_syslog(self, lines: _Lines, current: dict, targets) -> None:
        wanted: dict[str, int] = {}
        for target in targets:
            severity = int(target.severity)
            if not 0 <= severity <= 7:
                raise _invalid_value("Schweregrad", severity)
            wanted[validate_ipv4(target.host)] = severity
        keywords = {SEVERITY_BY_NUMBER[severity] for severity in wanted.values()}
        if len(keywords) > 1:
            raise InvalidInputError(t("Diese Plattform erlaubt nur einen gemeinsamen Syslog-Schweregrad für alle Ziele."))
        hosts = [entry["host"] for entry in current["syslog"]]
        for host in hosts:
            if host not in wanted:
                lines.add(f"no logging {host}")
        for host in wanted:
            if host not in hosts:
                lines.add(f"logging {host}")
        if keywords and (keyword := keywords.pop()) != current["_severity"]:
            lines.add(f"logging severity {keyword}")

    # --- Access: SNMPv3, AAA, users, SSH -----------------------------------------------------

    def plan_snmp_user_set(self, session: transport.SshSession, user: SnmpUserChange) -> ChangePlan:
        name = validate_username(user.name)
        if user.auth != "sha":
            raise InvalidInputError(t("Diese Plattform unterstützt für SNMPv3 nur SHA."))
        keys = [validate_secret(user.auth_key)]
        if user.priv is not None:
            if not user.priv_key:
                raise InvalidInputError(t("Für die Verschlüsselung ist ein Schlüssel erforderlich."))
            keys.append(validate_secret(user.priv_key))
        elif user.priv_key:
            raise InvalidInputError(t("Ein Verschlüsselungsschlüssel braucht ein Verschlüsselungsverfahren."))
        if any(len(key) > SNMP_KEY_MAX_LENGTH for key in keys):
            raise InvalidInputError(t("SNMPv3-Schlüssel dürfen auf dieser Plattform höchstens {limit} Zeichen lang sein.",
                                      limit=SNMP_KEY_MAX_LENGTH))
        access = validate_choice(user.access, ("ro", "rw"), "Zugriff")
        group = "operatorauth" if access == "ro" else ("managerpriv" if len(keys) > 1 else "managerauth")
        existing = next((item for item in self._snmp_users(session) if item["name"] == name), None)
        lines = _Lines()
        for old in (existing or {}).get("_groups", []):
            if old != group:
                lines.add(f'no snmpv3 group {old} user "{name}" sec-model ver3')
        shown = f'snmpv3 user "{name}" auth sha "{REDACTED}"'
        sent = f'snmpv3 user "{name}" auth sha "{keys[0]}"'
        if len(keys) > 1:
            shown += f' priv aes "{REDACTED}"'
            sent += f' priv aes "{keys[1]}"'
        lines.add(shown, sent, *keys)
        if group not in (existing or {}).get("_groups", []):
            lines.add(f'snmpv3 group {group} user "{name}" sec-model ver3')
        top, _blocks = self._device_blocks(session)
        if "snmpv3 enable" in top:
            return lines.plan()
        # ``snmpv3 enable`` creates the user "initial" interactively; it gets a throw-away password
        # and is removed again.
        initial = secrets_module.token_hex(8)
        lines.add('no snmpv3 user "initial"')
        prompts = ((r"(?i)password", initial), (YES_NO, "n"))
        return _interactive([("snmpv3 enable", "snmpv3 enable", prompts, (initial,))], lines)

    def plan_snmp_user_delete(self, session: transport.SshSession, name: str) -> ChangePlan:
        name = validate_username(name)
        existing = next((item for item in self._snmp_users(session) if item["name"] == name), None)
        if existing is None:
            raise InvalidInputError(t("SNMP-Benutzer {name} existiert auf dem Switch nicht.", name=name))
        lines = [f'no snmpv3 group {group} user "{name}" sec-model ver3' for group in existing["_groups"]]
        return cli_plan([*lines, f'no snmpv3 user "{name}"'])

    def plan_device_aaa(self, session: transport.SshSession, change: AaaChange) -> ChangePlan:
        current = self._aaa(session)
        lines = _Lines()
        hosts = {kind: [server["host"] for server in current[kind]] for kind in ("radius", "tacacs")}
        for kind in ("radius", "tacacs"):
            wanted = getattr(change, kind)
            if wanted is not None:
                hosts[kind] = self._replace_servers(lines, kind, current[kind], wanted)
        if change.login_order is not None:
            order = list(dict.fromkeys(change.login_order))
            if "local" not in order:
                raise InvalidInputError(t("Die lokale Anmeldung muss als Rückfallebene erhalten bleiben."))
            if len(order) > 2 or order[-1] != "local":
                raise InvalidInputError(t(
                    "AOS-S erlaubt eine Anmeldemethode vor der lokalen Anmeldung; die lokale Anmeldung muss die letzte sein."
                ))
            for method, label in (("radius", "RADIUS"), ("tacacs", "TACACS+")):
                if method in order and not hosts[method]:
                    raise InvalidInputError(t("Für die Anmeldung über {method} ist kein Server konfiguriert.",
                                              method=label))
            methods = "local none" if order == ["local"] else f"{order[0]} local"
            for access in LOGIN_ACCESS_TYPES:
                configured = current["_methods"].get(access)
                if order == ["local"] and configured in (None, ["local"]):
                    continue
                if configured != order:
                    lines.add(f"aaa authentication {access} login {methods}")
        return lines.plan()

    def _replace_servers(self, lines: _Lines, kind: str, configured: list[dict], wanted) -> list[str]:
        desired = {}
        for server in wanted:
            host = validate_ipv4(server.host)
            if host in desired:
                raise InvalidInputError(t("Jeder Server darf nur einmal angegeben werden."))
            if kind == "tacacs" and int(server.port) != 49:
                raise InvalidInputError(t("Der Wert {value} wird von diesem Gerät nicht unterstützt.",
                                          value=f"port {server.port}"))
            desired[host] = server
        current = {server["host"]: server for server in configured}
        command = f"{kind}-server host"
        for host in current:
            if host not in desired:
                lines.add(f"no {command} {host}")
        for host, server in desired.items():
            existing = current.get(host)
            key = validate_secret(server.key) if server.key is not None else None
            if existing is None and key is None:
                raise InvalidInputError(t("Für den neuen Server {host} ist ein Schlüssel erforderlich.", host=host))
            if key is not None:
                lines.add(f'{command} {host} key "{REDACTED}"', f'{command} {host} key "{key}"', key)
            if kind == "radius":
                ports = (int(server.auth_port), int(server.acct_port))
                if existing is None and ports != (1812, 1813) or existing is not None and ports != (
                        existing["auth_port"], existing["acct_port"]):
                    lines.add(f"{command} {host} auth-port {ports[0]} acct-port {ports[1]}")
        return list(desired)

    def _check_own_account(self, session: transport.SshSession, name: str | None) -> None:
        if name is not None and name == (session.credentials or {}).get("username"):
            raise InvalidInputError(t("Das Konto, mit dem SwitchSteward sich anmeldet, kann hier nicht geändert werden."))

    def plan_device_user_set(
        self, session: transport.SshSession, name: str, password: str | None, privilege: str,
    ) -> ChangePlan:
        """Manager/operator password slots; existing RBAC ``local-user`` accounts keep their form."""
        name = validate_username(name)
        self._check_own_account(session, name)
        privilege = validate_choice(privilege, ("admin", "read_only"), "Privileg")
        top, _blocks = self._device_blocks(session)
        users = parse_users(top)
        existing = next((user for user in users if user["name"] == name), None)
        if password is None:
            if existing is None:
                raise InvalidInputError(t("Für einen neuen Benutzer ist ein Passwort erforderlich."))
            if existing["privilege"] == privilege:
                raise _no_change()
            raise InvalidInputError(t("AOS-S ändert die Berechtigung eines Benutzers nur zusammen mit dem Passwort."))
        password = validate_secret(password)
        if existing is not None and existing["_slot"] is None:
            group = RBAC_GROUPS[privilege]
            command = f'aaa authentication local-user "{name}" group "{group}" password plaintext'
            return _interactive([(command, command, ((r"(?i)password", password),), (password,))])
        slot = "manager" if privilege == "admin" else "operator"
        warnings = []
        holder = next((user for user in users if user["_slot"] == slot), None)
        if holder is not None and holder["name"] != name:
            self._check_own_account(session, holder["name"])
            warnings.append(t("AOS-S kennt nur einen Benutzer pro Stufe; der bisherige {slot}-Zugang wird ersetzt.",
                              slot=slot))
        lines = _Lines()
        prefix = f'password {slot} user-name "{name}" plaintext '
        lines.add(f'{prefix}"{REDACTED}"', f'{prefix}"{password}"', password)
        if existing is not None and existing["_slot"] not in (None, slot):
            # The user moves to the other level: its old password slot is removed (asks y/n).
            command = f"no password {existing['_slot']}"
            return _interactive([(command, command, ((YES_NO, "y"),), ())], lines, tuple(warnings))
        return lines.plan(warnings=tuple(warnings))

    def plan_device_user_delete(self, session: transport.SshSession, name: str) -> ChangePlan:
        """``no password manager`` asks ``… continue [y/n]?``: exec steps inside configuration mode."""
        name = validate_username(name)
        self._check_own_account(session, name)
        top, _blocks = self._device_blocks(session)
        existing = next((user for user in parse_users(top) if user["name"] == name), None)
        if existing is None:
            raise InvalidInputError(t("Benutzer {name} existiert auf dem Switch nicht.", name=name))
        command = (f"no password {existing['_slot']}" if existing["_slot"]
                   else f'no aaa authentication local-user "{name}"')
        return _interactive([(command, command, ((YES_NO, "y"),), ())])

    def plan_device_ssh(
        self, session: transport.SshSession, timeout_seconds: int | None, telnet_enabled: bool | None,
        web_enabled: bool | None,
    ) -> ChangePlan:
        top, _blocks = self._device_blocks(session)
        current = parse_ssh(top)
        lines = _Lines()
        if timeout_seconds is not None:
            seconds = int(timeout_seconds)
            if seconds % 60 or seconds // 60 not in INACTIVITY_MINUTES:
                raise InvalidInputError(t("Der Timeout muss auf dieser Plattform einer dieser Minutenwerte sein: {values}.",
                                          values=", ".join(str(value) for value in INACTIVITY_MINUTES)))
            if current["timeout_seconds"] != seconds:
                lines.add(f"console inactivity-timer {seconds // 60}")
        if telnet_enabled is not None and telnet_enabled != current["telnet_enabled"]:
            lines.add("telnet-server" if telnet_enabled else "no telnet-server")
        if web_enabled is not None and web_enabled != current["web_enabled"]:
            lines.add("web-management" if web_enabled else "no web-management")
        return lines.plan()

    # --- Layer 3 -----------------------------------------------------------------------------

    def _vlan_exists(self, blocks, vlan: int) -> None:
        if not any(header == f"vlan {vlan}" for header, _lines in blocks):
            raise InvalidInputError(t("VLAN {vlan} existiert auf dem Switch nicht.", vlan=vlan))

    def plan_svi_set(
        self, session: transport.SshSession, vlan: int, address: str, prefix_length: int, dhcp_relay: tuple[str, ...],
    ) -> ChangePlan:
        vlan = validate_vlan_id(vlan)
        address = validate_ipv4(address)
        try:
            interface = ipaddress.IPv4Interface(f"{address}/{int(prefix_length)}")
        except (ValueError, TypeError):
            raise _invalid_value("Präfixlänge", prefix_length) from None
        relays = list(dict.fromkeys(validate_ipv4(server) for server in dhcp_relay))
        if len(relays) > 4:
            raise _invalid_value("DHCP-Relay", ", ".join(relays))
        top, blocks = self._device_blocks(session)
        self._vlan_exists(blocks, vlan)
        svis = [svi for svi in parse_l3(top, blocks)["svis"] if svi["vlan"] == vlan]
        lines = _Lines()
        wanted = (str(interface.ip), interface.network.prefixlen)
        for svi in svis:
            if svi["address"] is None:
                lines.add(f"no vlan {vlan} ip address dhcp-bootp")
            elif (svi["address"], svi["prefix_length"]) != wanted:
                lines.add(f"no vlan {vlan} ip address {svi['address']}/{svi['prefix_length']}")
        if not any((svi["address"], svi["prefix_length"]) == wanted for svi in svis):
            lines.add(f"vlan {vlan} ip address {wanted[0]}/{wanted[1]}")
        current_relays = svis[0]["dhcp_relay"] if svis else []
        for server in current_relays:
            if server not in relays:
                lines.add(f"no vlan {vlan} ip helper-address {server}")
        for server in relays:
            if server not in current_relays:
                lines.add(f"vlan {vlan} ip helper-address {server}")
        return lines.plan()

    def plan_svi_delete(self, session: transport.SshSession, vlan: int) -> ChangePlan:
        vlan = validate_vlan_id(vlan)
        top, blocks = self._device_blocks(session)
        svis = [svi for svi in parse_l3(top, blocks)["svis"] if svi["vlan"] == vlan]
        if not svis:
            raise InvalidInputError(t("Das VLAN-Interface {vlan} existiert auf dem Switch nicht.", vlan=vlan))
        lines = [f"no vlan {vlan} ip helper-address {server}" for server in svis[0]["dhcp_relay"]]
        for svi in svis:
            target = "dhcp-bootp" if svi["address"] is None else f"{svi['address']}/{svi['prefix_length']}"
            lines.append(f"no vlan {vlan} ip address {target}")
        return cli_plan(lines)

    def plan_gateway(self, session: transport.SshSession, gateway: str) -> ChangePlan:
        """``ip default-gateway`` without routing; with ``ip routing`` the default route (ignored gateway)."""
        gateway = validate_ipv4(gateway)
        top, blocks = self._device_blocks(session)
        l3 = parse_l3(top, blocks)
        lines = _Lines()
        if l3["routing_enabled"]:
            defaults = [route["next_hop"] for route in l3["routes"] if route["prefix_length"] == 0]
            for next_hop in defaults:
                if next_hop != gateway:
                    lines.add(f"no ip route 0.0.0.0/0 {next_hop}")
            if gateway not in defaults:
                lines.add(f"ip route 0.0.0.0/0 {gateway}")
        elif l3["_ip_default_gateway"] != gateway:
            lines.add(f"ip default-gateway {gateway}")
        return lines.plan()

    def plan_route_add(
        self, session: transport.SshSession, prefix: str, prefix_length: int, next_hop: str, distance: int | None,
    ) -> ChangePlan:
        network = validate_ipv4_prefix(prefix, prefix_length)
        next_hop = validate_ipv4(next_hop)
        if distance is not None and not 1 <= int(distance) <= 255:
            raise _invalid_value("Distanz", distance)
        top, blocks = self._device_blocks(session)
        for route in parse_l3(top, blocks)["routes"]:
            if (route["prefix"], route["prefix_length"], route["next_hop"]) == (
                    str(network.network_address), network.prefixlen, next_hop) and route["distance"] == distance:
                raise _no_change()
        suffix = f" distance {int(distance)}" if distance is not None else ""
        return cli_plan([f"ip route {network} {next_hop}{suffix}"])

    def plan_route_delete(
        self, session: transport.SshSession, prefix: str, prefix_length: int, next_hop: str,
    ) -> ChangePlan:
        network = validate_ipv4_prefix(prefix, prefix_length)
        next_hop = validate_ipv4(next_hop)
        top, blocks = self._device_blocks(session)
        if not any((route["prefix"], route["prefix_length"], route["next_hop"]) == (
                str(network.network_address), network.prefixlen, next_hop) for route in parse_l3(top, blocks)["routes"]):
            raise InvalidInputError(t("Die Route existiert auf dem Switch nicht."))
        return cli_plan([f"no ip route {network} {next_hop}"])

    # --- ACLs --------------------------------------------------------------------------------

    def _acls(self, session: transport.SshSession) -> list[dict]:
        return parse_acls(self._device_blocks(session)[1])

    def _acl(self, session: transport.SshSession, name: str) -> dict:
        name = validate_acl_name(name)
        acl = next((acl for acl in self._acls(session) if acl["name"] == name), None)
        if acl is None:
            raise InvalidInputError(t("ACL {name} existiert auf dem Switch nicht.", name=name))
        return acl

    def plan_acl_create(self, session: transport.SshSession, name: str, acl_type: str) -> ChangePlan:
        name = validate_acl_name(name)
        acl_type = validate_choice(acl_type, ("standard", "extended"), "Typ")
        if any(acl["name"] == name for acl in self._acls(session)):
            raise InvalidInputError(t("ACL {name} existiert bereits.", name=name))
        return cli_plan([f'ip access-list {acl_type} "{name}"', "exit"])

    def plan_acl_delete(self, session: transport.SshSession, name: str) -> ChangePlan:
        acl = self._acl(session, name)
        if acl["bindings"]:
            interfaces = ", ".join(dict.fromkeys(binding["interface"] for binding in acl["bindings"]))
            raise InvalidInputError(t("Die ACL ist noch an {interfaces} gebunden.", interfaces=interfaces))
        return cli_plan([f'no ip access-list {acl["type"]} "{acl["name"]}"'])

    def plan_acl_entry_add(self, session: transport.SshSession, name: str, entry: AclEntry) -> ChangePlan:
        acl = self._acl(session, name)
        seq = int(entry.seq)
        if not 1 <= seq <= 2147483647:
            raise _invalid_value("Sequenz", seq)
        action = validate_choice(entry.action, ("permit", "deny"), "Aktion")
        source = _acl_operand(entry.src, entry.src_len)
        if acl["type"] == "standard":
            if entry.protocol != "ip" or entry.dst is not None or entry.dst_port_op:
                raise InvalidInputError(t("Eine Standard-ACL prüft nur die Quelladresse."))
            rule = f"{seq} {action} {source}"
        else:
            protocol = validate_choice(entry.protocol, ("ip", "tcp", "udp", "icmp"), "Protokoll")
            rule = f"{seq} {action} {protocol} {source} {_acl_operand(entry.dst, entry.dst_len)}"
            if entry.dst_port_op is not None:
                if protocol not in ("tcp", "udp"):
                    raise InvalidInputError(t("Zielports gibt es nur für TCP und UDP."))
                if entry.dst_port is None:
                    raise InvalidInputError(t("Es fehlt der Zielport."))
                if entry.dst_port_op == "eq":
                    rule += f" eq {int(entry.dst_port)}"
                else:
                    if entry.dst_port_end is None or entry.dst_port_end < entry.dst_port:
                        raise InvalidInputError(t("Das Ende des Portbereichs muss größer oder gleich dem Anfang sein."))
                    rule += f" range {int(entry.dst_port)} {int(entry.dst_port_end)}"
        return cli_plan([f'ip access-list {acl["type"]} "{acl["name"]}"', rule, "exit"])

    def plan_acl_entry_delete(self, session: transport.SshSession, name: str, seq: int) -> ChangePlan:
        acl = self._acl(session, name)
        if not any(entry["seq"] == int(seq) for entry in acl["entries"]):
            raise InvalidInputError(t("Der Eintrag {seq} existiert nicht.", seq=seq))
        return cli_plan([f'ip access-list {acl["type"]} "{acl["name"]}"', f"no {int(seq)}", "exit"])

    def _acl_target(self, session: transport.SshSession, interface: str) -> tuple[str, str]:
        """(binding key, command prefix ``interface X`` / ``vlan N``) of a port, LAG or VLAN interface."""
        match = _VLAN_IF_RE.fullmatch(interface.strip())
        if match:
            vlan = validate_vlan_id(int(match.group(1)))
            self._vlan_exists(self._device_blocks(session)[1], vlan)
            return f"vlan{vlan}", f"vlan {vlan}"
        name = self.validate_interface(interface)
        return name, f"interface {name}"

    def plan_acl_bind(self, session: transport.SshSession, name: str, interface: str, direction: str) -> ChangePlan:
        acl = self._acl(session, name)
        direction = validate_choice(direction, ("in", "out"), "Richtung")
        key, prefix = self._acl_target(session, interface)
        if any(binding["interface"] == key and binding["_form"] == direction for binding in acl["bindings"]):
            raise _no_change()
        return cli_plan([f'{prefix} ip access-group "{acl["name"]}" {direction}'])

    def plan_acl_unbind(self, session: transport.SshSession, name: str, interface: str, direction: str) -> ChangePlan:
        name = validate_acl_name(name)
        direction = validate_choice(direction, ("in", "out"), "Richtung")
        key, prefix = self._acl_target(session, interface)
        acl = next((acl for acl in self._acls(session) if acl["name"] == name), None)
        bound = [binding for binding in (acl or {}).get("bindings", [])
                 if binding["interface"] == key and binding["direction"] == direction]
        if not bound:
            raise InvalidInputError(t("Die ACL {name} ist an {interface} nicht gebunden.", name=name, interface=interface))
        return cli_plan([f'no {prefix} ip access-group "{name}" {binding["_form"]}' for binding in bound])

    # --- Firmware -----------------------------------------------------------------------

    def _image_state(self, session: transport.SshSession) -> dict:
        cached = session.cache.get("aoss:images")
        if cached is None:
            cached = parse_flash(self._show(session, "show flash"))
            cached.update(parse_version(self._show(session, "show version")))
            session.cache["aoss:images"] = cached
        return cached

    def _inactive_slot(self, session: transport.SshSession) -> str:
        active = self._image_state(session)["active"]
        if active not in SLOTS:
            raise InvalidInputError(t("Das aktive Image des Switches konnte nicht ermittelt werden."))
        return SLOTS[1 - SLOTS.index(active)]

    def read_firmware(self, session: transport.SshSession) -> dict:
        state = self._image_state(session)
        return {
            "running_version": state["version"],
            "boot_images": [f"{slot} ({info['version']})" for slot, info in state["slots"].items() if info["version"]],
            "next_boot": state["default"],
            "install_mode": None,
            "free_bytes": None,
            "files": [],
        }

    def plan_firmware_stage(
        self, session: transport.SshSession, image: FirmwareImage, transfer: TransferLocation, firmware: dict,
    ) -> ChangePlan:
        """``copy sftp flash {user}@{host} {file} {slot}`` into the non-active slot; the image signature is
        checked by the switch while writing, the version afterwards in ``show flash``."""
        if transfer.method != "sftp" or transfer.port != 22:
            raise InvalidInputError(t(
                "Diese Plattform lädt per SFTP nur von Port 22. Bitte den SFTP-Port in Administration → Betrieb auf 22 "
                "setzen."
            ))
        slot = self._inactive_slot(session)
        prompts = ((r"\(yes/no\)", "yes"), (r"(?i)password:", transfer.password), (YES_NO, "y"))
        tail = f"{transfer.host} {transfer.filename} {slot}"
        copy = CliCommand(f"copy sftp flash {transfer.username}@{tail}", prompts=prompts,
                          timeout=FIRMWARE_TIMEOUT_SECONDS)
        steps = [copy]
        lines = [f"copy sftp flash {REDACTED}@{tail}"]
        version = _image_file_version(image.filename)
        if version is not None:
            steps.append(CliCommand("show flash", success=re.escape(version)))
            lines.append("show flash")
        return ChangePlan(lines=tuple(lines), steps=tuple(steps), secrets=_transfer_secrets(transfer), persistent=True)

    def plan_firmware_activate(
        self, session: transport.SshSession, image: FirmwareImage, firmware: dict, reload_now: bool,
    ) -> ChangePlan:
        """``boot set-default flash {slot}`` for the non-active slot holding ``image`` (checked by version)."""
        slot = self._inactive_slot(session)
        version = _image_file_version(image.filename)
        staged = self._image_state(session)["slots"].get(slot, {}).get("version")
        if version is not None and staged != version:
            raise InvalidInputError(t("Das Image {file} liegt nicht im Flash des Switches; bitte zuerst übertragen.",
                                      file=image.filename))
        step = CliCommand(f"boot set-default flash {slot}", prompts=((YES_NO, "y"),))
        plan = ChangePlan(lines=(step.command,), steps=(step,), persistent=True)
        return combine_plans(plan, self.plan_reload(session)) if reload_now else plan

    # --- Diagnostics -------------------------------------------------------------------------

    def read_counters(self, session: transport.SshSession, interface: str | None) -> list[dict]:
        if interface is not None:
            ports = [self.validate_interface(interface)]
        else:
            ports = [row["port"] for row in self._brief(session) if self.is_physical_interface(row["port"])]
        if not ports:
            return []
        return parse_counters(self._show(session, f"show interfaces {','.join(ports)}"))

    def plan_counters_clear(self, session: transport.SshSession, interface: str) -> ChangePlan:
        interface = self.validate_interface(interface)
        step = CliCommand(f"clear statistics {interface}", prompts=((YES_NO, "y"),))
        return ChangePlan(lines=(step.command,), steps=(step,), persistent=True)

    def read_transceivers(self, session: transport.SshSession) -> list[dict]:
        return parse_transceivers(self._show(session, "show interfaces transceiver detail", allow_empty=True))

    def read_log(self, session: transport.SshSession, lines: int = 500) -> list[str]:
        return parse_log(self._show(session, "show logging -r", allow_empty=True))[: int(lines)]

    def read_environment(self, session: transport.SshSession) -> dict:
        return parse_environment(
            self._show(session, "show system temperature", allow_empty=True),
            self._show(session, "show system fans", allow_empty=True),
            self._show(session, "show system power-supply", allow_empty=True),
        )

    def plan_cable_test(self, session: transport.SshSession, interface: str) -> ChangePlan:
        interface = self.validate_interface(interface)
        if not self.is_physical_interface(interface):
            raise InvalidInputError(t("Ungültiger Interface-Name: {interface}", interface=interface))
        step = CliCommand(f"test cable-diagnostics {interface}", prompts=((YES_NO, "y"),))
        return ChangePlan(lines=(step.command,), steps=(step,), persistent=True)

    def read_cable_test(self, session: transport.SshSession, interface: str) -> dict:
        interface = self.validate_interface(interface)
        return parse_cable_test(self._show(session, f"show cable-diagnostics {interface}", allow_empty=True), interface)


def _image_file_version(filename: str) -> str | None:
    """``WC_16_10_0012.swi`` -> ``WC.16.10.0012`` (the version ``show flash`` reports), else None."""
    match = _IMAGE_FILE_RE.fullmatch(filename or "")
    return ".".join((match.group(1).upper(), *match.groups()[1:])) if match else None
