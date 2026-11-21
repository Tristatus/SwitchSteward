"""Aruba AOS-CX device settings, firmware and diagnostics.

Mixed into ``ArubaAosCxDriver``; uses only ``self`` methods of the driver (``_show``,
``read_management_path``, ``validate_interface``, ``plan_reload``) and shared helpers (no
import of ``aruba_aoscx.py``). Plans read the running configuration first so that lists
replace the configured state and the preview shows only real changes. Secrets (SNMPv3 keys,
RADIUS/TACACS keys, local passwords, transfer credentials) only go into ``steps``/``secrets``;
``lines`` show ``REDACTED``. Services, AAA, HTTPS and firmware downloads use the management
VRF (``mgmt`` when the session runs over the management port, else ``default``).
"""

import ipaddress
import re
from datetime import datetime, timezone

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
from .aruba_aoscx_l2 import config_sections, interface_sections, vlan_sections
from .cli import parse_key_values
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
    "device_ssh": supported(("timeout", "web")),
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
SLOTS = ("primary", "secondary")
# Syslog severities by number (0-7).
SEVERITIES = ("emergency", "alert", "critical", "error", "warning", "notice", "info", "debug")
SNMP_KEY_MAX_LENGTH = 32
USER_GROUPS = {"admin": "administrators", "read_only": "operators"}
ANY_ADDRESS = "0.0.0.0"  # noqa: S104 - ACL operand "any", not a bind address
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_VLAN_IF_RE = re.compile(r"^(?:interface\s+)?vlan\s*(\d{1,4})$", re.IGNORECASE)
_PORT_RE = re.compile(r"^\d+/\d+/\d+$")
_LAG_RE = re.compile(r"^lag\s?(\d+)$", re.IGNORECASE)
_BANNER_RE = re.compile(r"^banner motd (\S)\s*$")


def _no_change() -> InvalidInputError:
    return InvalidInputError(t("Keine Änderung nötig."))


def _invalid_value(label: str, value) -> InvalidInputError:
    return InvalidInputError(t("Ungültiger Wert für {label}: {value}", label=label, value=repr(value)))


def _transfer_secrets(transfer: TransferLocation) -> tuple[str, ...]:
    # Imported here: ``app.transfer`` imports ``drivers.plans`` (and with it this package).
    from ...transfer import location_secrets

    return location_secrets(transfer)


def _vrf_suffix(vrf: str | None) -> str:
    return f" vrf {vrf}" if vrf and vrf != "default" else ""


def _number(text: str | None) -> float | None:
    match = re.match(r"^-?\d+(?:\.\d+)?", (text or "").strip())
    return float(match.group(0)) if match else None


def _int(text: str | None) -> int | None:
    value = (text or "").replace(",", "").strip()
    return int(value) if value.isdigit() else None


# --- Running configuration -------------------------------------------------------------------


def split_banner(text: str) -> tuple[str | None, str]:
    """Banner text of ``banner motd X`` … ``X`` and the configuration without the banner lines."""
    lines = (text or "").splitlines()
    for index, line in enumerate(lines):
        match = _BANNER_RE.match(line)
        if not match:
            continue
        delimiter = match.group(1)
        for end in range(index + 1, len(lines)):
            if lines[end].strip() == delimiter:
                banner = "\n".join(lines[index + 1:end])
                return banner, "\n".join(lines[:index] + lines[end + 1:])
    return None, text or ""


def _top(sections) -> list[str]:
    return [header for header, _children in sections]


def _section(sections, header: str) -> list[str] | None:
    for name, children in sections:
        if name == header:
            return [text for _indent, text in children]
    return None


def _words_after(line: str, keyword: str) -> str | None:
    words = line.split()
    return words[words.index(keyword) + 1] if keyword in words and words.index(keyword) + 1 < len(words) else None


def parse_identity(banner: str | None, sections) -> dict:
    top = _top(sections)

    def value(prefix: str) -> str | None:
        return next((line[len(prefix):].strip() for line in top if line.startswith(prefix)), None)

    return {
        "hostname": value("hostname "),
        "banner": banner,
        "snmp_location": value("snmp-server system-location "),
        "snmp_contact": value("snmp-server system-contact "),
    }


def _zone_offset(name: str) -> int | None:
    """UTC offset in minutes of an AOS-CX time zone name (``europe/berlin``, ``etc/gmt-1``, ``utc``)."""
    from zoneinfo import ZoneInfo

    parts = name.split("/")
    if name.lower() == "utc":
        key = "UTC"
    elif parts[0].lower() == "etc":
        key = "Etc/" + parts[-1].upper()
    else:
        key = "/".join(part.title() for part in parts)
    try:
        offset = datetime.now(timezone.utc).astimezone(ZoneInfo(key)).utcoffset()
    except Exception:
        return None
    return int(offset.total_seconds() // 60) if offset is not None else None


def zone_name(offset_minutes: int) -> str:
    """AOS-CX time zone for a fixed offset (POSIX ``etc/gmt`` names invert the sign)."""
    if offset_minutes % 60:
        raise InvalidInputError(t("Diese Plattform stellt Zeitzonen nur in ganzen Stunden ein."))
    hours = offset_minutes // 60
    if hours == 0:
        return "utc"
    return f"etc/gmt{'-' if hours > 0 else '+'}{abs(hours)}"


def parse_services(sections) -> dict:
    top = _top(sections)
    ntp = [line.split()[2] for line in top if re.match(r"^ntp server \S+", line)]
    timezone_name = next((line.split()[2] for line in top if re.match(r"^clock timezone \S+$", line)), None)
    dns: dict[str, str] = {}
    domain_line = None
    syslog: dict[str, tuple[int | None, str]] = {}
    for line in top:
        words = line.split()
        if line.startswith("ip dns server-address ") and len(words) > 3:
            dns[words[3]] = line
        elif line.startswith("ip dns domain-name ") and len(words) > 3:
            domain_line = line
        elif len(words) >= 2 and words[0] == "logging" and re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z0-9-]+", words[1]):
            severity = _words_after(line, "severity")
            syslog[words[1]] = (SEVERITIES.index(severity) if severity in SEVERITIES else None, line)
    return {
        "ntp_servers": ntp,
        "timezone": {"name": timezone_name, "offset_minutes": _zone_offset(timezone_name) if timezone_name else None}
        if timezone_name else None,
        "dns_servers": list(dns),
        "domain_name": domain_line.split()[3] if domain_line else None,
        "syslog": [{"host": host, "severity": severity} for host, (severity, _line) in syslog.items()],
        "_dns": dns,
        "_domain_line": domain_line,
        "_syslog": syslog,
        "_ntp_vrf": next((line.split()[2] for line in top if re.match(r"^ntp vrf \S+$", line)), None),
        "_ntp_enabled": "ntp enable" in top,
    }


def parse_snmp_users(sections) -> list[dict]:
    users = []
    for line in _top(sections):
        match = re.match(r"^snmpv3 user (\S+)(.*)$", line)
        if not match:
            continue
        rest = match.group(2).split()
        auth = _words_after(line, "auth")
        users.append({
            "name": match.group(1),
            "auth": auth if auth in ("sha", "sha256") else None,
            "priv": "aes128" if _words_after(line, "priv") == "aes" else None,
            "access": "rw" if "access-level" in rest and _words_after(line, "access-level") == "rw" else "ro",
        })
    return users


def _server(line: str, kind: str) -> dict:
    words = line.split()
    port = _int(_words_after(line, "port"))
    server = {"host": words[2], "key_configured": "key" in words, "vrf": _words_after(line, "vrf")}
    if kind == "radius":
        server.update(auth_port=port or 1812, acct_port=_int(_words_after(line, "acct-port")) or 1813)
    else:
        server["port"] = port or 49
    return server


def parse_aaa(sections) -> dict:
    top = _top(sections)
    order = ["local"]
    for line in top:
        match = re.match(r"^aaa authentication login default (.+)$", line)
        if match:
            methods = [word for word in match.group(1).split() if word != "group"]
            order = [method for method in methods if method in ("local", "radius", "tacacs")] or ["local"]
    return {
        "radius": [_server(line, "radius") for line in top if re.match(r"^radius-server host \S+", line)],
        "tacacs": [_server(line, "tacacs") for line in top if re.match(r"^tacacs-server host \S+", line)],
        "login_order": order,
        "_login_configured": any(line.startswith("aaa authentication login default ") for line in top),
    }


def parse_users(sections) -> list[dict]:
    users = []
    for line in _top(sections):
        match = re.match(r"^user (\S+) group (\S+)", line)
        if match:
            users.append({"name": match.group(1),
                          "privilege": "admin" if match.group(2) == "administrators" else "read_only"})
    return users


def parse_ssh(sections) -> dict:
    top = _top(sections)
    session = _section(sections, "cli-session") or []
    minutes = next((int(m.group(1)) for line in session if (m := re.fullmatch(r"timeout (\d+)", line))), None)
    return {
        "version": "2",
        "timeout_seconds": minutes * 60 if minutes is not None else None,
        "telnet_enabled": any(line.startswith("telnet server") for line in top),
        "web_enabled": any(line.startswith("https-server vrf ") for line in top),
        "_https_vrfs": [line.split()[2] for line in top if re.match(r"^https-server vrf \S+$", line)],
    }


def _address_length(text: str) -> tuple[str, int] | None:
    match = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+)/(\d+)", text)
    return (match.group(1), int(match.group(2))) if match else None


def parse_l3(sections) -> dict:
    interfaces = interface_sections(sections)
    svis = []
    for key, children in interfaces.items():
        match = re.fullmatch(r"vlan(\d+)", key)
        if not match:
            continue
        lines = [text for _indent, text in children]
        address = next((parsed for line in lines if line.startswith("ip address ")
                        and (parsed := _address_length(line.split()[2]))), None)
        svis.append({
            "vlan": int(match.group(1)),
            "address": address[0] if address else None,
            "prefix_length": address[1] if address else None,
            "dhcp_relay": [line.split()[2] for line in lines if re.match(r"^ip helper-address \S+", line)],
            "enabled": "shutdown" not in lines,
        })
    routes = []
    for line in _top(sections):
        match = re.match(r"^ip route (\d+\.\d+\.\d+\.\d+)/(\d+) (\d+\.\d+\.\d+\.\d+)(.*)$", line)
        if match and _words_after(line, "vrf") in (None, "default"):
            routes.append({
                "prefix": match.group(1), "prefix_length": int(match.group(2)), "next_hop": match.group(3),
                "distance": _int(_words_after(line, "distance")) or 1,
            })
    mgmt = [text for _indent, text in interfaces.get("mgmt", [])]
    mgmt_gateway = next((line.split()[1] for line in mgmt if re.fullmatch(r"default-gateway \S+", line)), None)
    default = next((route["next_hop"] for route in routes if route["prefix_length"] == 0), None)
    return {
        "svis": sorted(svis, key=lambda svi: svi["vlan"]),
        "default_gateway": default or mgmt_gateway,
        "routes": routes,
        "routing_enabled": True,
        "_mgmt_gateway": mgmt_gateway,
    }


def _acl_address(tokens: list[str], index: int) -> tuple[str, int, int]:
    """(address, prefix length, next index) of ``any`` / ``A.B.C.D`` / ``A.B.C.D/mask|len``."""
    word = tokens[index] if index < len(tokens) else "any"
    if word == "any":
        return ANY_ADDRESS, 0, index + 1
    address, _, mask = word.partition("/")
    if not mask:
        return address, 32, index + 1
    length = int(mask) if mask.isdigit() else ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    return address, length, index + 1


def _acl_port(tokens: list[str], index: int) -> tuple[str | None, int | None, int | None, int]:
    if index < len(tokens) and tokens[index] == "eq" and index + 1 < len(tokens):
        return "eq", _int(tokens[index + 1]), None, index + 2
    if index < len(tokens) and tokens[index] == "range" and index + 2 < len(tokens):
        return "range", _int(tokens[index + 1]), _int(tokens[index + 2]), index + 3
    return None, None, None, index


def parse_acl_entry(line: str) -> dict | None:
    tokens = line.split()
    if len(tokens) < 4 or not tokens[0].isdigit() or tokens[1] not in ("permit", "deny"):
        return None
    protocol = "ip" if tokens[2] in ("any", "ip") else tokens[2]
    src, src_len, index = _acl_address(tokens, 3)
    _op, _port, _end, index = _acl_port(tokens, index)  # source port (not modelled)
    dst, dst_len, index = _acl_address(tokens, index)
    op, port, end, _index = _acl_port(tokens, index)
    return {
        "seq": int(tokens[0]), "action": tokens[1], "protocol": protocol, "src": src, "src_len": src_len,
        "dst": dst, "dst_len": dst_len, "dst_port_op": op, "dst_port": port, "dst_port_end": end,
    }


def parse_acl_bindings(sections) -> dict[str, list[dict]]:
    """ACL name -> [{interface, direction}]; VLAN (bridged) and SVI (routed) bindings both as ``vlan{N}``."""
    pattern = re.compile(r"^apply access-list ip (\S+) (in|out|routed-in|routed-out)$")
    bindings: dict[str, list[dict]] = {}

    def add(name: str, interface: str, direction: str, form: str) -> None:
        bindings.setdefault(name, []).append(
            {"interface": interface, "direction": direction.removeprefix("routed-"), "_form": form},
        )

    for key, children in interface_sections(sections).items():
        for _indent, text in children:
            if match := pattern.match(text):
                add(match.group(1), key, match.group(2), "svi" if key.startswith("vlan") else "port")
    for vlan, lines in vlan_sections(sections).items():
        for text in lines:
            if match := pattern.match(text):
                add(match.group(1), f"vlan{vlan}", match.group(2), "vlan")
    return bindings


def parse_acls(sections) -> list[dict]:
    acls = []
    bindings = parse_acl_bindings(sections)
    for header, children in sections:
        match = re.fullmatch(r"access-list ip (\S+)", header)
        if not match:
            continue
        entries = [entry for _indent, text in children if (entry := parse_acl_entry(text))]
        standard = bool(entries) and all(
            entry["protocol"] == "ip" and entry["dst_len"] == 0 and entry["dst_port_op"] is None for entry in entries
        )
        acls.append({
            "name": match.group(1),
            "type": "standard" if standard else "extended",
            "entries": entries,
            "bindings": [{key: value for key, value in binding.items() if not key.startswith("_")}
                         for binding in bindings.get(match.group(1), [])],
        })
    return acls


def _is_port_key(key: str) -> bool:
    return bool(_PORT_RE.match(key) or _LAG_RE.match(key))


def parse_qos(sections) -> dict:
    ports, voice = {}, {}
    for key, children in interface_sections(sections).items():
        if not _is_port_key(key):
            continue
        trust = next((m.group(1) for _i, text in children if (m := re.fullmatch(r"qos trust (\S+)", text))), None)
        ports[key] = {"trust": trust}
        voice[key] = trust == "dscp"
    return {"ports": ports, "voice_preset": voice}


# --- Firmware --------------------------------------------------------------------------------


def parse_images(output: str) -> dict:
    """``show images``: per slot ``version``/``sha256`` plus ``default`` and ``active`` slot."""
    slots: dict[str, dict] = {}
    current = None
    for line in (output or "").splitlines():
        heading = re.search(r"\b(Primary|Secondary) Image\s*$", line.strip())
        if heading and ":" not in line:
            current = heading.group(1).lower()
            slots[current] = {"version": None, "sha256": None}
            continue
        if current is None or ":" not in line:
            continue
        key, _, value = (part.strip() for part in line.partition(":"))
        if key == "Version":
            slots[current]["version"] = value or None
        elif key == "SHA-256":
            slots[current]["sha256"] = value.lower() or None
    values = parse_key_values(output)
    return {
        "slots": slots,
        "default": (values.get("Default Image") or "").lower() or None,
        "active": (values.get("Active Image") or "").lower() or None,
    }


# --- Diagnostics -----------------------------------------------------------------------------

_COUNTER_ROWS = {"Bytes": ("in_octets", "out_octets"), "Errors": ("in_errors", "out_errors"),
                 "CRC/FCS": ("crc", None), "Dropped": ("drops_in", "drops_out"), "Collision": (None, "collisions")}


def parse_counters(output: str) -> list[dict]:
    """``show interface [IF]``: RX/TX statistics table per ``Interface X is …`` block."""
    rows: list[dict] = []
    row = None
    for line in (output or "").splitlines():
        match = re.match(r"^\s*Interface (\S+) is ", line)
        if match:
            row = dict.fromkeys(("in_octets", "out_octets", "in_errors", "out_errors", "crc", "drops_in",
                                 "drops_out", "collisions"))
            row = {"interface": match.group(1), **row}
            rows.append(row)
            continue
        tokens = line.split()
        if row is None or len(tokens) < 4 or tokens[0] not in _COUNTER_ROWS:
            continue
        rx_field, tx_field = _COUNTER_ROWS[tokens[0]]
        rx, tx = tokens[-3], tokens[-2]
        if rx_field:
            row[rx_field] = _int(rx)
        if tx_field:
            row[tx_field] = _int(tx)
    return rows


def parse_transceivers(output: str) -> list[dict]:
    """``show interface dom``: Temperature, Voltage, Tx Bias, Rx/Tx power as ``mW, dBm``."""
    result = []
    for line in (output or "").splitlines():
        tokens = line.replace(",", " ").split()
        if len(tokens) < 9 or not _PORT_RE.match(tokens[0]):
            continue
        numbers = tokens[2:]
        if len(numbers) < 7 or any(_number(value) is None and value != "-inf" for value in numbers[-7:]):
            continue
        temperature, voltage, _bias, _rx_mw, rx_dbm, _tx_mw, tx_dbm = numbers[-7:]
        result.append({
            "interface": tokens[0], "type": tokens[1], "temperature_c": _number(temperature),
            "voltage_v": _number(voltage), "tx_power_dbm": _number(tx_dbm), "rx_power_dbm": _number(rx_dbm),
            "alarm": None,
        })
    return result


def parse_log(output: str) -> list[str]:
    lines = []
    for line in (output or "").splitlines():
        text = line.rstrip()
        if not text.strip() or text.strip().startswith("---") or text.strip().lower().startswith("event logs"):
            continue
        lines.append(text)
    return lines


def parse_environment(temperature: str, fans: str, power: str) -> dict:
    temperatures = []
    for line in (temperature or "").splitlines():
        match = re.match(r"^\s*(\S+)\s+.*?\s(-?\d+(?:\.\d+)?)\s*C\s+(\S+)\s*$", line)
        if match:
            temperatures.append({"sensor": match.group(1), "celsius": float(match.group(2)),
                                 "status": match.group(3)})
    fan_rows = []
    for line in (fans or "").splitlines():
        tokens = line.split()
        if len(tokens) >= 3 and re.fullmatch(r"\d+/\d+", tokens[0]):
            status = tokens[-2] if tokens[-1].isdigit() else tokens[-1]
            fan_rows.append({"name": tokens[0], "status": status})
    supplies = []
    for line in (power or "").splitlines():
        match = re.match(r"^\s*(\d+/\d+)\s+\S+\s+\S+\s+(.+?)\s+(\d+)\s*$", line)
        if match:
            supplies.append({"name": match.group(1), "status": match.group(2), "watts": int(match.group(3))})
    return {"temperatures": temperatures, "fans": fan_rows, "power_supplies": supplies}


def parse_cable_test(output: str) -> dict:
    text = output or ""
    if re.search(r"not supported", text, re.IGNORECASE):
        return {"status": "unsupported", "pairs": []}
    pairs = []
    for line in text.splitlines():
        match = re.match(r"^\s*(?:\d+/\d+/\d+\s+)?(\d-\d)\s+(\S+)\s+\S+\s+(\d+)?", line)
        if match:
            pairs.append({"pair": match.group(1), "status": match.group(2),
                          "length_m": int(match.group(3)) if match.group(3) else None})
    if not pairs or re.search(r"in progress|running", text, re.IGNORECASE):
        return {"status": "running", "pairs": pairs}
    return {"status": "done", "pairs": pairs}


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


def _acl_operand(address: str | None, prefix_length: int | None) -> str:
    if address is None or not prefix_length:
        return "any"
    network = validate_ipv4_prefix(address, prefix_length)
    return str(network.network_address) if network.prefixlen == 32 else f"{network.network_address}/{network.prefixlen}"


class AosCxDeviceMixin:
    """Device settings, firmware and diagnostics reads and plans of the AOS-CX driver."""

    transfer_method = "sftp"
    # AOS-CX has no command to reset interface counters.
    can_clear_counters = False

    # --- Shared reads ---------------------------------------------------------------------------

    def _device_running_text(self, session: transport.SshSession) -> str:
        """Full running configuration; a failed read raises (plans must not work on a guessed state)."""
        cached = session.cache.get("aoscx:running-text") or session.cache.get("running_text")
        if cached is not None:
            return cached
        conn = session.conn
        previous = getattr(conn, "read_timeout_override", None)
        conn.read_timeout_override = max(previous or 0, transport.SAVE_CONFIG_MIN_TIMEOUT_SECONDS)
        try:
            output = self._show(session, "show running-config")
        finally:
            conn.read_timeout_override = previous
        session.cache["aoscx:running-text"] = output
        return output

    def _device_config(self, session: transport.SshSession) -> tuple[str | None, list]:
        """(banner, sections) of the running configuration."""
        banner, rest = split_banner(self._device_running_text(session))
        return banner, config_sections(rest)

    def _device_sections(self, session: transport.SshSession) -> list:
        return self._device_config(session)[1]

    def _mgmt_vrf(self, session: transport.SshSession) -> str:
        """``mgmt`` when the session runs over the management port, else ``default``."""
        if "aoscx:vrf" not in session.cache:
            path = self.read_management_path(session)
            session.cache["aoscx:vrf"] = "mgmt" if path.get("management_interface") == "mgmt" else "default"
        return session.cache["aoscx:vrf"]

    # --- Device settings read -----------------------------------------------------------------------------

    def read_device_config(self, session: transport.SshSession) -> dict:
        banner, sections = self._device_config(session)

        def public(block: dict) -> dict:
            return {key: value for key, value in block.items() if not key.startswith("_")}

        aaa = parse_aaa(sections)
        return {
            "identity": parse_identity(banner, sections),
            "services": public(parse_services(sections)),
            "snmp": {"users": parse_snmp_users(sections)},
            "aaa": {
                "radius": [{key: server[key] for key in ("host", "auth_port", "acct_port", "key_configured")}
                           for server in aaa["radius"]],
                "tacacs": [{key: server[key] for key in ("host", "port", "key_configured")}
                           for server in aaa["tacacs"]],
                "login_order": aaa["login_order"],
            },
            "users": parse_users(sections),
            "ssh": public(parse_ssh(sections)),
            "l3": public(parse_l3(sections)),
            "acls": parse_acls(sections),
            "qos": parse_qos(sections),
        }

    # --- Identity and services ----------------------------------------------------------

    def plan_device_identity(self, session: transport.SshSession, change: IdentityChange) -> ChangePlan:
        banner, sections = self._device_config(session)
        current = parse_identity(banner, sections)
        lines = _Lines()
        if change.banner is not None:
            if change.banner == "":
                if current["banner"] is not None:
                    lines.add("no banner motd")
            else:
                body = [line for line in validate_banner(change.banner).split("\n") if line.strip()]
                existing = [line for line in (current["banner"] or "").split("\n") if line.strip()]
                if body != existing:
                    # "^" never occurs in a validated banner.
                    for line in ("banner motd ^", *body, "^"):
                        lines.add(line)
        for field, keyword in (("snmp_location", "system-location"), ("snmp_contact", "system-contact")):
            value = getattr(change, field)
            if value is None:
                continue
            if value == "":
                if current[field] is not None:
                    lines.add(f"no snmp-server {keyword}")
            elif (text := validate_snmp_text(value)) != current[field]:
                lines.add(f"snmp-server {keyword} {text}")
        if change.hostname is not None and validate_hostname(change.hostname) != current["hostname"]:
            # Last: the prompt changes with the hostname.
            lines.add(f"hostname {change.hostname}")
        return lines.plan()

    def plan_device_services(self, session: transport.SshSession, change: ServicesChange) -> ChangePlan:
        current = parse_services(self._device_sections(session))
        lines = _Lines()
        vrf = None
        if any(value is not None for value in (change.ntp_servers, change.dns_servers, change.domain_name,
                                               change.syslog)):
            vrf = self._mgmt_vrf(session)
        if change.ntp_servers is not None:
            wanted = list(dict.fromkeys(validate_host(server) for server in change.ntp_servers))
            for server in current["ntp_servers"]:
                if server not in wanted:
                    lines.add(f"no ntp server {server}")
            added = [server for server in wanted if server not in current["ntp_servers"]]
            for server in added:
                lines.add(f"ntp server {server} iburst")
            if added and vrf != "default" and current["_ntp_vrf"] != vrf:
                lines.add(f"ntp vrf {vrf}")
            if added and not current["_ntp_enabled"]:
                lines.add("ntp enable")
        if change.timezone_name is not None:
            name = zone_name(int(change.timezone_offset_minutes or 0))
            if (current["timezone"] or {}).get("name") != name:
                lines.add(f"clock timezone {name}")
        if change.dns_servers is not None:
            wanted = list(dict.fromkeys(validate_ipv4(server) for server in change.dns_servers))
            for server, line in current["_dns"].items():
                if server not in wanted:
                    lines.add(f"no {line}")
            for server in wanted:
                if server not in current["_dns"]:
                    lines.add(f"ip dns server-address {server}{_vrf_suffix(vrf)}")
        if change.domain_name is not None:
            if change.domain_name == "":
                if current["_domain_line"]:
                    lines.add(f"no {current['_domain_line']}")
            elif validate_host(change.domain_name) != current["domain_name"]:
                lines.add(f"ip dns domain-name {change.domain_name}{_vrf_suffix(vrf)}")
        if change.syslog is not None:
            wanted: dict[str, int] = {}
            for target in change.syslog:
                host = validate_host(target.host)
                if host in wanted:
                    raise InvalidInputError(t("Jeder Server darf nur einmal angegeben werden."))
                if not 0 <= int(target.severity) <= 7:
                    raise _invalid_value("Severity", target.severity)
                wanted[host] = int(target.severity)
            for host in current["_syslog"]:
                if host not in wanted:
                    lines.add(f"no logging {host}")
            for host, severity in wanted.items():
                if current["_syslog"].get(host, (None,))[0] != severity:
                    lines.add(f"logging {host} severity {SEVERITIES[severity]}{_vrf_suffix(vrf)}")
        return lines.plan()

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
        if any(len(key) > SNMP_KEY_MAX_LENGTH for key in keys):
            raise InvalidInputError(t("SNMPv3-Schlüssel dürfen auf dieser Plattform höchstens {limit} Zeichen lang sein.",
                                      limit=SNMP_KEY_MAX_LENGTH))
        access = validate_choice(user.access, ("ro", "rw"), "Zugriff")
        lines = _Lines()
        if any(existing["name"] == name for existing in parse_snmp_users(self._device_sections(session))):
            lines.add(f"no snmpv3 user {name}")
        shown = f"snmpv3 user {name} auth sha auth-pass plaintext {REDACTED}"
        sent = f"snmpv3 user {name} auth sha auth-pass plaintext {keys[0]}"
        if len(keys) > 1:
            shown += f" priv aes priv-pass plaintext {REDACTED}"
            sent += f" priv aes priv-pass plaintext {keys[1]}"
        lines.add(f"{shown} access-level {access}", f"{sent} access-level {access}", *keys)
        return lines.plan()

    def plan_snmp_user_delete(self, session: transport.SshSession, name: str) -> ChangePlan:
        name = validate_username(name)
        if not any(user["name"] == name for user in parse_snmp_users(self._device_sections(session))):
            raise InvalidInputError(t("SNMP-Benutzer {name} existiert auf dem Switch nicht.", name=name))
        return cli_plan([f"no snmpv3 user {name}"])

    def plan_device_aaa(self, session: transport.SshSession, change: AaaChange) -> ChangePlan:
        current = parse_aaa(self._device_sections(session))
        lines = _Lines()
        hosts = {kind: [server["host"] for server in current[kind]] for kind in ("radius", "tacacs")}
        for kind in ("radius", "tacacs"):
            wanted = getattr(change, kind)
            if wanted is not None:
                hosts[kind] = self._replace_servers(session, lines, kind, current[kind], wanted)
        if change.login_order is not None:
            order = list(dict.fromkeys(change.login_order))
            if "local" not in order:
                raise InvalidInputError(t("Die lokale Anmeldung muss als Rückfallebene erhalten bleiben."))
            for method, label in (("radius", "RADIUS"), ("tacacs", "TACACS+")):
                if method in order and not hosts[method]:
                    raise InvalidInputError(t("Für die Anmeldung über {method} ist kein Server konfiguriert.",
                                              method=label))
            if order != current["login_order"] or (order == ["local"] and current["_login_configured"]):
                if order == ["local"]:
                    lines.add("no aaa authentication login default")
                else:
                    lines.add(f"aaa authentication login default group {' '.join(order)}")
        return lines.plan()

    def _replace_servers(self, session, lines: _Lines, kind: str, configured: list[dict], wanted) -> list[str]:
        desired = {}
        for server in wanted:
            host = validate_ipv4(server.host)
            if host in desired:
                raise InvalidInputError(t("Jeder Server darf nur einmal angegeben werden."))
            desired[host] = server
        current = {server["host"]: server for server in configured}
        command = "radius-server host" if kind == "radius" else "tacacs-server host"
        for host, server in current.items():
            if host not in desired:
                lines.add(f"no {command} {host}{_vrf_suffix(server['vrf'])}")
        vrf = self._mgmt_vrf(session) if desired else None
        for host, server in desired.items():
            existing = current.get(host)
            key = validate_secret(server.key) if server.key is not None else None
            if kind == "radius":
                ports = f"port {int(server.auth_port)} acct-port {int(server.acct_port)}"
                same = existing is not None and (existing["auth_port"], existing["acct_port"]) == (
                    server.auth_port, server.acct_port)
            else:
                ports = f"port {int(server.port)}"
                same = existing is not None and existing["port"] == server.port
            if same and key is None and (existing["vrf"] or "default") == vrf:
                continue
            if key is None:
                # A server entry is identified by host and ports; a changed entry needs its key again.
                raise InvalidInputError(t("Für den neuen Server {host} ist ein Schlüssel erforderlich.", host=host))
            if existing is not None:
                lines.add(f"no {command} {host}{_vrf_suffix(existing['vrf'])}")
            tail = f" {ports} vrf {vrf}"
            lines.add(f"{command} {host} key plaintext {REDACTED}{tail}", f"{command} {host} key plaintext {key}{tail}",
                      key)
        return list(desired)

    def _check_own_account(self, session: transport.SshSession, name: str) -> None:
        if name == (session.credentials or {}).get("username"):
            raise InvalidInputError(t("Das Konto, mit dem SwitchSteward sich anmeldet, kann hier nicht geändert werden."))

    def plan_device_user_set(
        self, session: transport.SshSession, name: str, password: str | None, privilege: str,
    ) -> ChangePlan:
        name = validate_username(name)
        self._check_own_account(session, name)
        group = USER_GROUPS.get(privilege)
        if group is None:
            raise _invalid_value("Privileg", privilege)
        exists = any(user["name"] == name for user in parse_users(self._device_sections(session)))
        if password is None:
            if not exists:
                raise InvalidInputError(t("Für einen neuen Benutzer ist ein Passwort erforderlich."))
            return cli_plan([f"user {name} group {group}"])
        password = validate_secret(password)
        prefix = f"user {name} group {group} password plaintext "
        lines = _Lines()
        lines.add(prefix + REDACTED, prefix + password, password)
        return lines.plan()

    def plan_device_user_delete(self, session: transport.SshSession, name: str) -> ChangePlan:
        """``no user`` asks ``Continue (y/n)?``: exec steps through configuration mode."""
        name = validate_username(name)
        self._check_own_account(session, name)
        if not any(user["name"] == name for user in parse_users(self._device_sections(session))):
            raise InvalidInputError(t("Benutzer {name} existiert auf dem Switch nicht.", name=name))
        steps = (
            CliCommand("configure terminal"),
            CliCommand(f"no user {name}", prompts=((r"\(y/n\)", "y"),)),
            CliCommand("end"),
        )
        return ChangePlan(lines=tuple(step.command for step in steps), steps=steps)

    def plan_device_ssh(
        self, session: transport.SshSession, timeout_seconds: int | None, telnet_enabled: bool | None,
        web_enabled: bool | None,
    ) -> ChangePlan:
        if telnet_enabled is not None:
            raise InvalidInputError(t("Der Wert {value} wird von diesem Gerät nicht unterstützt.", value="telnet"))
        current = parse_ssh(self._device_sections(session))
        lines = _Lines()
        if timeout_seconds is not None:
            seconds = int(timeout_seconds)
            if not 60 <= seconds <= 3600:
                raise _invalid_value("Timeout", seconds)
            if seconds % 60:
                raise InvalidInputError(t("Diese Plattform stellt den Timeout nur in ganzen Minuten ein."))
            if current["timeout_seconds"] != seconds:
                for line in ("cli-session", f"timeout {seconds // 60}", "exit"):
                    lines.add(line)
        if web_enabled is True:
            vrf = self._mgmt_vrf(session)
            if vrf not in current["_https_vrfs"]:
                lines.add(f"https-server vrf {vrf}")
        elif web_enabled is False:
            for vrf in current["_https_vrfs"]:
                lines.add(f"no https-server vrf {vrf}")
        return lines.plan()

    # --- Layer 3 -----------------------------------------------------------------------------

    def plan_svi_set(
        self, session: transport.SshSession, vlan: int, address: str, prefix_length: int, dhcp_relay: tuple[str, ...],
    ) -> ChangePlan:
        vlan = validate_vlan_id(vlan)
        address = validate_ipv4(address)
        if not 1 <= int(prefix_length) <= 32:
            raise InvalidInputError(t("Ungültiges IPv4-Netz: {value}", value=repr(f"{address}/{prefix_length}")))
        relays = list(dict.fromkeys(validate_ipv4(server) for server in dhcp_relay))
        current = next((svi for svi in parse_l3(self._device_sections(session))["svis"] if svi["vlan"] == vlan), None)
        body: list[str] = []
        if current is None or (current["address"], current["prefix_length"]) != (address, int(prefix_length)):
            body.append(f"ip address {address}/{int(prefix_length)}")
        existing = current["dhcp_relay"] if current else []
        body += [f"no ip helper-address {server}" for server in existing if server not in relays]
        body += [f"ip helper-address {server}" for server in relays if server not in existing]
        if current is not None and not current["enabled"]:
            body.append("no shutdown")
        if not body:
            raise _no_change()
        return cli_plan([f"interface vlan {vlan}", *body, "exit"])

    def plan_svi_delete(self, session: transport.SshSession, vlan: int) -> ChangePlan:
        vlan = validate_vlan_id(vlan)
        if not any(svi["vlan"] == vlan for svi in parse_l3(self._device_sections(session))["svis"]):
            raise InvalidInputError(t("Das VLAN-Interface {vlan} existiert auf dem Switch nicht.", vlan=vlan))
        return cli_plan([f"no interface vlan {vlan}"])

    def plan_gateway(self, session: transport.SshSession, gateway: str) -> ChangePlan:
        """Management port: ``default-gateway`` in ``interface mgmt``; otherwise the default route."""
        gateway = validate_ipv4(gateway)
        l3 = parse_l3(self._device_sections(session))
        if self._mgmt_vrf(session) == "mgmt":
            if l3["_mgmt_gateway"] == gateway:
                raise _no_change()
            return cli_plan(["interface mgmt", f"default-gateway {gateway}", "exit"])
        hops = [route["next_hop"] for route in l3["routes"] if route["prefix_length"] == 0]
        lines = [f"ip route 0.0.0.0/0 {gateway}"] if gateway not in hops else []
        # Add the new route before removing the old ones: the session may depend on it.
        lines += [f"no ip route 0.0.0.0/0 {hop}" for hop in hops if hop != gateway]
        if not lines:
            raise _no_change()
        return cli_plan(lines)

    def plan_route_add(
        self, session: transport.SshSession, prefix: str, prefix_length: int, next_hop: str, distance: int | None,
    ) -> ChangePlan:
        network = validate_ipv4_prefix(prefix, prefix_length)
        next_hop = validate_ipv4(next_hop)
        if distance is not None and not 1 <= int(distance) <= 255:
            raise _invalid_value("Distanz", distance)
        for route in parse_l3(self._device_sections(session))["routes"]:
            if (route["prefix"], route["prefix_length"], route["next_hop"]) == (
                    str(network.network_address), network.prefixlen, next_hop) and (
                    distance is None or route["distance"] == int(distance)):
                raise _no_change()
        line = f"ip route {network.network_address}/{network.prefixlen} {next_hop}"
        return cli_plan([line + (f" distance {int(distance)}" if distance is not None else "")])

    def plan_route_delete(
        self, session: transport.SshSession, prefix: str, prefix_length: int, next_hop: str,
    ) -> ChangePlan:
        network = validate_ipv4_prefix(prefix, prefix_length)
        next_hop = validate_ipv4(next_hop)
        if not any((route["prefix"], route["prefix_length"], route["next_hop"]) == (
                str(network.network_address), network.prefixlen, next_hop)
                for route in parse_l3(self._device_sections(session))["routes"]):
            raise InvalidInputError(t("Die Route existiert auf dem Switch nicht."))
        return cli_plan([f"no ip route {network.network_address}/{network.prefixlen} {next_hop}"])

    # --- ACLs --------------------------------------------------------------------------------

    def _acl(self, session: transport.SshSession, name: str) -> dict:
        name = validate_acl_name(name)
        acl = next((acl for acl in parse_acls(self._device_sections(session)) if acl["name"] == name), None)
        if acl is None:
            raise InvalidInputError(t("ACL {name} existiert auf dem Switch nicht.", name=name))
        return acl

    def plan_acl_create(self, session: transport.SshSession, name: str, acl_type: str) -> ChangePlan:
        """AOS-CX has only IP ACLs; standard entries are emulated (``any {src} any``)."""
        name = validate_acl_name(name)
        validate_choice(acl_type, ("standard", "extended"), "ACL-Typ")
        if any(acl["name"] == name for acl in parse_acls(self._device_sections(session))):
            raise InvalidInputError(t("ACL {name} existiert bereits.", name=name))
        return cli_plan([f"access-list ip {name}", "exit"])

    def plan_acl_delete(self, session: transport.SshSession, name: str) -> ChangePlan:
        acl = self._acl(session, name)
        if acl["bindings"]:
            interfaces = ", ".join(f"{binding['interface']} ({binding['direction']})" for binding in acl["bindings"])
            raise InvalidInputError(t("Die ACL ist noch an {interfaces} gebunden.", interfaces=interfaces))
        return cli_plan([f"no access-list ip {acl['name']}"])

    def plan_acl_entry_add(self, session: transport.SshSession, name: str, entry: AclEntry) -> ChangePlan:
        acl = self._acl(session, name)
        seq = int(entry.seq)
        if not 1 <= seq <= 2147483647:
            raise _invalid_value("Seq", seq)
        if any(existing["seq"] == seq for existing in acl["entries"]):
            raise InvalidInputError(t("Der Eintrag {seq} existiert bereits.", seq=seq))
        action = validate_choice(entry.action, ("permit", "deny"), "Aktion")
        protocol = validate_choice(entry.protocol, ("ip", "tcp", "udp", "icmp"), "Protokoll")
        source = _acl_operand(entry.src, entry.src_len)
        destination = _acl_operand(entry.dst, entry.dst_len)
        rule = f"{seq} {action} {'any' if protocol == 'ip' else protocol} {source} {destination}"
        if entry.dst_port_op is not None:
            if protocol not in {"tcp", "udp"}:
                raise InvalidInputError(t("Zielports gibt es nur für TCP und UDP."))
            if entry.dst_port is None or not 1 <= int(entry.dst_port) <= 65535:
                raise InvalidInputError(t("Es fehlt der Zielport."))
            if entry.dst_port_op == "eq":
                rule += f" eq {int(entry.dst_port)}"
            else:
                end = entry.dst_port_end
                if end is None or not int(entry.dst_port) <= int(end) <= 65535:
                    raise InvalidInputError(t("Das Ende des Portbereichs muss größer oder gleich dem Anfang sein."))
                rule += f" range {int(entry.dst_port)} {int(end)}"
        return cli_plan([f"access-list ip {acl['name']}", rule, "exit"])

    def plan_acl_entry_delete(self, session: transport.SshSession, name: str, seq: int) -> ChangePlan:
        acl = self._acl(session, name)
        if not any(entry["seq"] == int(seq) for entry in acl["entries"]):
            raise InvalidInputError(t("Der Eintrag {seq} existiert nicht.", seq=seq))
        return cli_plan([f"access-list ip {acl['name']}", f"no {int(seq)}", "exit"])

    def _acl_target(self, session: transport.SshSession, interface: str) -> tuple[str, str, str]:
        """(key as in bindings, context line, direction prefix) of a port, LAG, VLAN or SVI."""
        match = _VLAN_IF_RE.fullmatch(interface.strip())
        if match:
            vlan = validate_vlan_id(int(match.group(1)))
            if any(svi["vlan"] == vlan for svi in parse_l3(self._device_sections(session))["svis"]):
                return f"vlan{vlan}", f"interface vlan {vlan}", "routed-"
            return f"vlan{vlan}", f"vlan {vlan}", ""
        name = self.validate_interface(interface)
        lag = _LAG_RE.match(name)
        if not _is_port_key(name.lower()):
            raise InvalidInputError(t("Das Interface {interface} kann keine ACL tragen.", interface=interface))
        return name.lower(), f"interface lag {lag.group(1)}" if lag else f"interface {name}", ""

    def plan_acl_bind(self, session: transport.SshSession, name: str, interface: str, direction: str) -> ChangePlan:
        acl = self._acl(session, name)
        direction = validate_choice(direction, ("in", "out"), "Richtung")
        key, context, prefix = self._acl_target(session, interface)
        if any(binding["interface"] == key and binding["direction"] == direction for binding in acl["bindings"]):
            raise _no_change()
        return cli_plan([context, f"apply access-list ip {acl['name']} {prefix}{direction}", "exit"])

    def plan_acl_unbind(self, session: transport.SshSession, name: str, interface: str, direction: str) -> ChangePlan:
        name = validate_acl_name(name)
        direction = validate_choice(direction, ("in", "out"), "Richtung")
        key, _context, _prefix = self._acl_target(session, interface)
        bound = [binding for binding in parse_acl_bindings(self._device_sections(session)).get(name, [])
                 if binding["interface"] == key and binding["direction"] == direction]
        if not bound:
            raise InvalidInputError(t("Die ACL {name} ist an {interface} nicht gebunden.", name=name, interface=interface))
        lines = []
        for binding in bound:
            form = binding["_form"]
            if form == "vlan":
                context, word = f"vlan {key[4:]}", direction
            elif form == "svi":
                context, word = f"interface vlan {key[4:]}", f"routed-{direction}"
            else:
                lag = _LAG_RE.match(key)
                context, word = (f"interface lag {lag.group(1)}" if lag else f"interface {key}"), direction
            lines += [context, f"no apply access-list ip {name} {word}", "exit"]
        return cli_plan(lines)

    # --- QoS ---------------------------------------------------------------------------------

    def plan_qos_port(
        self, session: transport.SshSession, interface: str, trust: str | None, voice_preset: bool | None,
    ) -> ChangePlan:
        """Voice preset = ``qos trust dscp`` (EF -> local priority 5); removing it returns to the global trust."""
        name = self.validate_interface(interface)
        if trust is not None:
            validate_choice(trust, ("none", "cos", "dscp"), "Trust")
        if voice_preset is True and trust not in (None, "dscp"):
            raise InvalidInputError(t("Die Voice-Vorlage setzt auf dieser Plattform Trust DSCP voraus."))
        key = name.lower()
        current = parse_qos(self._device_sections(session))["ports"].get(key, {}).get("trust")
        target = "dscp" if voice_preset else trust
        lines = []
        if target is not None and target != current:
            lines.append(f"qos trust {target}")
        elif target is None and voice_preset is False and current == "dscp":
            lines.append("no qos trust")
        if not lines:
            raise _no_change()
        lag = _LAG_RE.match(name)
        return cli_plan([f"interface lag {lag.group(1)}" if lag else f"interface {name}", *lines, "exit"])

    # --- Firmware -----------------------------------------------------------------------

    def _image_state(self, session: transport.SshSession) -> dict:
        cached = session.cache.get("aoscx:images")
        if cached is None:
            version = parse_key_values(self._show(session, "show version"))
            cached = parse_images(self._show(session, "show images"))
            cached["version"] = version.get("Version")
            cached["active"] = (version.get("Active Image") or "").lower() or cached["active"]
            session.cache["aoscx:images"] = cached
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
        """``copy {sftp-url} {slot} vrf {vrf}`` into the non-active slot, then check its SHA-256."""
        if not _SHA256_RE.fullmatch(image.sha256 or ""):
            raise _invalid_value("SHA-256", image.sha256)
        slot = self._inactive_slot(session)
        vrf = self._mgmt_vrf(session)
        prompts = ((r"\(yes/no\)", "yes"), (r"(?i)password:", transfer.password), (r"\(y/n\)", "y"))
        copy = CliCommand(f"copy {transfer.url} {slot} vrf {vrf}", prompts=prompts, timeout=FIRMWARE_TIMEOUT_SECONDS,
                          success=r"(?i)verifying and writing")
        verify = CliCommand("show images", success=f"(?i){image.sha256}")
        return ChangePlan(
            lines=(f"copy {transfer.display_url} {slot} vrf {vrf}", verify.command),
            steps=(copy, verify),
            secrets=_transfer_secrets(transfer),
            persistent=True,
        )

    def plan_firmware_activate(
        self, session: transport.SshSession, image: FirmwareImage, firmware: dict, reload_now: bool,
    ) -> ChangePlan:
        """``boot set-default {slot}`` for the non-active slot holding ``image`` (checked by SHA-256)."""
        slot = self._inactive_slot(session)
        staged = self._image_state(session)["slots"].get(slot, {}).get("sha256")
        if not staged or staged != (image.sha256 or "").lower():
            raise InvalidInputError(t("Das Image {file} liegt nicht im Flash des Switches; bitte zuerst übertragen.",
                                      file=image.filename))
        step = CliCommand(f"boot set-default {slot}", prompts=((r"\(y/n\)", "y"),),
                          success=r"(?i)default boot image set")
        plan = ChangePlan(lines=(step.command,), steps=(step,), persistent=True)
        return combine_plans(plan, self.plan_reload(session)) if reload_now else plan

    # --- Diagnostics --------------------------------------------------------------------

    def read_counters(self, session: transport.SshSession, interface: str | None) -> list[dict]:
        if interface is not None:
            interface = self.validate_interface(interface)
            return parse_counters(self._show(session, f"show interface {interface}"))
        rows = parse_counters(self._show(session, "show interface"))
        return [row for row in rows if _is_port_key(row["interface"].lower())]

    def read_transceivers(self, session: transport.SshSession) -> list[dict]:
        return parse_transceivers(self._show(session, "show interface dom", allow_empty=True))

    def read_log(self, session: transport.SshSession, lines: int = 500) -> list[str]:
        return parse_log(self._show(session, f"show events -r -n {int(lines)}", allow_empty=True))[: int(lines)]

    def read_environment(self, session: transport.SshSession) -> dict:
        return parse_environment(
            self._show(session, "show environment temperature", allow_empty=True),
            self._show(session, "show environment fan", allow_empty=True),
            self._show(session, "show environment power-supply", allow_empty=True),
        )

    def plan_cable_test(self, session: transport.SshSession, interface: str) -> ChangePlan:
        interface = self.validate_interface(interface)
        if not self.is_physical_interface(interface):
            raise InvalidInputError(t("Ungültiger Interface-Name: {interface}", interface=repr(interface)))
        step = CliCommand(f"diag cable-diagnostic test {interface}", prompts=((r"\(y/n\)", "y"),))
        return ChangePlan(lines=(step.command,), steps=(step,), persistent=True)

    def read_cable_test(self, session: transport.SshSession, interface: str) -> dict:
        interface = self.validate_interface(interface)
        return parse_cable_test(self._show(session, f"diag cable-diagnostic show {interface}", allow_empty=True))
