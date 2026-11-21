"""MikroTik RouterOS device settings, firmware and diagnostics.

Mixin of ``MikrotikDriver``; uses the driver's REST helpers through ``self`` (``request``, ``_list``,
``_object``, ``_cached``, ``_resource``, ``_ethernet``, ``_bridge``) and never imports the driver module.
Every write is a list of ``RestCall`` steps; singleton menus are changed with ``POST /{menu}/set``.
RouterOS stores every change immediately, so all plans are ``persistent``.

Platform decisions:
- No system domain name; SSH is always SSHv2 without a settable timeout, "web off" disables
  ``www`` and WebFig on HTTPS (``/ip/service/webserver``) but never ``www-ssl`` (REST API).
- ACLs: RouterOS has no ACL objects. An ACL is stored as disabled ``/ip/firewall/filter`` rules
  (header ``swm:{acl}:0:{type}``, one template per entry ``swm:{acl}:{seq}``). A port binding (ingress only)
  copies the entries into ``/interface/ethernet/switch/rule`` (``comment="swm:{acl}:{seq}"``, ``ports`` = all
  bound ports) plus a final drop rule ``swm:{acl}:end``; a VLAN-interface binding copies them into the
  ``forward`` chain with ``in-interface``/``out-interface`` (``swm:{acl}:{seq}:{in|out}:{interface}`` and
  ``swm:{acl}:end:{in|out}:{interface}``). The explicit drop rule reproduces the implicit deny of other platforms.
- QoS: only with ``qos-hw-offloading=yes`` on the switch chip. This is a device-level state, so it is checked
  where it matters instead of a per-port runtime override: ``read_device_config`` reports ``qos=None`` plus a
  warning and ``plan_qos_port`` raises ``UnsupportedFeatureError("qos", …)``.
- Firmware: ``/tool/fetch`` of the ``.npk`` runs as a background script (``POST /execute``); the plan then
  waits with a ``RestWaitForFile`` step (executed by ``run_device_step``) until the file has the image size.
  Activation = reboot (``plan_reload``); a downgrade uses ``/system/package/downgrade``.
"""

import ipaddress
import json
import re
import time
from dataclasses import asdict, dataclass

from ...i18n import t
from ..errors import InvalidInputError, SwitchConnectionError, UnsupportedFeatureError, append_warning
from ..validation import (
    validate_acl_name,
    validate_banner,
    validate_host,
    validate_hostname,
    validate_ipv4,
    validate_ipv4_prefix,
    validate_secret,
    validate_snmp_text,
    validate_username,
    validate_vlan_id,
)
from .plans import REDACTED, AclEntry, ChangePlan, FirmwareImage, RestCall, TransferLocation, combine_plans

_UNSPECIFIED = str(ipaddress.IPv4Address(0))
QOS_OFFLOAD_REASON = "QoS-Hardware-Offloading ist auf diesem Gerät nicht aktiv."

# Body keys whose values are secrets (same set as ``mikrotik.SECRET_KEYS``).
_SECRET_KEYS = frozenset({"password", "secret", "authentication-password", "encryption-password"})
_ROW_ID_RE = re.compile(r"\*[0-9A-Fa-f]{1,16}")
_VLAN_TARGET_RE = re.compile(r"(?:interface\s+)?vlan\s*(\d{1,4})", re.IGNORECASE)
_ACL_HEADER_RE = re.compile(r"swm:([A-Za-z0-9_-]+):0:(standard|extended)")
_ACL_TEMPLATE_RE = re.compile(r"swm:([A-Za-z0-9_-]+):([1-9]\d*)")
_ACL_SWITCH_RE = re.compile(r"swm:([A-Za-z0-9_-]+):([1-9]\d*|end)")
_ACL_FILTER_BIND_RE = re.compile(r"swm:([A-Za-z0-9_-]+):([1-9]\d*|end):(in|out):(\S+)")
_NPK_VERSION_RE = re.compile(r"-(\d+(?:\.\d+)+)(?:-|\.npk$)")
_SEVERITY_TOPICS = (("critical", 0), ("error", 3), ("warning", 4), ("info", 5), ("debug", 7))
_TOPIC_SEVERITY = {"critical": 2, "error": 3, "warning": 4, "info": 6, "debug": 7}
_TRUST_BODIES = {
    "none": {"trust-l2": "ignore", "trust-l3": "ignore"},
    "cos": {"trust-l2": "trust", "trust-l3": "ignore"},
    "dscp": {"trust-l3": "trust"},
}


@dataclass(frozen=True)
class RestWaitForFile:
    """Poll ``GET /file?name={name}`` until the file has ``size`` bytes (background ``/tool/fetch``).

    Fails after ``timeout`` seconds or when the size has not changed for ``stall_seconds``.
    """

    name: str
    size: int
    timeout: int = 3600
    interval: int = 5
    stall_seconds: int = 180


# --- Helpers --------------------------------------------------------------------------


def _bool(value) -> bool | None:
    text = str(value).strip().lower() if value is not None else ""
    if text in {"true", "yes"}:
        return True
    if text in {"false", "no"}:
        return False
    return None


def _split(value) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _number(value) -> float | None:
    """``"33"``, ``"-5.792dBm"``, ``"3.237V"`` -> float (unit suffix stripped)."""
    match = re.match(r"\s*(-?\d+(?:\.\d+)?)", str(value if value is not None else ""))
    return float(match.group(1)) if match else None


def _int(value) -> int | None:
    number = _number(value)
    return int(number) if number is not None else None


def _rid(row: dict) -> str:
    row_id = str(row.get(".id") or "")
    if not _ROW_ID_RE.fullmatch(row_id):
        raise SwitchConnectionError(t("Der Switch hat einen Eintrag ohne gültige .id geliefert."))
    return row_id


def _gateway(value) -> str | None:
    text = str(value or "").split("%", 1)[0].strip()
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return text or None


def _prefix(value) -> tuple[str | None, int | None]:
    """``10.0.0.0/24`` -> ("10.0.0.0", 24); bare address = /32; empty -> (None, None)."""
    text = str(value or "").strip()
    if not text:
        return None, None
    address, _, length = text.partition("/")
    return address, int(length) if length.isdigit() else 32


def _offset_minutes(value) -> int | None:
    text = str(value or "").strip()
    match = re.fullmatch(r"([+-])(\d{1,2}):(\d{2})", text)
    if match:
        minutes = int(match.group(2)) * 60 + int(match.group(3))
        return -minutes if match.group(1) == "-" else minutes
    if re.fullmatch(r"[+-]?\d+", text):  # seconds
        return int(text) // 60
    return None


def _script_text(value: str) -> str:
    """Quote a value for a RouterOS script string literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")


def _transfer_secrets(transfer: TransferLocation) -> tuple[str, ...]:
    # Imported here: ``app.transfer`` imports ``drivers.plans`` (and with it this package).
    from ...transfer import location_secrets

    return location_secrets(transfer)


def rest_text(call: RestCall) -> str:
    """Displayed form of a REST call (format of ``mikrotik.rest_line``); secret values redacted."""
    if call.body is None:
        return f"{call.method} {call.path}"
    body = {key: REDACTED if key in _SECRET_KEYS else value for key, value in call.body.items()}
    return f"{call.method} {call.path} {json.dumps(body, sort_keys=True, ensure_ascii=False)}"


def wait_text(step: RestWaitForFile) -> str:
    return f"WAIT GET /file?name={step.name} size={step.size}"


class _Plan:
    """Collects REST steps, their displayed lines and the secrets they carry."""

    def __init__(self):
        self.steps: list = []
        self.lines: list[str] = []
        self.secrets: list[str] = []
        self.warnings: list[str] = []

    def call(self, method: str, path: str, body: dict | None = None, *secrets: str, shown: str | None = None):
        step = RestCall(method, path, body)
        self.steps.append(step)
        self.lines.append(shown if shown is not None else rest_text(step))
        self.secrets.extend(secret for secret in secrets if secret)

    def wait(self, step: RestWaitForFile):
        self.steps.append(step)
        self.lines.append(wait_text(step))

    def build(self, *, require: bool = True, **kwargs) -> ChangePlan:
        if require and not self.steps:
            raise InvalidInputError(t("Keine Änderung nötig."))
        warnings = tuple(dict.fromkeys([*self.warnings, *kwargs.pop("warnings", ())]))
        return ChangePlan(
            lines=tuple(self.lines), steps=tuple(self.steps), persistent=True, warnings=warnings,
            secrets=tuple(dict.fromkeys(self.secrets)), **kwargs,
        )


def _acl_entry_dict(entry: AclEntry) -> dict:
    return asdict(entry)


def _match_body(entry: dict) -> dict:
    """Match fields shared by firewall filter and switch rules."""
    body = {}
    if entry["protocol"] != "ip":
        body["protocol"] = entry["protocol"]
    if entry["src_len"]:
        body["src-address"] = f"{entry['src']}/{entry['src_len']}"
    if entry.get("dst") is not None and entry.get("dst_len"):
        body["dst-address"] = f"{entry['dst']}/{entry['dst_len']}"
    if entry.get("dst_port_op") == "eq":
        body["dst-port"] = str(entry["dst_port"])
    elif entry.get("dst_port_op") == "range":
        body["dst-port"] = f"{entry['dst_port']}-{entry['dst_port_end']}"
    return body


def _filter_body(entry: dict) -> dict:
    return {"chain": "forward", "action": "accept" if entry["action"] == "permit" else "drop", **_match_body(entry)}


def _switch_body(entry: dict) -> dict:
    body = _match_body(entry)
    if entry["action"] == "deny":
        body["new-dst-ports"] = ""
    return body


def _entry_from_filter(seq: int, row: dict) -> dict:
    src, src_len = _prefix(row.get("src-address"))
    dst, dst_len = _prefix(row.get("dst-address"))
    port = str(row.get("dst-port") or "")
    first, _, last = port.partition("-")
    return {
        "seq": seq,
        "action": "deny" if row.get("action") in {"drop", "reject"} else "permit",
        "protocol": row.get("protocol") or "ip",
        "src": src or _UNSPECIFIED,
        "src_len": src_len or 0,
        "dst": dst,
        "dst_len": dst_len,
        "dst_port_op": ("range" if last else "eq") if first.isdigit() else None,
        "dst_port": int(first) if first.isdigit() else None,
        "dst_port_end": int(last) if last.isdigit() else None,
    }


class MikrotikDeviceMixin:
    """Device settings, firmware and diagnostics (except ``plan_reload``) for ``MikrotikDriver``."""

    # --- Shared reads -------------------------------------------------------------------

    def _optional(self, session, path: str) -> list[dict]:
        rows = self._list(session, path, missing_ok=True)
        return rows or []

    def _singleton(self, session, path: str) -> dict | None:
        data = self.request(session, "GET", path, missing_ok=True)
        if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
            data = data[0]
        return data if isinstance(data, dict) else None

    def _vlan_interfaces(self, session) -> list[dict]:
        data = self._cached(
            session, "vlan_interfaces", lambda: self.request(session, "GET", "/interface/vlan", missing_ok=True),
        )
        return [row for row in data or () if isinstance(row, dict) and row.get("name")]

    def _vlan_interface(self, session, vlan: int) -> dict | None:
        return next((row for row in self._vlan_interfaces(session) if str(row.get("vlan-id")) == str(vlan)), None)

    def _switch_chips(self, session) -> list[dict]:
        return self._cached(session, "switch_chips", lambda: self._optional(session, "/interface/ethernet/switch"))

    def _qos_offloading(self, session) -> bool:
        return any(_bool(row.get("qos-hw-offloading")) is True for row in self._switch_chips(session))

    # --- read_device_config ---------------------------------------------------------------

    def read_device_config(self, session) -> dict:
        """All phase-6 blocks; a block that cannot be read is ``None`` with a session warning. No secrets."""
        config = {}
        for name, read in (
            ("identity", self._read_identity), ("services", self._read_services), ("snmp", self._read_snmp),
            ("aaa", self._read_aaa), ("users", self._read_users), ("ssh", self._read_ssh), ("l3", self._read_l3),
            ("acls", self._read_acls), ("qos", self._read_qos),
        ):
            try:
                config[name] = read(session)
            except (SwitchConnectionError, InvalidInputError):
                append_warning(session.warnings, t("Der Bereich {section} konnte nicht gelesen werden.", section=name))
                config[name] = None
        return config

    def _read_identity(self, session) -> dict:
        identity = self._object(session, "/system/identity")
        note = self._singleton(session, "/system/note") or {}
        snmp = self._singleton(session, "/snmp") or {}
        return {
            "hostname": identity.get("name") or None,
            "banner": note.get("note") or None,
            "snmp_location": snmp.get("location") or None,
            "snmp_contact": snmp.get("contact") or None,
        }

    def _ntp_server_rows(self, session) -> list[dict] | None:
        """``/system/ntp/client/servers`` rows (newer 7.x) or None when the menu does not exist."""
        return self._list(session, "/system/ntp/client/servers", missing_ok=True)

    def _syslog_actions(self, session) -> tuple[list[dict], list[dict]]:
        actions = [
            row for row in self._list(session, "/system/logging/action")
            if row.get("target") == "remote" and row.get("name")
        ]
        return actions, self._list(session, "/system/logging")

    @staticmethod
    def _action_severity(action: str, rules: list[dict]) -> int | None:
        levels = []
        for rule in rules:
            if rule.get("action") != action or _bool(rule.get("disabled")) is True:
                continue
            for topic in _split(rule.get("topics")):
                if topic in _TOPIC_SEVERITY:
                    levels.append(_TOPIC_SEVERITY[topic])
        return max(levels) if levels else None

    def _read_services(self, session) -> dict:
        rows = self._ntp_server_rows(session)
        if rows is None:
            ntp = _split((self._singleton(session, "/system/ntp/client") or {}).get("servers"))
        else:
            ntp = [str(row["address"]) for row in rows if row.get("address")]
        clock = self._singleton(session, "/system/clock") or {}
        dns = self._singleton(session, "/ip/dns") or {}
        actions, rules = self._syslog_actions(session)
        syslog = [
            {"host": str(row["remote"]), "severity": self._action_severity(row["name"], rules)}
            for row in actions if _gateway(row.get("remote")) not in (None, _UNSPECIFIED)
        ]
        return {
            "ntp_servers": ntp,
            "timezone": {"name": clock.get("time-zone-name") or None,
                         "offset_minutes": _offset_minutes(clock.get("gmt-offset"))},
            "dns_servers": _split(dns.get("servers")),
            "domain_name": None,
            "syslog": syslog,
        }

    def _read_snmp(self, session) -> dict:
        users = []
        for row in self._list(session, "/snmp/community"):
            if row.get("security") not in {"authorized", "private"}:
                continue
            auth = {"SHA1": "sha", "SHA256": "sha256"}.get(str(row.get("authentication-protocol") or "").upper())
            priv = "aes128" if row.get("security") == "private" and str(row.get("encryption-protocol")).upper() == "AES" else None
            users.append({
                "name": row.get("name"),
                "auth": auth,
                "priv": priv,
                "access": "rw" if _bool(row.get("write-access")) else "ro",
            })
        return {"users": users}

    def _login_radius(self, session) -> list[dict]:
        return [row for row in self._list(session, "/radius") if "login" in _split(row.get("service"))]

    def _read_aaa(self, session) -> dict:
        radius = [
            {
                "host": row.get("address"),
                "auth_port": _int(row.get("authentication-port")) or 1812,
                "acct_port": _int(row.get("accounting-port")) or 1813,
                "key_configured": bool(row.get("secret")) if "secret" in row else None,
            }
            for row in self._login_radius(session)
        ]
        aaa = self._singleton(session, "/user/aaa") or {}
        order = ["local", "radius"] if _bool(aaa.get("use-radius")) else ["local"]
        return {"radius": radius, "tacacs": None, "login_order": order}

    def _read_users(self, session) -> list[dict]:
        groups = {"full": "admin", "read": "read_only"}
        return [{"name": row.get("name"), "privilege": groups.get(row.get("group"))}
                for row in self._list(session, "/user") if row.get("name")]

    def _services(self, session) -> dict[str, dict]:
        return {row["name"]: row for row in self._list(session, "/ip/service") if row.get("name")}

    def _read_ssh(self, session) -> dict:
        services = self._services(session)
        webserver = self._singleton(session, "/ip/service/webserver")
        www = _bool(services.get("www", {}).get("disabled")) is False
        webfig = _bool(webserver.get("webfig-secure")) is True if webserver else False
        telnet = services.get("telnet")
        return {
            "version": "2",
            "timeout_seconds": None,
            "telnet_enabled": None if telnet is None else _bool(telnet.get("disabled")) is False,
            "web_enabled": www or webfig,
        }

    def _static_routes(self, session) -> list[dict]:
        return [row for row in self._list(session, "/ip/route?static=true")
                if _bool(row.get("static")) is not False and _bool(row.get("dynamic")) is not True
                and row.get("dst-address")]

    def _read_l3(self, session) -> dict:
        addresses = self._list(session, "/ip/address")
        relays = self._optional(session, "/ip/dhcp-relay")
        svis = []
        for row in self._vlan_interfaces(session):
            if not str(row.get("vlan-id") or "").isdigit():
                continue
            address = next((item for item in addresses if item.get("interface") == row["name"]), None)
            ip, length = _prefix(address.get("address")) if address else (None, None)
            relay = [server for item in relays if item.get("interface") == row["name"]
                     for server in _split(item.get("dhcp-server"))]
            svis.append({"vlan": int(row["vlan-id"]), "address": ip, "prefix_length": length,
                         "dhcp_relay": relay, "enabled": _bool(row.get("disabled")) is not True})
        routes = []
        default = None
        for row in self._static_routes(session):
            prefix, length = _prefix(row.get("dst-address"))
            gateway = _gateway(row.get("gateway"))
            if prefix == _UNSPECIFIED and length == 0 and (default is None or _bool(row.get("active"))):
                default = gateway
            routes.append({"prefix": prefix, "prefix_length": length, "next_hop": gateway,
                           "distance": _int(row.get("distance"))})
        return {"svis": svis, "default_gateway": default, "routes": routes, "routing_enabled": True}

    def _read_qos(self, session) -> dict | None:
        if not self._qos_offloading(session):
            append_warning(session.warnings, t(QOS_OFFLOAD_REASON))
            return None
        ports = {}
        for row in self._list(session, "/interface/ethernet/switch/qos/port"):
            if not row.get("name"):
                continue
            if row.get("trust-l3") in {"trust", "keep"}:
                trust = "dscp"
            elif row.get("trust-l2") in {"trust", "keep"}:
                trust = "cos"
            else:
                trust = "none"
            ports[self.interface_key(row["name"])] = {"trust": trust}
        return {"ports": ports, "voice_preset": None}

    # --- Identity --------------------------------------------------------------------

    def plan_device_identity(self, session, change) -> ChangePlan:
        plan = _Plan()
        if change.hostname is not None:
            plan.call("POST", "/system/identity/set", {"name": validate_hostname(change.hostname)})
        if change.banner is not None:
            banner = validate_banner(change.banner)
            body = {"note": banner, "show-at-login": "yes"} if banner else {"note": ""}
            plan.call("POST", "/system/note/set", body)
        snmp = {}
        if change.snmp_location is not None:
            snmp["location"] = validate_snmp_text(change.snmp_location) if change.snmp_location else ""
        if change.snmp_contact is not None:
            snmp["contact"] = validate_snmp_text(change.snmp_contact) if change.snmp_contact else ""
        if snmp:
            plan.call("POST", "/snmp/set", snmp)
        return plan.build()

    # --- Services --------------------------------------------------------------------

    def plan_device_services(self, session, change) -> ChangePlan:
        if change.domain_name:
            raise InvalidInputError(t("RouterOS kennt keinen Domänennamen; das Feld wird nicht unterstützt."))
        plan = _Plan()
        if change.ntp_servers is not None:
            self._ntp_steps(session, plan, [validate_host(server) for server in change.ntp_servers])
        if change.timezone_name is not None or change.timezone_offset_minutes is not None:
            offset = change.timezone_offset_minutes
            if offset is None or not -720 <= offset <= 840:
                raise InvalidInputError(t("RouterOS braucht für die Zeitzone den Zeitversatz in Minuten."))
            sign = "-" if offset < 0 else "+"
            plan.call("POST", "/system/clock/set", {"time-zone-autodetect": "no", "time-zone-name": "manual"})
            plan.call("POST", "/system/clock/manual/set",
                      {"time-zone": f"{sign}{abs(offset) // 60:02d}:{abs(offset) % 60:02d}"})
            if change.timezone_name:
                plan.warnings.append(t("RouterOS speichert nur den Zeitversatz; der Name {name} wird nicht übernommen.",
                                       name=change.timezone_name))
        if change.dns_servers is not None:
            plan.call("POST", "/ip/dns/set", {"servers": ",".join(validate_ipv4(item) for item in change.dns_servers)})
        if change.syslog is not None:
            self._syslog_steps(session, plan, change.syslog)
        return plan.build()

    def _ntp_steps(self, session, plan: _Plan, servers: list[str]) -> None:
        client = self._singleton(session, "/system/ntp/client") or {}
        rows = self._ntp_server_rows(session)
        if rows is None:  # older 7.x: one "servers" list on the client
            body = {"enabled": "yes", "mode": "unicast", "servers": ",".join(servers)} if servers else {"enabled": "no"}
            plan.call("POST", "/system/ntp/client/set", body)
            return
        configured = [row for row in rows if _bool(row.get("dynamic")) is not True]
        for row in configured:
            if row.get("address") not in servers:
                plan.call("DELETE", f"/system/ntp/client/servers/{_rid(row)}")
        present = {row.get("address") for row in configured}
        for server in servers:
            if server not in present:
                plan.call("PUT", "/system/ntp/client/servers", {"address": server})
        enabled = _bool(client.get("enabled")) is True and client.get("mode") in (None, "unicast")
        if servers and not enabled:
            plan.call("POST", "/system/ntp/client/set", {"enabled": "yes", "mode": "unicast"})
        elif not servers and _bool(client.get("enabled")) is True:
            plan.call("POST", "/system/ntp/client/set", {"enabled": "no"})

    def _syslog_steps(self, session, plan: _Plan, targets) -> None:
        wanted: dict[str, int] = {}
        for target in targets:
            host = validate_ipv4(target.host)
            if not 0 <= target.severity <= 7:
                raise InvalidInputError(t("Ungültiger Schweregrad: {value}", value=target.severity))
            if host in wanted:
                raise InvalidInputError(t("Jeder Server darf nur einmal angegeben werden."))
            wanted[host] = target.severity
        actions, rules = self._syslog_actions(session)
        names = {row["name"] for row in actions}
        existing: dict[str, dict] = {}
        for action in actions:
            host = _gateway(action.get("remote"))
            if host in (None, _UNSPECIFIED):
                continue
            current = self._action_severity(action["name"], rules)
            if host in wanted and host not in existing and current == wanted[host]:
                existing[host] = action
                continue
            for rule in rules:
                if rule.get("action") == action["name"] and _bool(rule.get("dynamic")) is not True:
                    plan.call("DELETE", f"/system/logging/{_rid(rule)}")
            if host in wanted and host not in existing:
                existing[host] = action
                self._syslog_rules(plan, action["name"], wanted[host])
            elif _bool(action.get("default")) is True:
                plan.call("PATCH", f"/system/logging/action/{_rid(action)}", {"remote": _UNSPECIFIED})
            else:
                plan.call("DELETE", f"/system/logging/action/{_rid(action)}")
        number = 1
        for host, severity in wanted.items():
            if host in existing:
                continue
            while f"swmsyslog{number}" in names:
                number += 1
            name = f"swmsyslog{number}"
            names.add(name)
            plan.call("PUT", "/system/logging/action", {
                "name": name, "target": "remote", "remote": host, "remote-port": "514",
                "remote-log-format": "syslog", "syslog-facility": "local7",
            })
            self._syslog_rules(plan, name, severity)

    @staticmethod
    def _syslog_rules(plan: _Plan, action: str, severity: int) -> None:
        # One rule per topic: several topics in one rule are ANDed by RouterOS.
        for topic, minimum in _SEVERITY_TOPICS:
            if severity >= minimum:
                plan.call("PUT", "/system/logging", {"topics": topic, "action": action})

    # --- SNMP, AAA, users, SSH -----------------------------------------------------------

    def _community(self, session, name: str) -> dict | None:
        return next((row for row in self._list(session, "/snmp/community") if row.get("name") == name), None)

    def plan_snmp_user_set(self, session, user) -> ChangePlan:
        name = validate_username(user.name)
        auth_key = validate_secret(user.auth_key)
        body = {
            "name": name,
            "security": "private" if user.priv else "authorized",
            "authentication-protocol": {"sha": "SHA1", "sha256": "SHA256"}[user.auth],
            "authentication-password": auth_key,
            "read-access": "yes",
            "write-access": "yes" if user.access == "rw" else "no",
        }
        secrets = [auth_key]
        if user.priv:
            if not user.priv_key:
                raise InvalidInputError(t("Für die Verschlüsselung ist ein Schlüssel erforderlich."))
            body["encryption-protocol"] = "AES"
            body["encryption-password"] = validate_secret(user.priv_key)
            secrets.append(body["encryption-password"])
        plan = _Plan()
        snmp = self._singleton(session, "/snmp") or {}
        if _bool(snmp.get("enabled")) is not True:
            plan.call("POST", "/snmp/set", {"enabled": "yes"})
        row = self._community(session, name)
        if row is None:
            plan.call("PUT", "/snmp/community", body, *secrets)
        else:
            plan.call("PATCH", f"/snmp/community/{_rid(row)}", body, *secrets)
        return plan.build()

    def plan_snmp_user_delete(self, session, name: str) -> ChangePlan:
        row = self._community(session, validate_username(name))
        if row is None:
            raise InvalidInputError(t("SNMP-Benutzer {name} existiert auf dem Switch nicht.", name=name))
        plan = _Plan()
        plan.call("DELETE", f"/snmp/community/{_rid(row)}")
        return plan.build()

    def plan_device_aaa(self, session, change) -> ChangePlan:
        if change.tacacs:
            raise InvalidInputError(t("RouterOS hat keinen TACACS+-Client."))
        if change.login_order is not None and ("tacacs" in change.login_order or "local" not in change.login_order):
            raise InvalidInputError(t("RouterOS meldet immer zuerst lokal und danach per RADIUS an."))
        plan = _Plan()
        use_radius = None
        if change.radius is not None:
            self._radius_steps(session, plan, change.radius)
            use_radius = bool(change.radius)
        if change.login_order is not None:
            use_radius = "radius" in change.login_order
        if use_radius is not None:
            aaa = self._singleton(session, "/user/aaa") or {}
            if _bool(aaa.get("use-radius")) is not use_radius:
                plan.call("POST", "/user/aaa/set", {"use-radius": "yes" if use_radius else "no"})
        return plan.build()

    def _radius_steps(self, session, plan: _Plan, servers) -> None:
        rows = self._login_radius(session)
        by_host = {row.get("address"): row for row in rows}
        hosts = [validate_ipv4(server.host) for server in servers]
        if len(set(hosts)) != len(hosts):
            raise InvalidInputError(t("Jeder Server darf nur einmal angegeben werden."))
        for row in rows:
            if row.get("address") in hosts:
                continue
            services = [item for item in _split(row.get("service")) if item != "login"]
            if services:
                plan.call("PATCH", f"/radius/{_rid(row)}", {"service": ",".join(services)})
            else:
                plan.call("DELETE", f"/radius/{_rid(row)}")
        for host, server in zip(hosts, servers, strict=True):
            key = validate_secret(server.key) if server.key is not None else None
            body = {"authentication-port": str(server.auth_port), "accounting-port": str(server.acct_port)}
            row = by_host.get(host)
            if row is None:
                if key is None:
                    raise InvalidInputError(t("Für den neuen Server {host} ist ein Schlüssel erforderlich.", host=host))
                plan.call("PUT", "/radius", {"address": host, "secret": key, "service": "login", **body,
                                             "timeout": "300ms"}, key)
                continue
            if key is not None:
                body["secret"] = key
            changed = {k: v for k, v in body.items()
                       if k == "secret" or str(row.get(k) or "") != v}
            if changed:
                plan.call("PATCH", f"/radius/{_rid(row)}", changed, key or "")

    def _user(self, session, name: str) -> dict | None:
        return next((row for row in self._list(session, "/user") if row.get("name") == name), None)

    def plan_device_user_set(self, session, name: str, password: str | None, privilege: str) -> ChangePlan:
        name = validate_username(name)
        group = {"admin": "full", "read_only": "read"}.get(privilege)
        if group is None:
            raise InvalidInputError(t("Ungültige Berechtigung: {value}", value=privilege))
        password = validate_secret(password) if password is not None else None
        row = self._user(session, name)
        plan = _Plan()
        if row is None:
            if password is None:
                raise InvalidInputError(t("Für einen neuen Benutzer ist ein Passwort erforderlich."))
            plan.call("PUT", "/user", {"name": name, "group": group, "password": password}, password)
        else:
            body = {"group": group} if row.get("group") != group else {}
            if password is not None:
                body["password"] = password
            if body:
                plan.call("PATCH", f"/user/{_rid(row)}", body, password or "")
        return plan.build()

    def plan_device_user_delete(self, session, name: str) -> ChangePlan:
        row = self._user(session, validate_username(name))
        if row is None:
            raise InvalidInputError(t("Benutzer {name} existiert auf dem Switch nicht.", name=name))
        plan = _Plan()
        plan.call("DELETE", f"/user/{_rid(row)}")
        return plan.build()

    def plan_device_ssh(
        self, session, timeout_seconds: int | None, telnet_enabled: bool | None, web_enabled: bool | None,
    ) -> ChangePlan:
        if timeout_seconds is not None:
            raise InvalidInputError(t("RouterOS hat keinen einstellbaren SSH-Timeout."))
        plan = _Plan()
        services = self._services(session)
        if telnet_enabled is not None:
            plan.call("PATCH", "/ip/service/telnet", {"disabled": "false" if telnet_enabled else "true"})
        if web_enabled is not None:
            if "www" in services:
                plan.call("PATCH", "/ip/service/www", {"disabled": "false" if web_enabled else "true"})
            value = "yes" if web_enabled else "no"
            if self._singleton(session, "/ip/service/webserver") is not None:
                plan.call("POST", "/ip/service/webserver/set",
                          {"webfig-secure": value, "graphs-secure": value, "index-secure": value})
            elif not web_enabled:
                plan.warnings.append(t("Diese RouterOS-Version kann WebFig über HTTPS nicht getrennt von der "
                                       "REST-API abschalten; nur HTTP (www) wird deaktiviert."))
        return plan.build()

    # --- Layer 3 ------------------------------------------------------------------

    def _vlan_target_bridge(self, session, vlan: int, plan: _Plan) -> str:
        """Bridge carrying ``vlan``; adds the bridge to the VLAN entry's tagged list if needed."""
        bridges, _ports, entries = self._bridge(session)
        filtering = [name for name, row in bridges.items() if _bool(row.get("vlan-filtering")) is True]
        if len(filtering) != 1:
            raise InvalidInputError(
                t("VLANs können nur angelegt werden, wenn genau eine Bridge mit VLAN-Filterung existiert.")
            )
        bridge = filtering[0]
        rows = []
        for row in entries:
            if row.get("bridge") != bridge or _bool(row.get("dynamic")) is True:
                continue
            ids = set()
            for item in _split(row.get("vlan-ids")):
                first, _, last = item.partition("-")
                if first.isdigit():
                    ids.update(range(int(first), int(last or first) + 1))
            if vlan in ids:
                rows.append((row, ids))
        if not rows:
            raise InvalidInputError(t("VLAN {vlan} existiert auf dem Switch nicht.", vlan=vlan))
        if any(bridge in _split(row.get("tagged")) for row, _ids in rows):
            return bridge
        row, ids = rows[0]
        if len(ids) > 1:
            raise InvalidInputError(t(
                "Der VLAN-Eintrag {ids} umfasst mehrere VLANs; bitte auf dem Gerät aufteilen.", ids=row.get("vlan-ids"),
            ))
        plan.call("PATCH", f"/interface/bridge/vlan/{_rid(row)}",
                  {"tagged": ",".join([*_split(row.get("tagged")), bridge])})
        return bridge

    def plan_svi_set(
        self, session, vlan: int, address: str, prefix_length: int, dhcp_relay: tuple[str, ...],
    ) -> ChangePlan:
        vlan = validate_vlan_id(vlan)
        ip = validate_ipv4(address)
        interface = ipaddress.IPv4Interface(f"{ip}/{int(prefix_length)}") if 1 <= int(prefix_length) <= 32 else None
        if interface is None:
            raise InvalidInputError(t("Ungültiges IPv4-Netz: {value}", value=repr(f"{address}/{prefix_length}")))
        relays = [validate_ipv4(server) for server in dhcp_relay]
        plan = _Plan()
        row = self._vlan_interface(session, vlan)
        if row is None:
            bridge = self._vlan_target_bridge(session, vlan, plan)
            name = f"vlan{vlan}"
            plan.call("PUT", "/interface/vlan", {"name": name, "vlan-id": str(vlan), "interface": bridge})
            current_addresses, current_relays = [], []
        else:
            name = row["name"]
            if _bool(row.get("disabled")) is True:
                plan.call("PATCH", f"/interface/vlan/{_rid(row)}", {"disabled": "no"})
            current_addresses = [item for item in self._list(session, "/ip/address")
                                 if item.get("interface") == name and _bool(item.get("dynamic")) is not True]
            current_relays = [item for item in self._optional(session, "/ip/dhcp-relay") if item.get("interface") == name]
        wanted = f"{ip}/{interface.network.prefixlen}"
        # Add the new address before removing old ones (management access may run over this SVI).
        if not any(item.get("address") == wanted for item in current_addresses):
            plan.call("PUT", "/ip/address", {"address": wanted, "interface": name})
        for item in current_addresses:
            if item.get("address") != wanted:
                plan.call("DELETE", f"/ip/address/{_rid(item)}")
        if not relays:
            for item in current_relays:
                plan.call("DELETE", f"/ip/dhcp-relay/{_rid(item)}")
        else:
            body = {"dhcp-server": ",".join(relays), "local-address": ip, "disabled": "no"}
            if current_relays:
                first = current_relays[0]
                if any(str(first.get(key) or "") != value for key, value in body.items() if key != "disabled") \
                        or _bool(first.get("disabled")) is True:
                    plan.call("PATCH", f"/ip/dhcp-relay/{_rid(first)}", body)
                for item in current_relays[1:]:
                    plan.call("DELETE", f"/ip/dhcp-relay/{_rid(item)}")
            else:
                plan.call("PUT", "/ip/dhcp-relay", {"name": f"relay-{name}", "interface": name, **body})
        return plan.build()

    def plan_svi_delete(self, session, vlan: int) -> ChangePlan:
        row = self._vlan_interface(session, validate_vlan_id(vlan))
        if row is None:
            raise InvalidInputError(t("Das VLAN-Interface {vlan} existiert auf dem Switch nicht.", vlan=vlan))
        plan = _Plan()
        for item in self._optional(session, "/ip/dhcp-relay"):
            if item.get("interface") == row["name"]:
                plan.call("DELETE", f"/ip/dhcp-relay/{_rid(item)}")
        for item in self._list(session, "/ip/address"):
            if item.get("interface") == row["name"] and _bool(item.get("dynamic")) is not True:
                plan.call("DELETE", f"/ip/address/{_rid(item)}")
        plan.call("DELETE", f"/interface/vlan/{_rid(row)}")
        return plan.build()

    def plan_gateway(self, session, gateway: str) -> ChangePlan:
        gateway = validate_ipv4(gateway)
        defaults = [row for row in self._static_routes(session) if row.get("dst-address") == "0.0.0.0/0"]
        plan = _Plan()
        if not defaults:
            plan.call("PUT", "/ip/route", {"dst-address": "0.0.0.0/0", "gateway": gateway})
        else:
            if _gateway(defaults[0].get("gateway")) != gateway:
                plan.call("PATCH", f"/ip/route/{_rid(defaults[0])}", {"gateway": gateway})
            for row in defaults[1:]:
                plan.call("DELETE", f"/ip/route/{_rid(row)}")
        return plan.build()

    def _route(self, session, network, next_hop: str) -> dict | None:
        return next((row for row in self._static_routes(session)
                     if row.get("dst-address") == str(network) and _gateway(row.get("gateway")) == next_hop), None)

    def plan_route_add(
        self, session, prefix: str, prefix_length: int, next_hop: str, distance: int | None,
    ) -> ChangePlan:
        network = validate_ipv4_prefix(prefix, prefix_length)
        next_hop = validate_ipv4(next_hop)
        if self._route(session, network, next_hop) is not None:
            raise InvalidInputError(t("Die Route existiert bereits."))
        plan = _Plan()
        plan.call("PUT", "/ip/route", {"dst-address": str(network), "gateway": next_hop,
                                       "distance": str(distance or 1)})
        return plan.build()

    def plan_route_delete(self, session, prefix: str, prefix_length: int, next_hop: str) -> ChangePlan:
        row = self._route(session, validate_ipv4_prefix(prefix, prefix_length), validate_ipv4(next_hop))
        if row is None:
            raise InvalidInputError(t("Die Route existiert auf dem Switch nicht."))
        plan = _Plan()
        plan.call("DELETE", f"/ip/route/{_rid(row)}")
        return plan.build()

    # --- ACLs ------------------------------------------------------------------

    def _acl_state(self, session) -> dict[str, dict]:
        """name -> {type, header, templates: {seq: row}, switch: {seq|"end": row}, bound: {(iface, dir): {seq: row}}}."""
        def read():
            acls: dict[str, dict] = {}

            def acl(name):
                return acls.setdefault(name, {"type": None, "header": None, "templates": {}, "switch": {},
                                              "bound": {}})

            for row in self._list(session, "/ip/firewall/filter"):
                comment = str(row.get("comment") or "")
                if match := _ACL_HEADER_RE.fullmatch(comment):
                    acl(match.group(1)).update(type=match.group(2), header=row)
                elif match := _ACL_TEMPLATE_RE.fullmatch(comment):
                    acl(match.group(1))["templates"][int(match.group(2))] = row
                elif match := _ACL_FILTER_BIND_RE.fullmatch(comment):
                    key = (match.group(4), match.group(3))
                    seq = match.group(2)
                    acl(match.group(1))["bound"].setdefault(key, {})[int(seq) if seq.isdigit() else "end"] = row
            for row in self._optional(session, "/interface/ethernet/switch/rule"):
                if match := _ACL_SWITCH_RE.fullmatch(str(row.get("comment") or "")):
                    seq = match.group(2)
                    acl(match.group(1))["switch"][int(seq) if seq.isdigit() else "end"] = row
            return acls

        return self._cached(session, "acl_state", read)

    def _acl(self, session, name: str) -> dict:
        state = self._acl_state(session).get(validate_acl_name(name))
        if state is None or (state["header"] is None and not state["templates"]):
            raise InvalidInputError(t("ACL {name} existiert auf dem Switch nicht.", name=name))
        return state

    @staticmethod
    def _switch_ports(state: dict) -> list[str]:
        ports: list[str] = []
        for row in state["switch"].values():
            for port in _split(row.get("ports")):
                if port not in ports:
                    ports.append(port)
        return ports

    def _vlan_name_map(self, session) -> dict[str, str]:
        return {row["name"]: f"vlan{row['vlan-id']}" for row in self._vlan_interfaces(session)
                if str(row.get("vlan-id") or "").isdigit()}

    def _read_acls(self, session) -> list[dict]:
        names = self._vlan_name_map(session)
        result = []
        for name, state in sorted(self._acl_state(session).items()):
            if state["header"] is None and not state["templates"]:
                continue
            bindings = [{"interface": port, "direction": "in"} for port in self._switch_ports(state)]
            bindings += [{"interface": names.get(iface, iface), "direction": direction}
                         for iface, direction in state["bound"]]
            result.append({
                "name": name,
                "type": state["type"] or "extended",
                "entries": [_entry_from_filter(seq, row) for seq, row in sorted(state["templates"].items())],
                "bindings": bindings,
            })
        return result

    def plan_acl_create(self, session, name: str, acl_type: str) -> ChangePlan:
        name = validate_acl_name(name)
        if acl_type not in {"standard", "extended"}:
            raise InvalidInputError(t("Ungültiger ACL-Typ: {value}", value=acl_type))
        state = self._acl_state(session).get(name)
        if state is not None and (state["header"] is not None or state["templates"]):
            raise InvalidInputError(t("ACL {name} existiert bereits.", name=name))
        plan = _Plan()
        plan.call("PUT", "/ip/firewall/filter", {"chain": "forward", "action": "passthrough", "disabled": "yes",
                                                 "comment": f"swm:{name}:0:{acl_type}"})
        return plan.build()

    def _binding_names(self, session, state: dict) -> list[str]:
        names = self._vlan_name_map(session)
        return [*self._switch_ports(state), *(f"{names.get(iface, iface)} {direction}"
                                              for iface, direction in state["bound"])]

    def plan_acl_delete(self, session, name: str) -> ChangePlan:
        state = self._acl(session, name)
        bound = self._binding_names(session, state)
        if bound:
            raise InvalidInputError(t("Die ACL ist noch an {interfaces} gebunden.", interfaces=", ".join(bound)))
        plan = _Plan()
        for _seq, row in sorted(state["templates"].items()):
            plan.call("DELETE", f"/ip/firewall/filter/{_rid(row)}")
        if state["header"] is not None:
            plan.call("DELETE", f"/ip/firewall/filter/{_rid(state['header'])}")
        return plan.build()

    @staticmethod
    def _next_id(rules: dict, seq: int) -> str | None:
        """Id of the rule after ``seq`` (next higher sequence, else the final drop rule)."""
        later = sorted(key for key in rules if key != "end" and key > seq)
        row = rules[later[0]] if later else rules.get("end")
        return _rid(row) if row is not None else None

    def _switch_name(self, session) -> str:
        chip = next((row.get("name") for row in self._switch_chips(session) if row.get("name")), None)
        if not chip:
            raise SwitchConnectionError(t("Der Switch-Chip konnte nicht ermittelt werden."))
        return chip

    def plan_acl_entry_add(self, session, name: str, entry: AclEntry) -> ChangePlan:
        state = self._acl(session, name)
        data = self._validated_entry(state, entry)
        if data["seq"] in state["templates"]:
            raise InvalidInputError(t("Der Eintrag {seq} existiert bereits.", seq=data["seq"]))
        if state["switch"] and data["dst_port_op"] == "range":
            raise InvalidInputError(t("RouterOS-Switch-Regeln erlauben keine Portbereiche."))
        plan = _Plan()
        plan.call("PUT", "/ip/firewall/filter",
                  {**_filter_body(data), "disabled": "yes", "comment": f"swm:{name}:{data['seq']}"})
        ports = self._switch_ports(state)
        if ports:
            body = {"switch": self._switch_name(session), "ports": ",".join(ports), **_switch_body(data),
                    "comment": f"swm:{name}:{data['seq']}"}
            if (before := self._next_id(state["switch"], data["seq"])) is not None:
                body["place-before"] = before
            plan.call("PUT", "/interface/ethernet/switch/rule", body)
            plan.warnings.append(t("Änderungen an Switch-Regeln deaktivieren alle Switch-Regeln kurzzeitig."))
        for (iface, direction), rules in state["bound"].items():
            body = {**_filter_body(data), f"{direction}-interface": iface,
                    "comment": f"swm:{name}:{data['seq']}:{direction}:{iface}"}
            if (before := self._next_id(rules, data["seq"])) is not None:
                body["place-before"] = before
            plan.call("PUT", "/ip/firewall/filter", body)
        return plan.build()

    @staticmethod
    def _validated_entry(state: dict, entry: AclEntry) -> dict:
        data = _acl_entry_dict(entry)
        if not 1 <= data["seq"] <= 2147483647:
            raise InvalidInputError(t("Ungültige Sequenznummer: {value}", value=data["seq"]))
        if data["action"] not in {"permit", "deny"} or data["protocol"] not in {"ip", "tcp", "udp", "icmp"}:
            raise InvalidInputError(t("Ungültiger ACL-Eintrag."))
        network = validate_ipv4_prefix(data["src"], data["src_len"])
        data["src"], data["src_len"] = str(network.network_address), network.prefixlen
        if state["type"] == "standard" and (data["protocol"] != "ip" or data["dst"] is not None
                                            or data["dst_port_op"] is not None):
            raise InvalidInputError(t("Eine Standard-ACL prüft nur die Quelladresse."))
        if data["dst"] is not None:
            network = validate_ipv4_prefix(data["dst"], data["dst_len"] or 0)
            data["dst"], data["dst_len"] = str(network.network_address), network.prefixlen
        if data["dst_port_op"] is not None:
            if data["protocol"] not in {"tcp", "udp"}:
                raise InvalidInputError(t("Zielports gibt es nur für TCP und UDP."))
            if data["dst_port"] is None or not 1 <= data["dst_port"] <= 65535:
                raise InvalidInputError(t("Es fehlt der Zielport."))
            if data["dst_port_op"] == "range" and (data["dst_port_end"] is None
                                                   or not data["dst_port"] <= data["dst_port_end"] <= 65535):
                raise InvalidInputError(t("Das Ende des Portbereichs muss größer oder gleich dem Anfang sein."))
        return data

    def plan_acl_entry_delete(self, session, name: str, seq: int) -> ChangePlan:
        state = self._acl(session, name)
        if seq not in state["templates"]:
            raise InvalidInputError(t("Der Eintrag {seq} existiert nicht.", seq=seq))
        plan = _Plan()
        plan.call("DELETE", f"/ip/firewall/filter/{_rid(state['templates'][seq])}")
        if seq in state["switch"]:
            plan.call("DELETE", f"/interface/ethernet/switch/rule/{_rid(state['switch'][seq])}")
        for rules in state["bound"].values():
            if seq in rules:
                plan.call("DELETE", f"/ip/firewall/filter/{_rid(rules[seq])}")
        return plan.build()

    def _acl_target(self, session, interface: str, direction: str) -> tuple[str, str, str]:
        """-> (kind "port"|"vlan", device interface name, displayed name)."""
        if direction not in {"in", "out"}:
            raise InvalidInputError(t("Ungültige Richtung: {value}", value=direction))
        match = _VLAN_TARGET_RE.fullmatch((interface or "").strip())
        if match:
            vlan = validate_vlan_id(int(match.group(1)))
            row = self._vlan_interface(session, vlan)
            if row is None:
                raise InvalidInputError(t("Das VLAN-Interface {vlan} existiert auf dem Switch nicht.", vlan=vlan))
            return "vlan", row["name"], f"vlan{vlan}"
        port = self.validate_interface(interface)
        if direction == "out":
            raise InvalidInputError(t("RouterOS-Switch-Regeln filtern nur eingehenden Verkehr; an Ports ist nur "
                                      "„in“ möglich."))
        if port not in {row["name"] for row in self._ethernet(session)}:
            raise InvalidInputError(t("Interface {interface} existiert auf dem Switch nicht.", interface=port))
        return "port", port, port

    def plan_acl_bind(self, session, name: str, interface: str, direction: str) -> ChangePlan:
        state = self._acl(session, name)
        kind, iface, shown = self._acl_target(session, interface, direction)
        for other, other_state in self._acl_state(session).items():
            if (kind == "port" and iface in self._switch_ports(other_state)) or \
                    (kind == "vlan" and (iface, direction) in other_state["bound"]):
                if other == name:
                    raise InvalidInputError(t("Die ACL {name} ist an {interface} bereits gebunden.",
                                              name=name, interface=shown))
                raise InvalidInputError(t("An {interface} ist bereits die ACL {other} gebunden.",
                                          interface=shown, other=other))
        entries = [_entry_from_filter(seq, row) for seq, row in sorted(state["templates"].items())]
        if not entries:
            raise InvalidInputError(t("Die ACL {name} hat keine Einträge.", name=name))
        plan = _Plan()
        if kind == "port":
            if any(entry["dst_port_op"] == "range" for entry in entries):
                raise InvalidInputError(t("RouterOS-Switch-Regeln erlauben keine Portbereiche."))
            plan.warnings.append(t("Änderungen an Switch-Regeln deaktivieren alle Switch-Regeln kurzzeitig."))
            ports = self._switch_ports(state)
            if ports:
                for _seq, row in sorted(state["switch"].items(), key=lambda item: (item[0] == "end", str(item[0]))):
                    plan.call("PATCH", f"/interface/ethernet/switch/rule/{_rid(row)}",
                              {"ports": ",".join([*_split(row.get("ports")), iface])})
                return plan.build()
            switch = self._switch_name(session)
            for entry in entries:
                plan.call("PUT", "/interface/ethernet/switch/rule", {
                    "switch": switch, "ports": iface, **_switch_body(entry), "comment": f"swm:{name}:{entry['seq']}",
                })
            plan.call("PUT", "/interface/ethernet/switch/rule",
                      {"switch": switch, "ports": iface, "new-dst-ports": "", "comment": f"swm:{name}:end"})
            return plan.build()
        if any(_bool(row.get("l3-hw-offloading")) is True for row in self._switch_chips(session)):
            plan.warnings.append(t("Bei aktivem L3-Hardware-Offloading umgeht gerouteter Verkehr die Firewall-Regeln."))
        for entry in entries:
            plan.call("PUT", "/ip/firewall/filter", {
                **_filter_body(entry), f"{direction}-interface": iface,
                "comment": f"swm:{name}:{entry['seq']}:{direction}:{iface}",
            })
        plan.call("PUT", "/ip/firewall/filter", {"chain": "forward", "action": "drop", f"{direction}-interface": iface,
                                                 "comment": f"swm:{name}:end:{direction}:{iface}"})
        return plan.build()

    def plan_acl_unbind(self, session, name: str, interface: str, direction: str) -> ChangePlan:
        state = self._acl(session, name)
        kind, iface, shown = self._acl_target(session, interface, direction)
        plan = _Plan()
        if kind == "port":
            for _seq, row in state["switch"].items():
                ports = _split(row.get("ports"))
                if iface not in ports:
                    continue
                rest = [port for port in ports if port != iface]
                path = f"/interface/ethernet/switch/rule/{_rid(row)}"
                if rest:
                    plan.call("PATCH", path, {"ports": ",".join(rest)})
                else:
                    plan.call("DELETE", path)
            if plan.steps:
                plan.warnings.append(t("Änderungen an Switch-Regeln deaktivieren alle Switch-Regeln kurzzeitig."))
        else:
            for _seq, row in state["bound"].get((iface, direction), {}).items():
                plan.call("DELETE", f"/ip/firewall/filter/{_rid(row)}")
        if not plan.steps:
            raise InvalidInputError(t("Die ACL {name} ist an {interface} nicht gebunden.", name=name, interface=shown))
        return plan.build()

    # --- QoS -------------------------------------------------------------------

    def plan_qos_port(self, session, interface: str, trust: str | None, voice_preset: bool | None) -> ChangePlan:
        interface = self.validate_interface(interface)
        if voice_preset is not None:
            raise UnsupportedFeatureError("qos_voice", self.features["qos_voice"].reason)
        if not self._qos_offloading(session):
            raise UnsupportedFeatureError("qos", QOS_OFFLOAD_REASON)
        plan = _Plan()
        if trust is not None:
            if trust not in _TRUST_BODIES:
                raise InvalidInputError(t("Ungültiger Trust-Modus: {value}", value=trust))
            ports = {row.get("name") for row in self._list(session, "/interface/ethernet/switch/qos/port")}
            if interface not in ports:
                raise InvalidInputError(t("Interface {interface} existiert auf dem Switch nicht.", interface=interface))
            plan.call("PATCH", f"/interface/ethernet/switch/qos/port/{interface}", dict(_TRUST_BODIES[trust]))
        return plan.build()

    # --- Firmware ------------------------------------------------------------------

    def read_firmware(self, session) -> dict:
        resource = self._resource(session)
        packages = self._optional(session, "/system/package")
        files = [row for row in self._optional(session, "/file") if row.get("name")]
        routeros = next((row for row in packages if row.get("name") == "routeros"), None)
        version = (routeros or {}).get("version") or str(resource.get("version") or "").split(" ")[0] or None
        pending = [row["name"] for row in files if str(row["name"]).endswith(".npk")]
        return {
            "running_version": version,
            "boot_images": [f"{row['name']} {row.get('version') or ''}".strip() for row in packages if row.get("name")],
            "next_boot": pending[0] if pending else None,
            "install_mode": None,
            "free_bytes": _int(resource.get("free-hdd-space")),
            "files": [str(row["name"]) for row in files],
        }

    @staticmethod
    def _require_npk(image: FirmwareImage) -> None:
        if not image.filename.endswith(".npk"):
            raise InvalidInputError(t("RouterOS installiert nur .npk-Pakete."))

    def plan_firmware_stage(
        self, session, image: FirmwareImage, transfer: TransferLocation, firmware: dict,
    ) -> ChangePlan:
        """Background ``/tool/fetch`` (``POST /execute``) of the package, then wait until it is complete."""
        self._require_npk(image)
        if transfer.method != "http":
            raise InvalidInputError(t("RouterOS lädt Firmware nur per HTTP(S)."))
        name = image.filename
        plan = _Plan()
        for row in self._optional(session, f"/file?name={name}"):
            if row.get("name") == name:
                plan.call("DELETE", f"/file/{_rid(row)}")

        def script(url: str) -> str:
            return f'/tool/fetch url="{_script_text(url)}" dst-path="{_script_text(name)}" check-certificate=no'

        shown = rest_text(RestCall("POST", "/execute", {"script": script(transfer.display_url)}))
        plan.call("POST", "/execute", {"script": script(transfer.url)}, *_transfer_secrets(transfer), shown=shown)
        plan.wait(RestWaitForFile(name=name, size=image.size))
        plan.warnings.append(t("RouterOS hat keine Prüfsummenfunktion; die Prüfsumme wird nur auf dem Server "
                               "geprüft, die Paketsignatur prüft RouterOS bei der Installation."))
        return plan.build()

    def plan_firmware_activate(self, session, image: FirmwareImage, firmware: dict, reload_now: bool) -> ChangePlan:
        """RouterOS installs a package in the file root at the next reboot; a downgrade needs ``downgrade``."""
        self._require_npk(image)
        if image.filename not in (firmware.get("files") or ()):
            raise InvalidInputError(t("Das Image {file} liegt nicht im Flash des Switches; bitte zuerst übertragen.",
                                      file=image.filename))
        target = _NPK_VERSION_RE.search(image.filename)
        running = re.match(r"\d+(?:\.\d+)+", str(firmware.get("running_version") or ""))
        downgrade = bool(target and running) and (
            tuple(int(part) for part in target.group(1).split("."))
            < tuple(int(part) for part in running.group(0).split("."))
        )
        if downgrade:
            if not reload_now:
                raise InvalidInputError(t("Ein Downgrade startet den Switch sofort neu; bitte „jetzt“ wählen."))
            plan = _Plan()
            plan.steps.append(RestCall("POST", "/system/package/downgrade", {}, expect_disconnect=True))
            plan.lines.append(rest_text(plan.steps[-1]))
            return plan.build(reloads=True)
        if reload_now:
            return combine_plans(self.plan_reload(session))
        return _Plan().build(require=False, message=t("RouterOS installiert {file} beim nächsten Neustart.",
                                                      file=image.filename))

    # --- Polling step (called by ``MikrotikDriver.execute_plan``) ----------------------------

    def device_step_line(self, step) -> str:
        if isinstance(step, RestWaitForFile):
            return wait_text(step)
        raise TypeError(f"Unsupported step for the RouterOS driver: {type(step).__name__}")

    def run_device_step(self, session, step) -> str | None:
        """Run a non-REST step; returns a German failure message or None."""
        if not isinstance(step, RestWaitForFile):
            raise TypeError(f"Unsupported step for the RouterOS driver: {type(step).__name__}")
        started = last_change = time.monotonic()
        last_size = None
        while True:
            rows = self._optional(session, f"/file?name={step.name}")
            size = next((_int(row.get("size")) for row in rows if row.get("name") == step.name), None)
            if size == step.size:
                return None
            now = time.monotonic()
            if size is not None and size > step.size:
                return t("Die Datei {file} auf dem Switch ist größer als das Image.", file=step.name)
            if size != last_size:
                last_size, last_change = size, now
            if now - last_change >= step.stall_seconds or now - started >= step.timeout:
                return t("Die Übertragung von {file} wurde nicht abgeschlossen ({size} von {total} Bytes).",
                         file=step.name, size=size or 0, total=step.size)
            time.sleep(step.interval)

    # --- Diagnostics ------------------------------------------------------------------

    def read_counters(self, session, interface: str | None) -> list[dict]:
        names = [row["name"] for row in self._ethernet(session)]
        if interface is not None:
            interface = self.validate_interface(interface)
            if interface not in names:
                raise InvalidInputError(t("Interface {interface} existiert auf dem Switch nicht.", interface=interface))
            names = [interface]
        generic = {row.get("name"): row for row in self._list(session, "/interface")}
        stats = self.request(session, "POST", "/interface/ethernet/print", {"stats": ""}, missing_ok=True)
        stats = {row.get("name"): row for row in stats or () if isinstance(row, dict)}
        counters = []
        for name in names:
            row = generic.get(name, {})
            extra = stats.get(name, {})
            counters.append({
                "interface": name,
                "in_octets": _int(row.get("rx-byte")),
                "out_octets": _int(row.get("tx-byte")),
                "in_errors": _int(row.get("rx-error")),
                "out_errors": _int(row.get("tx-error")),
                "crc": _int(extra.get("rx-fcs-error")),
                "drops_in": _int(row.get("rx-drop")),
                "drops_out": _int(row.get("tx-drop")),
                "collisions": _int(extra.get("tx-collision")),
            })
        return counters

    def plan_counters_clear(self, session, interface: str) -> ChangePlan:
        interface = self.validate_interface(interface)
        if interface not in {row["name"] for row in self._ethernet(session)}:
            raise InvalidInputError(t("Interface {interface} existiert auf dem Switch nicht.", interface=interface))
        plan = _Plan()
        plan.call("POST", "/interface/ethernet/reset-counters", {"numbers": interface})
        return plan.build()

    def read_transceivers(self, session) -> list[dict]:
        names = [row["name"] for row in self._ethernet(session) if re.match(r"(?:sfp|qsfp|combo)", row["name"])]
        if not names:
            return []
        data = self.request(session, "POST", "/interface/ethernet/monitor", {"numbers": ",".join(names), "once": ""})
        result = []
        for row in data if isinstance(data, list) else ():
            if not isinstance(row, dict) or _bool(row.get("sfp-module-present")) is not True:
                continue
            result.append({
                "interface": row.get("name"),
                "type": row.get("sfp-type") or None,
                "temperature_c": _number(row.get("sfp-temperature")),
                "voltage_v": _number(row.get("sfp-supply-voltage")),
                "tx_power_dbm": _number(row.get("sfp-tx-power")),
                "rx_power_dbm": _number(row.get("sfp-rx-power")),
                "alarm": None,
            })
        return result

    def read_log(self, session, lines: int = 500) -> list[str]:
        rows = self._list(session, "/log")
        text = [" ".join(str(row.get(key) or "") for key in ("time", "topics", "message")).strip() for row in rows]
        return text[-lines:] if lines > 0 else []

    def read_environment(self, session) -> dict:
        data = self.request(session, "GET", "/system/health")
        if isinstance(data, dict):  # older format: one object with named values
            data = [{"name": key, "value": value, "type": ""} for key, value in data.items()]
        temperatures, fans, supplies = [], [], []
        for row in data if isinstance(data, list) else ():
            if not isinstance(row, dict) or not row.get("name"):
                continue
            name = str(row["name"])
            value = row.get("value")
            if row.get("type") == "C" or "temperature" in name:
                temperatures.append({"sensor": name, "celsius": _number(value), "status": None})
            elif name.startswith("fan") and name.endswith("-state"):
                fans.append({"name": name[: -len("-state")], "status": str(value)})
            elif name.startswith("fan"):
                speed = _int(value)
                fans.append({"name": name.removesuffix("-speed"),
                             "status": None if speed is None else ("ok" if speed > 0 else "stopped")})
            elif name.startswith("psu") and name.endswith("-state"):
                supplies.append({"name": name[: -len("-state")], "status": str(value), "watts": None})
        return {"temperatures": temperatures, "fans": fans, "power_supplies": supplies}
