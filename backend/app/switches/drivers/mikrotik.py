"""MikroTik RouterOS v7 driver over the REST API (``https://{host}:{port}/rest``).

All REST values are strings. Ports are mapped from the bridge configuration:
access = ``frame-types=admit-only-untagged-and-priority-tagged`` with ``pvid``;
trunk = ``admit-only-vlan-tagged`` (no native VLAN) or ``admit-all`` with tagged
memberships (native = ``pvid``); allowed VLANs = entries whose ``tagged`` list
contains the port. VLANs are only created through the VLAN tab (plan_vlan_create); port writes never create VLANs:
a missing single-VLAN entry is only added (PUT) when the VLAN already exists in another entry of the same bridge.
The VLAN name is the ``comment`` of the VLAN's static single-VLAN entry.
RouterOS applies every change persistently, so there is no save step.
"""

import ipaddress
import json
import logging
import re
import ssl
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx

from ...i18n import t
from .. import transport
from .. import vlans as vlanlib
from ..clients import format_mac_address, normalize_mac_address
from ..errors import InvalidInputError, SwitchConnectionError, append_warning
from ..features import VTP_CISCO_ONLY_REASON, supported, unsupported
from ..validation import format_vlan_list, sanitize_description, validate_choice, validate_vlan_id
from .base import (
    PortChange,
    SwitchDriver,
    WriteResult,
    client_snapshot,
    empty_poe_detail,
    empty_switchport_detail,
    neighbor_row,
    write_result,
)
from .mikrotik_device import MikrotikDeviceMixin
from .mikrotik_models import MIKROTIK_CATALOG
from .plans import (
    REDACTED,
    ChangePlan,
    Dot1xSettings,
    Pause,
    RestCall,
    SecurityChange,
    SecurityGlobalChange,
    StormControlSettings,
    redact,
)

logger = logging.getLogger("switchsteward.switches.mikrotik")

SPEED_OPTIONS = ("auto", "10", "100", "1000")
DUPLEX_OPTIONS = ("auto", "half", "full")
POE_MODE_OPTIONS = ("auto", "never")
MIN_SPEED_VERSION = (7, 12)
_DESCRIPTION_MAX_LENGTH = 200

ACCESS_FRAMES = "admit-only-untagged-and-priority-tagged"
TAGGED_FRAMES = "admit-only-vlan-tagged"
ALL_FRAMES = "admit-all"

SAVE_CONFIG_REASON = "RouterOS übernimmt Änderungen sofort dauerhaft."
POE_BUDGET_REASON = "RouterOS meldet kein PoE-Gesamtbudget."
POE_LIMIT_REASON = "PoE-Leistungsprofile werden für RouterOS nicht unterstützt."
VOICE_WARNING = (
    "Telefone erfahren das Voice-VLAN nur per LLDP-MED; diese globale Einstellung wird nicht geändert."
)
STORM_RATE_MISMATCH = "RouterOS erlaubt nur einen gemeinsamen Grenzwert pro Port."
SNOOPING_VLANS_REASON = "RouterOS wendet DHCP-Snooping auf die ganze Bridge an; die VLAN-Liste muss leer sein."
LOOP_GUARD_REASON = "RouterOS bietet Loop Guard nicht pro Port an."
STORM_SHUTDOWN_REASON = "RouterOS kann bei Stürmen nur verwerfen, nicht abschalten."
PVST_REASON = "RouterOS kennt keine Priorität pro VLAN; bitte MST-Instanzen verwenden."
STP_BRIDGE_REASON = "Spanning Tree ist nur mit genau einer Bridge mit VLAN-Filterung einstellbar."
NOT_BRIDGE_PORT_REASON = "Interface {interface} ist kein aktiver Bridge-Port."
MSTI_MISSING_REASON = "MST-Instanz {instance} existiert auf dem Switch nicht."
PORT_DISABLED_REASON = "Port {interface} ist ausgeschaltet; ein Neustart des Ports ist nicht möglich."
NO_POE_REASON = "Interface {interface} unterstützt kein PoE."
# Reboot steps: answered with a dropped connection.
REBOOT = RestCall("POST", "/system/reboot", {}, expect_disconnect=True)
# Volatile export lines: the timestamp comment at the top of ``/export``.
VOLATILE_EXPORT_PATTERNS = (r"^#.* by RouterOS ",)
BOND_SPEED_REASON = "Speed/Duplex werden an den Mitgliedern eines LAG eingestellt."
NO_BRIDGE_REASON = "Der Port ist keiner Bridge zugeordnet."
NO_VLAN_FILTERING_REASON = "Auf der Bridge ist die VLAN-Filterung (vlan-filtering) nicht aktiviert."
OLD_VERSION_REASON = "Speed/Duplex-Einstellungen erfordern RouterOS 7.12 oder neuer."
UNKNOWN_VERSION_REASON = "Die RouterOS-Version ist unbekannt; Speed/Duplex bleiben gesperrt."
NO_POE_PORT_REASON = "Dieses Interface stellt kein PoE bereit."
# Reasons for unsupported features.
VLAN_VOICE_REASON = "RouterOS kennt kein Voice-VLAN-Objekt."
CONFIG_COMPARE_REASON = "RouterOS hat keine Startup-Konfiguration."
CONFIG_RESTORE_REASON = (
    "Ein RouterOS-Export enthält keine Zertifikatsschlüssel; nach dem Zurücksetzen wäre die REST-API nicht erreichbar."
)
ROLLBACK_REASON = "Die Plattform hat kein zeitgesteuertes Rollback."
PORT_SECURITY_REASON = "CRS3xx kennt keine MAC-Begrenzung pro Port."
DOT1X_OPTIONS_REASON = "RouterOS kennt keine 802.1X-Host-Modi und Ersatz-VLANs."
ARP_INSPECTION_REASON = "RouterOS kennt keine Dynamic ARP Inspection."
IP_SOURCE_GUARD_REASON = "RouterOS kennt kein IP Source Guard."
QOS_VOICE_REASON = "RouterOS bietet keine Voice-QoS-Vorlage pro Port."
CABLE_TEST_REASON = "CRS3xx unterstützt keinen Kabeltest."

# Body keys whose values never appear in previews or logs.
SECRET_KEYS = frozenset({"password", "secret", "authentication-password", "encryption-password"})

FEATURES = {
    "device_summary": supported(),
    "poe_budget": unsupported(POE_BUDGET_REASON),
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
    "vlan_voice": unsupported(VLAN_VOICE_REASON),
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
    "save_config": unsupported(SAVE_CONFIG_REASON),
    "config_backup": supported(),
    "config_compare": unsupported(CONFIG_COMPARE_REASON),
    "config_restore": unsupported(CONFIG_RESTORE_REASON),
    "config_rollback": unsupported(ROLLBACK_REASON),
    "management_path": supported(),
    "port_security": unsupported(PORT_SECURITY_REASON),
    "port_security_sticky": unsupported(PORT_SECURITY_REASON),
    "dot1x": supported(("dot1x", "mab")),
    "dot1x_host_mode": unsupported(DOT1X_OPTIONS_REASON),
    "dot1x_fallback_vlans": unsupported(DOT1X_OPTIONS_REASON),
    "stp_guard": supported(("bpdu_guard", "root_guard")),
    "storm_control": supported(("broadcast", "multicast", "unknown_unicast")),
    "storm_control_action": supported(("drop",)),
    "dhcp_snooping": supported(),
    "arp_inspection": unsupported(ARP_INSPECTION_REASON),
    "ip_source_guard": unsupported(IP_SOURCE_GUARD_REASON),
    "lag": supported(("static", "lacp_active")),
    "stp": supported(("stp", "rstp", "mstp")),
    "stp_mst": supported(),
    "device_identity": supported(),
    "device_services": supported(),
    "device_snmp": supported(),
    "device_aaa": supported(("radius",)),
    "device_users": supported(),
    "device_ssh": supported(("telnet", "web")),
    "device_l3": supported(("svi", "gateway", "dhcp_relay", "static_routes")),
    "acl": supported(("port_in", "vlan_in", "vlan_out")),
    # Both need qos-hw-offloading; checked per device in mikrotik_device (plan_qos_port, read_device_config).
    "qos": supported(("none", "cos", "dscp")),
    "qos_voice": unsupported(QOS_VOICE_REASON),
    "firmware": supported(),
    "diag_counters": supported(),
    "diag_transceivers": supported(),
    "device_log": supported(),
    "environment": supported(),
    "cable_test": unsupported(CABLE_TEST_REASON),
    "reload": supported(),
}
VLAN_FEATURES = ("port_mode", "access_vlan", "native_vlan", "trunk_allowed_vlans", "voice_vlan", "edge_port")
POE_PORT_FEATURES = ("poe", "poe_mode", "poe_cycle")
MAX_LAG_ID = 64
_BOND_RE = re.compile(r"bond([1-9]\d{0,2})")
_LAG_MODES = {"static": "balance-xor", "lacp_active": "802.3ad", "lacp_passive": "802.3ad"}
_STP_MODES = ("stp", "rstp", "mstp")

_SPEED_VALUES = {
    ("10", "half"): "10M-baseT-half",
    ("10", "full"): "10M-baseT-full",
    ("100", "half"): "100M-baseT-half",
    ("100", "full"): "100M-baseT-full",
    ("1000", "full"): "1G-baseT-full",
}
_SPEED_NAMES = {"10M": "10", "100M": "100", "1G": "1000"}
_INTERFACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
# Names of non-Ethernet RouterOS interface types (bridge/VLAN/tunnel/...) are not editable.
_NON_ETHERNET_RE = re.compile(
    r"(?:bridge|vlan|bond|lo|wg|eoip|gre|ipip|l2tp|pppoe|ppp|sstp|ovpn|pptp|veth|wlan|wifi|vrrp|vxlan)"
    r"(?:\d|[-_.]|$)",
    re.IGNORECASE,
)
_ROW_ID_RE = re.compile(r"\*[0-9A-Fa-f]{1,16}")
_VERSION_RE = re.compile(r"^\s*(\d+)\.(\d+)")


@dataclass
class RestSession:
    client: httpx.Client
    switch: dict
    warnings: list[str] = field(default_factory=list)
    cache: dict[str, Any] = field(default_factory=dict)


# --- Value helpers ---------------------------------------------------------------------


def as_bool(value) -> bool | None:
    text = str(value).strip().lower() if value is not None else ""
    if text in {"true", "yes"}:
        return True
    if text in {"false", "no"}:
        return False
    return None


def split_list(value) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def parse_vlan_ids(value) -> set[int] | None:
    """``10,20-30`` -> {10, 20, ..., 30}; ``None`` for unreadable lists."""
    ids: set[int] = set()
    items = split_list(value)
    if not items:
        return None
    for item in items:
        match = re.fullmatch(r"(\d{1,4})(?:-(\d{1,4}))?", item)
        if not match:
            return None
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if not 1 <= start <= end <= 4094:
            return None
        ids.update(range(start, end + 1))
    return ids


def parse_version(value) -> tuple[int, int] | None:
    match = _VERSION_RE.match(str(value or ""))
    return (int(match.group(1)), int(match.group(2))) if match else None


def parse_watts(value) -> float | None:
    match = re.match(r"\s*(\d+(?:\.\d+)?)", str(value or ""))
    return float(match.group(1)) if match else None


def parse_speed(row: dict) -> tuple[str | None, str | None]:
    """Configured speed/duplex of an ``/interface/ethernet`` row."""
    if as_bool(row.get("auto-negotiation")) is True:
        return "auto", "auto"
    value = row.get("speed")
    if not value:
        return None, None
    match = re.fullmatch(r"(\d+[MG])-base\w+-(half|full)", str(value))
    if match and match.group(1) in _SPEED_NAMES:
        return _SPEED_NAMES[match.group(1)], match.group(2)
    return str(value), None


def _row_id(row: dict) -> str:
    row_id = str(row.get(".id") or "")
    if not _ROW_ID_RE.fullmatch(row_id):
        raise SwitchConnectionError(t("Der Switch hat einen Eintrag ohne gültige .id geliefert."))
    return row_id


def _error_detail(content: bytes) -> str | None:
    try:
        data = json.loads(content)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    detail = data.get("detail") or data.get("message")
    return str(detail).strip()[:500] if detail else None


def _ipv4(text: str | None) -> str | None:
    try:
        address = ipaddress.IPv4Address((text or "").strip())
    except ipaddress.AddressValueError:
        return None
    return None if address.is_unspecified else str(address)


def rest_line(call: RestCall) -> str:
    """Displayed form of a REST call: ``METHOD path {json}``; secret values are redacted."""
    if call.body is None:
        return f"{call.method} {call.path}"
    body = {key: REDACTED if key in SECRET_KEYS else value for key, value in call.body.items()}
    return f"{call.method} {call.path} {json.dumps(body, sort_keys=True, ensure_ascii=False)}"


def rest_plan(steps, **kwargs) -> ChangePlan:
    """Plan of REST calls (pauses are not displayed); RouterOS stores every change immediately (``persistent``)."""
    steps = tuple(steps)
    lines = tuple(rest_line(step) for step in steps if isinstance(step, RestCall))
    return ChangePlan(lines=lines, steps=steps, persistent=True, **kwargs)


def _number(value) -> int | None:
    """RouterOS integer (decimal or ``0x8000``); None for unreadable values."""
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


STORM_FLAGS = {
    "broadcast": "limit-broadcasts",
    "multicast": "limit-unknown-multicasts",
    "unknown_unicast": "limit-unknown-unicasts",
}
_STP_ROLES = {"root-port": "root", "designated-port": "designated", "alternate-port": "alternate",
              "backup-port": "backup", "disabled-port": "disabled"}


def storm_state(row: dict | None) -> dict:
    """One ``storm-rate`` per port applies to every enabled ``limit-*`` type (100 % = off)."""
    state = dict.fromkeys(STORM_FLAGS)
    rate = parse_watts((row or {}).get("storm-rate"))
    if rate is not None and rate < 100:
        for field, key in STORM_FLAGS.items():
            if as_bool(row.get(key)) is True:
                state[field] = rate
    return {**state, "action": "drop" if any(state.values()) else None}


def dot1x_state(server: dict | None, status: str | None) -> dict:
    """``/interface/dot1x/server`` row -> phase-4 ``dot1x`` block."""
    if server is None or as_bool(server.get("disabled")) is True:
        mode = "off"
    else:
        types = set(split_list(server.get("auth-types") or "dot1x"))
        mode = "dot1x_mab" if types >= {"dot1x", "mac-auth"} else "mab" if "mac-auth" in types else "dot1x"
    server = server or {}
    return {"mode": mode, "host_mode": None, "guest_vlan": _number(server.get("guest-vlan-id")),
            "auth_fail_vlan": _number(server.get("reject-vlan-id")), "status": status}



# --- Bridge view -----------------------------------------------------------------------


def bridge_rows(vlans: list[dict], bridge: str) -> list[dict]:
    """Parsed ``/interface/bridge/vlan`` entries of one bridge (unreadable entries ignored)."""
    rows = []
    for row in vlans:
        if row.get("bridge") != bridge or as_bool(row.get("disabled")) is True:
            continue
        ids = parse_vlan_ids(row.get("vlan-ids"))
        if ids is None:
            continue
        rows.append({
            "raw": row,
            "id": row.get(".id"),
            "vlan_ids": str(row.get("vlan-ids")),
            "ids": ids,
            "tagged": split_list(row.get("tagged")),
            "untagged": split_list(row.get("untagged")),
            "current_tagged": split_list(row.get("current-tagged")),
            "dynamic": as_bool(row.get("dynamic")) is True,
        })
    return rows


def port_view(name: str, bridges: dict[str, dict], ports: dict[str, dict], vlans: list[dict]) -> dict:
    """VLAN view of one bridge port (Ethernet or bond) from the bridge configuration.

    ``admit-all`` with a PVID and exactly one further tagged VLAN is an access port with
    that VLAN as voice VLAN.
    """
    port = ports.get(name)
    view = {
        "bridge": None,
        "vlan_filtering": None,
        "pvid": None,
        "frame_types": None,
        "edge": None,
        "mode": "routed",
        "tagged": set(),
        "allowed": None,
        "native": None,
        "voice": None,
        "port_row": port,
        "rows": [],
    }
    if port is None:
        return view
    bridge = port.get("bridge")
    view["bridge"] = bridge
    view["vlan_filtering"] = as_bool((bridges.get(bridge) or {}).get("vlan-filtering")) is True
    pvid = port.get("pvid")
    view["pvid"] = int(pvid) if str(pvid or "").isdigit() else None
    view["frame_types"] = port.get("frame-types") or None
    view["edge"] = port.get("edge") or None
    rows = bridge_rows(vlans, bridge)
    view["rows"] = rows
    tagged = set()
    for row in rows:
        if name in row["tagged"] or name in row["current_tagged"]:
            tagged.update(row["ids"])
    view["tagged"] = tagged
    frames = view["frame_types"] or ALL_FRAMES
    extra = tagged - {view["pvid"]}
    if frames == ALL_FRAMES and view["pvid"] is not None and len(extra) == 1:
        view["mode"] = "access"
        (view["voice"],) = extra
    elif frames == TAGGED_FRAMES or (frames == ALL_FRAMES and tagged):
        view["mode"] = "trunk"
        view["native"] = view["pvid"] if frames == ALL_FRAMES else None
        allowed = set(tagged)
        if view["native"] is not None:
            allowed.add(view["native"])
        view["allowed"] = allowed
    else:
        view["mode"] = "access"
    return view


def switchport_detail(name: str, view: dict) -> dict:
    detail = empty_switchport_detail(name)
    if view["bridge"] is None:
        detail.update(switchport_enabled=False, administrative_mode="routed", operational_mode="routed",
                      mode="routed")
        return detail
    mode = view["mode"]
    detail.update(switchport_enabled=True, administrative_mode=mode, operational_mode=mode, mode=mode)
    if mode == "access":
        detail["access_vlan"] = view["pvid"]
        detail["voice_vlan"] = view["voice"]
    else:
        detail["native_vlan"] = view["native"]
        detail["trunk_allowed_vlan"] = format_vlan_list(tuple(sorted(view["allowed"]))) if view["allowed"] else "none"
    return detail


def interface_row(eth: dict, view: dict) -> dict:
    name = eth["name"]
    disabled = as_bool(eth.get("disabled")) is True
    running = as_bool(eth.get("running"))
    if disabled:
        status, admin_state, link_state = "disabled", "disabled", "down"
    elif running is None:
        status, admin_state, link_state = "unknown", "enabled", "unknown"
    else:
        status = "connected" if running else "notconnect"
        admin_state, link_state = "enabled", "up" if running else "down"
    if view["bridge"] is None:
        vlan = "routed"
    elif view["mode"] == "trunk":
        vlan = "trunk"
    else:
        vlan = str(view["pvid"]) if view["pvid"] is not None else ""
    return {
        "port": name,
        "description": eth.get("comment") or "",
        "status": status,
        "vlan": vlan,
        "admin_state": admin_state,
        "link_state": link_state,
    }


def parse_neighbors(rows: list[dict]) -> list[dict]:
    """``/ip/neighbor`` -> neighbor rows; protocol = first entry of ``discovered-by``."""
    neighbors = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        protocols = [item for item in split_list(row.get("discovered-by")) if item in {"mndp", "cdp", "lldp"}]
        addresses = [
            str(row[key]) for key in ("address4", "address", "address6")
            if row.get(key) and (key != "address" or not row.get("address4"))
        ]
        local = split_list(row.get("interface"))
        identity = row.get("identity") or None
        neighbors.append(neighbor_row(
            protocols[0] if protocols else None,
            device_id=identity or row.get("mac-address") or None,
            system_name=identity,
            chassis_id=row.get("mac-address") or None,
            platform=" ".join(part for part in (row.get("platform"), row.get("board")) if part) or None,
            capabilities=row.get("system-caps-enabled") or row.get("system-caps") or None,
            ip_addresses=list(dict.fromkeys(addresses)),
            local_interface=local[0] if local else None,
            remote_interface=row.get("interface-name") or None,
            software_version=row.get("version") or None,
        ))
    return neighbors


# --- Driver ----------------------------------------------------------------------------


class MikrotikDriver(MikrotikDeviceMixin, SwitchDriver):
    id = "mikrotik_routeros"
    vendor = "MikroTik"
    label = "MikroTik RouterOS v7"
    transport = "https"
    default_port = 443
    experimental = True
    features = FEATURES
    catalog = MIKROTIK_CATALOG
    transfer_method = "http"
    volatile_config_patterns = VOLATILE_EXPORT_PATTERNS
    max_lag_id = MAX_LAG_ID

    def __init__(self, http_transport: httpx.BaseTransport | None = None):
        self._http_transport = http_transport

    @contextmanager
    def session(self, switch: dict, credentials: dict) -> Iterator[RestSession]:
        """The enable secret is ignored; TLS replaces the SSH host-key check."""
        with transport.https_client(
            switch, credentials, base_path="/rest", transport=self._http_transport,
        ) as client:
            yield RestSession(client=client, switch=switch)

    # --- REST ------------------------------------------------------------------------

    def request(self, session: RestSession, method: str, path: str, body: dict | None = None, *,
                missing_ok: bool = False) -> Any:
        """One REST call with the response size limit and error mapping."""
        started = time.monotonic()
        status = None
        try:
            with session.client.stream(method, path, json=body) as response:
                status = response.status_code
                length = response.headers.get("content-length", "")
                if length.isdigit() and int(length) > transport.HTTPS_MAX_RESPONSE_BYTES:
                    raise SwitchConnectionError(t("Die Antwort des Switches überschreitet die zulässige Größe."))
                chunks = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > transport.HTTPS_MAX_RESPONSE_BYTES:
                        raise SwitchConnectionError(t("Die Antwort des Switches überschreitet die zulässige Größe."))
                    chunks.append(chunk)
        except httpx.TimeoutException:
            raise SwitchConnectionError(t("Zeitüberschreitung - Switch nicht erreichbar (IP/Port/Firewall prüfen)")) from None
        except (httpx.HTTPError, ssl.SSLError, OSError) as exc:
            logger.warning("REST %s %s on switch %s failed (%s)", method, path, session.switch.get("name"),
                           type(exc).__name__)
            raise SwitchConnectionError(
                t("REST-Verbindung zum Switch fehlgeschlagen ({error}). Adresse, Port und TLS-Zertifikat prüfen.",
                  error=type(exc).__name__)
            ) from None
        finally:
            logger.info("REST %s %s on switch %s -> %s (%.2f s)", method, path, session.switch.get("name"),
                        status, time.monotonic() - started)
        content = b"".join(chunks)
        if status == 401:
            raise SwitchConnectionError(t("Authentifizierung fehlgeschlagen (Benutzername/Passwort prüfen)"))
        if status == 403:
            raise SwitchConnectionError(t("Dem REST-Benutzer fehlt die Berechtigung für {path}.", path=path))
        if missing_ok and status in {400, 404}:
            return None
        if status == 400:
            detail = _error_detail(content)
            if detail:
                raise InvalidInputError(t("Der Switch hat die Anfrage abgelehnt: {detail}", detail=detail))
        if not 200 <= status < 300:
            raise SwitchConnectionError(
                t("Der Switch hat die REST-Anfrage {path} mit HTTP {status} beantwortet.", path=path, status=status)
            )
        if not content.strip():
            return None
        try:
            return json.loads(content)
        except ValueError:
            raise SwitchConnectionError(t("Der Switch hat keine gültige JSON-Antwort geliefert ({path}).",
                                          path=path)) from None

    def _object(self, session: RestSession, path: str) -> dict:
        data = self.request(session, "GET", path)
        if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
            data = data[0]
        if not isinstance(data, dict):
            raise SwitchConnectionError(t("Der Switch hat für {path} keine lesbaren Daten geliefert.", path=path))
        return data

    def _list(self, session: RestSession, path: str, *, missing_ok: bool = False) -> list[dict] | None:
        data = self.request(session, "GET", path, missing_ok=missing_ok)
        if data is None and missing_ok:
            return None
        if not isinstance(data, list):
            raise SwitchConnectionError(t("Der Switch hat für {path} keine lesbaren Daten geliefert.", path=path))
        return [row for row in data if isinstance(row, dict)]

    def _cached(self, session: RestSession, key: str, read):
        if key not in session.cache:
            session.cache[key] = read()
        return session.cache[key]

    def _resource(self, session: RestSession) -> dict:
        return self._cached(session, "resource", lambda: self._object(session, "/system/resource"))

    def _ethernet(self, session: RestSession) -> list[dict]:
        return self._cached(
            session, "ethernet",
            lambda: [row for row in self._list(session, "/interface/ethernet") if row.get("name")],
        )

    def _bridge(self, session: RestSession) -> tuple[dict[str, dict], dict[str, dict], list[dict]]:
        def read():
            bridges = {row["name"]: row for row in self._list(session, "/interface/bridge") if row.get("name")}
            ports = {
                row["interface"]: row
                for row in self._list(session, "/interface/bridge/port")
                if row.get("interface") and as_bool(row.get("disabled")) is not True
            }
            return bridges, ports, self._list(session, "/interface/bridge/vlan")

        return self._cached(session, "bridge", read)

    def _bonds(self, session: RestSession) -> list[dict]:
        """``/interface/bonding`` rows named ``bond{n}`` (the LAG convention)."""
        def read():
            rows = self._list(session, "/interface/bonding", missing_ok=True) or []
            return [row for row in rows if _BOND_RE.fullmatch(str(row.get("name") or ""))]

        return self._cached(session, "bonds", read)

    def _port_rows(self, session: RestSession) -> list[dict]:
        """Ethernet rows followed by the bond rows (both are editable ports)."""
        return [*self._ethernet(session), *self._bonds(session)]

    def _views(self, session: RestSession) -> dict[str, dict]:
        bridges, ports, vlans = self._bridge(session)
        return {row["name"]: port_view(row["name"], bridges, ports, vlans) for row in self._port_rows(session)}

    def _ethernet_row(self, session: RestSession, interface: str) -> dict:
        row = next((item for item in self._ethernet(session) if item["name"] == interface), None)
        if row is None:
            raise InvalidInputError(t("Interface {interface} ist kein Ethernet-Interface dieses Switches.",
                                      interface=interface))
        return row

    def _interface_row(self, session: RestSession, interface: str) -> tuple[str, dict]:
        """(``ethernet`` | ``bonding``, row) of an editable port."""
        if _BOND_RE.fullmatch(interface):
            row = next((item for item in self._bonds(session) if item["name"] == interface), None)
            if row is None:
                raise InvalidInputError(t("Interface {interface} ist kein Ethernet-Interface dieses Switches.",
                                          interface=interface))
            return "bonding", row
        return "ethernet", self._ethernet_row(session, interface)

    def _bridge_port(self, session: RestSession, interface: str) -> tuple[str, dict]:
        """(bridge, active bridge-port row) of ``interface``; ``InvalidInputError`` if it is none."""
        _bridges, ports, _vlans = self._bridge(session)
        row = ports.get(interface)
        if row is None or not row.get("bridge"):
            raise InvalidInputError(t(NOT_BRIDGE_PORT_REASON, interface=interface))
        return str(row["bridge"]), row

    # --- Interface names -------------------------------------------------------------

    def validate_interface(self, name: str) -> str:
        """Ethernet names and LAG bonds ``bond{n}``."""
        text = (name or "").strip() if isinstance(name, str) else ""
        if _BOND_RE.fullmatch(text):
            return text
        if not _INTERFACE_RE.fullmatch(text) or _NON_ETHERNET_RE.match(text):
            raise InvalidInputError(t("Ungültiger Interface-Name: {interface}", interface=str(name)[:80]))
        return text

    def interface_key(self, name: str) -> str:
        return (name or "").strip()

    def is_physical_interface(self, name: str) -> bool:
        text = (name or "").strip()
        return bool(_INTERFACE_RE.fullmatch(text)) and not _NON_ETHERNET_RE.match(text)

    # --- Reads -----------------------------------------------------------------------

    def check_connection(self, switch: dict, credentials: dict) -> dict:
        try:
            with self.session(switch, credentials) as session:
                info = self.read_device_info(session)
        except (SwitchConnectionError, InvalidInputError) as exc:
            return {"ok": False, "message": str(exc), "model": None}
        except Exception as exc:
            logger.warning("REST connection test failed for switch id=%s (%s)", switch.get("id"), type(exc).__name__)
            return {"ok": False, "message": t("REST-Verbindung fehlgeschlagen. Server-Log prüfen."), "model": None}
        return {
            "ok": True,
            "message": t("Verbindung erfolgreich: {name} (RouterOS {version})",
                         name=info["hostname"] or "?", version=info["software_version"] or "?"),
            "model": info["model"],
        }

    def read_device_info(self, session: RestSession) -> dict:
        resource = self._resource(session)
        identity = self._object(session, "/system/identity")
        routerboard = self.request(session, "GET", "/system/routerboard", missing_ok=True)
        routerboard = routerboard if isinstance(routerboard, dict) else {}
        model = routerboard.get("model") if as_bool(routerboard.get("routerboard")) is not False else None
        return {
            "hostname": identity.get("name") or None,
            "model": model or resource.get("board-name") or None,
            "serial_number": routerboard.get("serial-number") or None,
            "software_version": resource.get("version") or None,
            "uptime": resource.get("uptime") or None,
        }

    def read_interfaces(self, session: RestSession) -> list[dict]:
        """Ethernet ports and LAG bonds; ``errdisabled_reason`` (BPDU guard, loop-protect, 802.1X)."""
        views = self._views(session)
        disabled = self._errdisabled(session)
        return [
            {**interface_row(row, views[row["name"]]), "errdisabled_reason": (disabled.get(row["name"]) or {}).get("reason")}
            for row in self._port_rows(session)
        ]

    def _errdisabled(self, session: RestSession) -> dict[str, dict]:
        """Port -> {"reason", ...} of ports disabled by a protection feature; unreadable sources warn."""
        def read():
            found: dict[str, dict] = {}
            for row in self._ethernet(session):
                if row.get("loop-protect-status") == "disable":
                    found[row["name"]] = {"reason": "loop-protect", "row": row}
            _bridges, ports, _vlans = self._bridge(session)
            guarded = {name: row for name, row in ports.items() if as_bool(row.get("bpdu-guard")) is True}
            if guarded:
                link_up = {row["name"] for row in self._ethernet(session)
                           if as_bool(row.get("running")) is True and as_bool(row.get("disabled")) is not True}
                for item in self._port_monitor(session, list(guarded.values())):
                    name = item.get("interface")
                    if name in guarded and name in link_up and item.get("role") == "disabled-port" and name not in found:
                        found[name] = {"reason": "bpdu-guard", "row": guarded[name]}
            for item in self._dot1x_states(session):
                name = item.get("interface")
                if name and item.get("status") == "rejected-holding" and name not in found:
                    found[name] = {"reason": "dot1x", "row": None}
            return found

        return self._cached(session, "errdisabled", read)

    def _port_monitor(self, session: RestSession, rows: list[dict]) -> list[dict]:
        """``/interface/bridge/port/monitor`` of the given bridge-port rows (empty on failure, with a warning)."""
        ids = ",".join(_row_id(row) for row in rows)
        if not ids:
            return []
        try:
            data = self.request(session, "POST", "/interface/bridge/port/monitor", {"numbers": ids, "once": ""},
                                missing_ok=True)
        except SwitchConnectionError as exc:
            logger.warning("Bridge port monitor failed on switch %s: %s", session.switch.get("name"), exc)
            data = None
        if not isinstance(data, list):
            append_warning(session.warnings, t("Der Zustand der Bridge-Ports konnte nicht gelesen werden."))
            return []
        return [item for item in data if isinstance(item, dict)]

    def _all_bridge_rows(self, session: RestSession) -> list[dict]:
        _bridges, _ports, vlans = self._bridge(session)
        rows = []
        for bridge in sorted({str(row.get("bridge")) for row in vlans if row.get("bridge")}):
            rows.extend(bridge_rows(vlans, bridge))
        return rows

    def read_vlans(self, session: RestSession) -> list[dict]:
        rows = self._all_bridge_rows(session)
        ids = set().union(*(row["ids"] for row in rows)) if rows else set()
        names: dict[int, str] = {}
        for row in rows:
            if not row["dynamic"] and len(row["ids"]) == 1:
                (vlan,) = row["ids"]
                names.setdefault(vlan, str(row["raw"].get("comment") or ""))
        return [{"id": vlan, "name": names.get(vlan, ""), "status": "active"} for vlan in sorted(ids)]

    def read_switchports(self, session: RestSession, interfaces: list[dict]) -> dict[str, dict]:
        views = self._views(session)
        return {self.interface_key(name): switchport_detail(name, view) for name, view in views.items()}

    def _poe_rows(self, session: RestSession) -> list[dict]:
        rows = self._cached(session, "poe", lambda: self._list(session, "/interface/ethernet/poe", missing_ok=True))
        return [row for row in rows or () if row.get("name")]

    def read_poe_ports(self, session: RestSession) -> dict[str, dict] | None:
        rows = self._poe_rows(session)
        monitor: dict[str, dict] = {}
        if rows:
            try:
                data = self.request(session, "POST", "/interface/ethernet/poe/monitor",
                                    {"numbers": ",".join(row["name"] for row in rows), "once": ""})
            except (SwitchConnectionError, InvalidInputError) as exc:
                logger.warning("PoE monitor failed on switch %s: %s", session.switch.get("name"), exc)
                append_warning(session.warnings, t("Die PoE-Messwerte konnten nicht gelesen werden."))
                data = []
            for item in data if isinstance(data, list) else ():
                if isinstance(item, dict) and item.get("name"):
                    monitor[item["name"]] = item
        ports = {}
        for row in rows:
            values = monitor.get(row["name"], {})
            detail = empty_poe_detail(True)
            detail["poe_mode"] = {"auto-on": "auto", "off": "never", "forced-on": "static"}.get(row.get("poe-out"))
            detail["poe_status"] = values.get("poe-out-status") or None
            detail["poe_used_watts"] = parse_watts(values.get("poe-out-power"))
            ports[self.interface_key(row["name"])] = detail
        return ports

    def read_port_detail(self, session: RestSession, interface: str) -> dict:
        interface = self.validate_interface(interface)
        menu, eth = self._interface_row(session, interface)
        view = self._views(session)[interface]
        resource = self._resource(session)
        if menu == "ethernet":
            poe = self.read_poe_ports(session).get(interface) or empty_poe_detail(False)
            monitor = self.request(session, "POST", "/interface/ethernet/monitor", {"numbers": interface, "once": ""})
            monitor = monitor[0] if isinstance(monitor, list) and monitor and isinstance(monitor[0], dict) else {}
            speed, duplex = parse_speed(eth)
        else:
            poe, monitor, speed, duplex = empty_poe_detail(False), {}, None, None
        full_duplex = as_bool(monitor.get("full-duplex"))
        return {
            "interface": interface,
            "description": eth.get("comment") or None,
            **switchport_detail(interface, view),
            "portfast": view["edge"] in {"yes", "yes-discover"},
            "speed": speed,
            "duplex": duplex,
            "shutdown": as_bool(eth.get("disabled")) is True,
            "operational_speed": monitor.get("rate") or None,
            "operational_duplex": None if full_duplex is None else "full" if full_duplex else "half",
            **poe,
            "poe_configured_max_watts": None,
            "lag": menu == "bonding",
            "bridge": view["bridge"],
            "vlan_filtering": view["vlan_filtering"],
            "edge": view["edge"],
            "frame_types": view["frame_types"],
            "software_version": resource.get("version") or None,
            "port_options": {},
            "warnings": session.warnings,
        }

    def runtime_overrides(self, detail: dict) -> dict[str, str]:
        overrides = {}
        if "bridge" in detail and detail["bridge"] is None:
            overrides.update(dict.fromkeys(VLAN_FEATURES, NO_BRIDGE_REASON))
        elif "vlan_filtering" in detail and not detail["vlan_filtering"]:
            overrides.update(dict.fromkeys(VLAN_FEATURES, NO_VLAN_FILTERING_REASON))
        if "software_version" in detail:
            version = parse_version(detail["software_version"])
            if version is None:
                overrides.update(dict.fromkeys(("speed", "duplex"), UNKNOWN_VERSION_REASON))
            elif version < MIN_SPEED_VERSION:
                overrides.update(dict.fromkeys(("speed", "duplex"), OLD_VERSION_REASON))
        if detail.get("poe_supported") is False:
            overrides.update(dict.fromkeys(POE_PORT_FEATURES, NO_POE_PORT_REASON))
        if detail.get("lag"):
            overrides.update(dict.fromkeys(("speed", "duplex"), BOND_SPEED_REASON))
        return overrides

    def read_neighbors(self, session: RestSession) -> list[dict]:
        return parse_neighbors(self._list(session, "/ip/neighbor"))

    def _optional_list(self, session: RestSession, path: str, label: str) -> tuple[list[dict], str]:
        try:
            return self._list(session, path), "ok"
        except (SwitchConnectionError, InvalidInputError) as exc:
            logger.warning("Optional REST read %s failed on switch %s: %s", path, session.switch.get("name"), exc)
            append_warning(session.warnings, t("{label} konnte nicht gelesen werden; die Client-Daten können "
                                               "unvollständig sein.", label=label))
            return [], "error"

    def read_client_snapshot(self, session: RestSession, switch: dict) -> dict:
        interfaces = self.read_interfaces(session)
        switchports = self.read_switchports(session, interfaces)
        views = self._views(session)
        mac_entries = []
        for row in self._list(session, "/interface/bridge/host"):
            if as_bool(row.get("local")) is True:
                continue
            mac = normalize_mac_address(row.get("mac-address"))
            port = row.get("on-interface")
            if not mac or not port or port not in views:
                continue
            vid = str(row.get("vid") or "")
            if not vid.isdigit():
                pvid = views[port]["pvid"]
                vid = str(pvid) if pvid is not None else ""
            dynamic = as_bool(row.get("dynamic"))
            mac_entries.append({
                "vlan": vid,
                "mac": mac,
                "type": "" if dynamic is None else "DYNAMIC" if dynamic else "STATIC",
                "interface": port,
            })
        arp_rows, arp_status = self._optional_list(session, "/ip/arp", t("Die ARP-Tabelle"))
        ip_bindings = {}
        for row in arp_rows:
            mac = normalize_mac_address(row.get("mac-address"))
            address = row.get("address")
            if mac and address and as_bool(row.get("invalid")) is not True:
                ip_bindings[mac] = str(address)
        neighbor_rows, neighbor_status = self._optional_list(session, "/ip/neighbor", t("Die Nachbarliste"))
        return client_snapshot(
            switch,
            self,
            mac_entries=mac_entries,
            interfaces=interfaces,
            switchports=switchports,
            ip_bindings=ip_bindings,
            ip_sources=dict.fromkeys(ip_bindings, "arp"),
            neighbors=parse_neighbors(neighbor_rows),
            source_status={"arp": arp_status, "neighbors": neighbor_status},
            warnings=session.warnings,
        )

    # --- Writes ----------------------------------------------------------------------

    def speed_body(self, speed: str | None, duplex: str | None) -> dict:
        if speed is None and duplex is None:
            return {}
        if speed in (None, "auto"):
            if duplex not in (None, "auto"):
                raise InvalidInputError(t("Bei Speed auto muss Duplex auto sein."))
            return {"auto-negotiation": "yes"}
        validate_choice(str(speed), SPEED_OPTIONS, "Speed")
        if duplex in (None, "auto"):
            raise InvalidInputError(t("Bei fester Geschwindigkeit muss Duplex half oder full sein."))
        validate_choice(str(duplex), DUPLEX_OPTIONS, "Duplex")
        value = _SPEED_VALUES.get((speed, duplex))
        if value is None:
            raise InvalidInputError(t("1000 Mbit/s ist nur mit Vollduplex möglich."))
        return {"auto-negotiation": "no", "speed": value}

    def validate_port_change(self, interface: str, change: PortChange) -> None:
        if change.description is not None:
            sanitize_description(change.description, _DESCRIPTION_MAX_LENGTH)
        for vlan in (change.access_vlan, change.native_vlan):
            if vlan is not None:
                validate_vlan_id(vlan)
        if change.poe_mode is not None:
            validate_choice(change.poe_mode, POE_MODE_OPTIONS, "PoE-Modus")
        if change.poe_standard is not None:
            raise InvalidInputError(t(POE_LIMIT_REASON))
        self.speed_body(change.speed, change.duplex)

    def read_port_state(self, session: RestSession, interface: str, change: PortChange) -> dict:
        """Current Ethernet, bridge and (for PoE changes) PoE state; keys checked by ``runtime_overrides``.

        ``mode`` is always present (``switchport_detail`` semantics: access/trunk/routed).
        """
        interface = self.validate_interface(interface)
        menu, eth = self._interface_row(session, interface)
        bridges, ports, vlans = self._bridge(session)
        view = port_view(interface, bridges, ports, vlans)
        state = {
            "interface": interface,
            "mode": switchport_detail(interface, view)["mode"],
            "bridge": view["bridge"],
            "vlan_filtering": view["vlan_filtering"],
            "lag": menu == "bonding",
            "menu": menu,
            "ethernet": eth,
            "view": view,
        }
        if change.speed is not None or change.duplex is not None:
            state["software_version"] = self._resource(session).get("version") or None
        if change.poe_mode is not None:
            row = next((item for item in self._poe_rows(session) if item["name"] == interface), None)
            state["poe_row"] = row
            state["poe_supported"] = row is not None
        return state

    def bridge_steps(self, interface: str, change: PortChange, view: dict) -> list[RestCall]:
        """REST writes for mode/VLAN/edge changes; every check happens before the first write."""
        vlan_change = any(value is not None for value in (
            change.mode, change.access_vlan, change.native_vlan, change.trunk_allowed_vlans, change.voice_vlan,
        ))
        if not vlan_change and change.edge_port is None:
            return []
        if view["bridge"] is None:
            raise InvalidInputError(t(NO_BRIDGE_REASON))
        port_body: dict[str, str] = {}
        steps: list[RestCall] = []
        if vlan_change:
            if not view["vlan_filtering"]:
                raise InvalidInputError(t(NO_VLAN_FILTERING_REASON))
            steps, port_body = self._vlan_steps(interface, change, view)
        if change.edge_port is not None:
            port_body["edge"] = "yes" if change.edge_port else "no"
        if port_body:
            steps.append(RestCall("PATCH", f"/interface/bridge/port/{_row_id(view['port_row'])}", port_body))
        return steps

    def _vlan_steps(self, interface: str, change: PortChange, view: dict) -> tuple[list[RestCall], dict]:
        rows = view["rows"]
        existing = set().union(*(row["ids"] for row in rows)) if rows else set()
        current_mode = view["mode"]
        mode = change.mode or current_mode
        pvid = view["pvid"]
        voice = None
        if mode == "access":
            if change.trunk_allowed_vlans is not None and change.mode != "trunk":
                raise InvalidInputError(t("Erlaubte VLANs können nur für Trunk-Ports gesetzt werden."))
            new_pvid = validate_vlan_id(change.access_vlan) if change.access_vlan is not None else pvid
            if change.voice_vlan is not None:
                voice = validate_vlan_id(change.voice_vlan) if change.voice_vlan else None
            elif current_mode == "access":
                voice = view["voice"]
            if voice is not None and voice == new_pvid:
                raise InvalidInputError(t("Voice-VLAN und Access-VLAN müssen verschieden sein."))
            # The voice VLAN is a tagged membership next to the untagged PVID.
            new_frames = ALL_FRAMES if voice is not None else ACCESS_FRAMES
            new_tagged: set[int] = {voice} if voice is not None else set()
        else:
            if change.voice_vlan:
                raise InvalidInputError(t("Ein Voice-VLAN ist nur an Access-Ports möglich."))
            if change.native_vlan is not None:
                native = validate_vlan_id(change.native_vlan)
            elif current_mode == "access" or view["frame_types"] in (None, ALL_FRAMES):
                native = pvid
            else:
                native = None
            selection = change.trunk_allowed_vlans
            if selection is None:
                allowed = set(view["allowed"] or ()) if current_mode == "trunk" else set()
            elif selection == "all":
                allowed = set(existing)
            elif selection == "none":
                allowed = set()
            else:
                allowed = {validate_vlan_id(vlan) for vlan in selection}
            new_pvid = native if native is not None else pvid
            new_frames = ALL_FRAMES if native is not None else TAGGED_FRAMES
            new_tagged = allowed - {native}

        introduced = sorted((new_tagged - view["tagged"]) | ({new_pvid} if new_pvid != pvid else set()))
        for vlan in introduced:
            if vlan not in existing:
                raise InvalidInputError(t("VLAN {vlan} existiert auf dem Switch nicht.", vlan=vlan))

        untagged_vlan = new_pvid if new_frames != TAGGED_FRAMES else None
        steps: list[RestCall] = []
        covered: set[int] = set()
        static_rows = [row for row in rows if not row["dynamic"]]
        split = None
        if voice is not None and voice not in view["tagged"] and not any(row["ids"] == {voice} for row in static_rows):
            # A voice VLAN inside a multi-VLAN entry gets its own entry first.
            split = next((row for row in static_rows if voice in row["ids"]), None)
        for row in static_rows:
            body = {}
            ids = row["ids"] - {voice} if row is split else row["ids"]
            if row is split:
                body["vlan-ids"] = format_vlan_list(tuple(sorted(ids)))
            wanted = {vlan in new_tagged for vlan in ids}
            has_tag = interface in row["tagged"]
            if len(wanted) > 1:
                other_single = {vlan for other in static_rows if other is not row and len(other["ids"]) == 1
                                for vlan in other["ids"]}
                if has_tag or not (ids & new_tagged) <= other_single:
                    raise self._multi_vlan_error(row)
            elif wanted == {True}:
                covered.update(ids)
                if not has_tag:
                    body["tagged"] = ",".join([*row["tagged"], interface])
            elif has_tag:
                body["tagged"] = ",".join(item for item in row["tagged"] if item != interface)
            if interface in row["untagged"]:
                keep = {vlan == untagged_vlan for vlan in ids}
                if len(keep) > 1:
                    raise self._multi_vlan_error(row)
                if keep == {False}:
                    body["untagged"] = ",".join(item for item in row["untagged"] if item != interface)
            if body:
                steps.append(RestCall("PATCH", f"/interface/bridge/vlan/{_row_id(row['raw'])}", body))
            if row is split:
                entry = {"bridge": view["bridge"], "vlan-ids": str(voice),
                         "tagged": ",".join([*row["tagged"], interface])}
                untagged = [item for item in row["untagged"] if item != interface]
                if untagged:
                    entry["untagged"] = ",".join(untagged)
                steps.append(RestCall("PUT", "/interface/bridge/vlan", entry))
                covered.add(voice)
        for vlan in sorted(new_tagged - covered):
            # Exists only in a dynamic or multi-VLAN entry of this bridge: add a single-VLAN entry.
            steps.append(RestCall("PUT", "/interface/bridge/vlan",
                                  {"bridge": view["bridge"], "vlan-ids": str(vlan), "tagged": interface}))

        port_body = {}
        if new_frames != view["frame_types"]:
            port_body["frame-types"] = new_frames
        if new_pvid is not None and new_pvid != pvid:
            port_body["pvid"] = str(new_pvid)
        if voice is not None and as_bool((view["port_row"] or {}).get("ingress-filtering")) is not True:
            port_body["ingress-filtering"] = "yes"
        return steps, port_body

    @staticmethod
    def _multi_vlan_error(row: dict) -> InvalidInputError:
        return InvalidInputError(t(
            "Der VLAN-Eintrag {ids} umfasst mehrere VLANs; bitte auf dem Gerät aufteilen.", ids=row["vlan_ids"],
        ))

    def plan_port_change(self, session: RestSession, interface: str, change: PortChange, detail: dict) -> ChangePlan:
        interface = self.validate_interface(interface)
        if "view" not in detail:
            detail = self.read_port_state(session, interface, change)
        menu = detail.get("menu", "ethernet")
        eth_id = _row_id(detail["ethernet"])
        steps: list[RestCall] = []
        eth_body: dict[str, str] = {}
        if change.description is not None:
            eth_body["comment"] = sanitize_description(change.description, _DESCRIPTION_MAX_LENGTH)
        speed_body = self.speed_body(change.speed, change.duplex)
        if menu != "ethernet" and (speed_body or change.poe_mode is not None):
            raise InvalidInputError(t("Interface {interface} ist kein Ethernet-Interface dieses Switches.",
                                      interface=interface))
        eth_body.update(speed_body)
        if eth_body:
            steps.append(RestCall("PATCH", f"/interface/{menu}/{eth_id}", eth_body))
        steps.extend(self.bridge_steps(interface, change, detail["view"]))
        if change.poe_mode is not None:
            validate_choice(change.poe_mode, POE_MODE_OPTIONS, "PoE-Modus")
            row = detail.get("poe_row")
            if row is None:
                raise InvalidInputError(t(NO_POE_REASON, interface=interface))
            steps.append(RestCall("PATCH", f"/interface/ethernet/poe/{_row_id(row)}",
                                  {"poe-out": "auto-on" if change.poe_mode == "auto" else "off"}))
        if change.shutdown is not None:
            steps.append(RestCall("PATCH", f"/interface/{menu}/{eth_id}",
                                  {"disabled": "yes" if change.shutdown else "no"}))
        warnings = (t(VOICE_WARNING),) if change.voice_vlan else ()
        return rest_plan(steps, warnings=warnings,
                         message=t("Interface-Konfiguration übernommen (RouterOS speichert sofort dauerhaft)."))

    def plan_port_state(self, session: RestSession, interface: str, enabled: bool) -> ChangePlan:
        interface = self.validate_interface(interface)
        menu, eth = self._interface_row(session, interface)
        if enabled:
            message = t("Port {interface} wurde eingeschaltet.", interface=interface)
        else:
            message = t("Port {interface} wurde ausgeschaltet.", interface=interface)
        return rest_plan(
            [RestCall("PATCH", f"/interface/{menu}/{_row_id(eth)}", {"disabled": "no" if enabled else "yes"})],
            message=message,
        )

    def execute_plan(self, session: RestSession, plan: ChangePlan) -> WriteResult:
        """Send the REST calls in order and stop at the first rejected one; clears the session cache.

        ``plan.secrets`` are removed from the failure message and the returned log."""
        log: list[str] = []
        try:
            for step in plan.steps:
                if isinstance(step, RestCall):
                    log.append(rest_line(step))
                    try:
                        self.request(session, step.method, step.path, step.body)
                    except InvalidInputError as exc:
                        error = redact(str(exc), plan.secrets)
                        log.append(f"-> {error}")
                        return write_result(False, t("Der Switch hat einen Befehl abgelehnt: {errors}",
                                                     errors=error), redact("\n".join(log), plan.secrets))
                    except SwitchConnectionError:
                        if not step.expect_disconnect:
                            raise
                        # Reboot: the device closes the connection before answering.
                        log.append("-> connection closed")
                elif isinstance(step, Pause):
                    time.sleep(step.seconds)
                else:
                    log.append(self.device_step_line(step))
                    error = self.run_device_step(session, step)
                    if error:
                        error = redact(error, plan.secrets)
                        log.append(f"-> {error}")
                        return write_result(False, error, redact("\n".join(log), plan.secrets))
        finally:
            session.cache.clear()
        return write_result(True, plan.message or t("Änderung übernommen."), redact("\n".join(log), plan.secrets))

    # --- Management path (uplink detection) ---------------------------------------------

    def read_management_path(self, session: RestSession) -> dict:
        """Default route, the address row of the REST target and the VLAN behind its interface."""
        routes = [row for row in self._list(session, "/ip/route?dst-address=0.0.0.0/0")
                  if row.get("dst-address") == "0.0.0.0/0"]
        active = [row for row in routes if as_bool(row.get("active")) is True]
        gateway = next(
            (gw for gw in (_ipv4(str(row.get("gateway") or "").split("%", 1)[0]) for row in active or routes) if gw),
            None,
        )
        target = str(session.switch.get("ip") or "")
        address_row = next(
            (row for row in self._list(session, "/ip/address") if str(row.get("address") or "").split("/")[0] == target),
            None,
        )
        interface = str(address_row.get("interface") or "") if address_row else ""
        vlan = None
        if interface:
            interfaces = self._cached(
                session, "vlan_interfaces", lambda: self.request(session, "GET", "/interface/vlan", missing_ok=True),
            )
            row = next((item for item in interfaces or () if isinstance(item, dict) and item.get("name") == interface),
                       None)
            bridge = self._bridge(session)[0].get(interface)
            if row is not None and str(row.get("vlan-id") or "").isdigit():
                vlan = int(row["vlan-id"])
            elif bridge is not None and as_bool(bridge.get("vlan-filtering")) is True:
                pvid = str(bridge.get("pvid") or "1")
                vlan = int(pvid) if pvid.isdigit() else None
        return {"gateway": gateway, "management_ip": target if address_row else None,
                "management_interface": interface or None, "management_vlan": vlan}

    def lookup_arp(self, session: RestSession, ip: str) -> str | None:
        for row in self._list(session, f"/ip/arp?address={ip}"):
            if row.get("address") != ip or as_bool(row.get("invalid")) is True or as_bool(row.get("complete")) is False:
                continue
            mac = normalize_mac_address(row.get("mac-address"))
            if mac:
                return format_mac_address(mac)
        return None

    def lookup_mac_port(self, session: RestSession, mac: str) -> str | None:
        wanted = normalize_mac_address(mac)
        if not wanted:
            return None
        for row in self._list(session, f"/interface/bridge/host?mac-address={format_mac_address(wanted).upper()}"):
            if normalize_mac_address(row.get("mac-address")) != wanted or as_bool(row.get("local")) is True:
                continue
            port = row.get("on-interface") or row.get("interface")
            if port:
                return str(port)
        return None

    # --- VLAN administration ---------------------------------------------------------------

    def _static_rows(self, session: RestSession, vlan_id: int) -> list[dict]:
        return [row for row in self._all_bridge_rows(session) if not row["dynamic"] and vlan_id in row["ids"]]

    def read_vlan_constraints(self, session: RestSession) -> vlanlib.VlanConstraints:
        static = set()
        for row in self._all_bridge_rows(session):
            if not row["dynamic"]:
                static |= row["ids"]
        protected = {row["id"]: vlanlib.DYNAMIC_REASON for row in self.read_vlans(session) if row["id"] not in static}
        bridges, _ports, _vlans = self._bridge(session)
        interfaces = self._cached(
            session, "vlan_interfaces", lambda: self.request(session, "GET", "/interface/vlan", missing_ok=True),
        )
        if not isinstance(interfaces, list):
            l3 = None
        else:
            l3 = frozenset(
                int(row["vlan-id"]) for row in interfaces
                if isinstance(row, dict) and row.get("interface") in bridges and str(row.get("vlan-id") or "").isdigit()
            )
        return vlanlib.VlanConstraints(protected=protected, l3_interfaces=l3)

    @staticmethod
    def _vlan_plan(action: str, vlan_id: int, steps: list[RestCall]) -> ChangePlan:
        return rest_plan(steps, message=vlanlib.success_message(action, vlan_id, persistent=True))

    def plan_vlan_create(self, session: RestSession, vlan_id: int, name: str | None) -> ChangePlan:
        bridges, _ports, _vlans = self._bridge(session)
        filtering = [bridge for bridge, row in bridges.items() if as_bool(row.get("vlan-filtering")) is True]
        if len(filtering) != 1:
            raise InvalidInputError(
                t("VLANs können nur angelegt werden, wenn genau eine Bridge mit VLAN-Filterung existiert.")
            )
        body = {"bridge": filtering[0], "vlan-ids": str(vlan_id)}
        if name:
            body["comment"] = name
        return self._vlan_plan("create", vlan_id, [RestCall("PUT", "/interface/bridge/vlan", body)])

    def plan_vlan_rename(self, session: RestSession, vlan_id: int, name: str) -> ChangePlan:
        rows = [row for row in self._static_rows(session, vlan_id) if len(row["ids"]) == 1]
        if len(rows) != 1:
            raise InvalidInputError(
                t("Der Name kann nur für VLANs mit genau einem eigenen statischen Bridge-Eintrag gesetzt werden.")
            )
        steps = [RestCall("PATCH", f"/interface/bridge/vlan/{_row_id(rows[0]['raw'])}", {"comment": name})]
        return self._vlan_plan("rename", vlan_id, steps)

    def plan_vlan_delete(self, session: RestSession, vlan_id: int) -> ChangePlan:
        steps = []
        for row in self._static_rows(session, vlan_id):
            path = f"/interface/bridge/vlan/{_row_id(row['raw'])}"
            if len(row["ids"]) == 1:
                steps.append(RestCall("DELETE", path))
            else:
                remaining = format_vlan_list(tuple(sorted(row["ids"] - {vlan_id})))
                steps.append(RestCall("PATCH", path, {"vlan-ids": remaining}))
        return self._vlan_plan("delete", vlan_id, steps)

    # --- Port actions -----------------------------------------------

    def plan_port_bounce(self, session: RestSession, interface: str) -> ChangePlan:
        """Disable, wait 5 s, enable; refuses ports that are switched off."""
        interface = self.validate_interface(interface)
        menu, row = self._interface_row(session, interface)
        if as_bool(row.get("disabled")) is True:
            raise InvalidInputError(t(PORT_DISABLED_REASON, interface=interface))
        path = f"/interface/{menu}/{_row_id(row)}"
        return rest_plan([RestCall("PATCH", path, {"disabled": "true"}), Pause(5),
                          RestCall("PATCH", path, {"disabled": "false"})])

    def plan_poe_cycle(self, session: RestSession, interface: str) -> ChangePlan:
        """Native ``power-cycle`` (5 s); the PoE configuration stays untouched."""
        interface = self.validate_interface(interface)
        row = next((item for item in self._poe_rows(session) if item["name"] == interface), None)
        if row is None:
            raise InvalidInputError(t(NO_POE_REASON, interface=interface))
        if row.get("poe-out") == "off":
            raise InvalidInputError(t("PoE ist an Port {interface} ausgeschaltet; ein PoE-Neustart ist nicht möglich.",
                                      interface=interface))
        return rest_plan([RestCall("POST", "/interface/ethernet/poe/power-cycle",
                                   {"numbers": interface, "duration": "5s"})])

    def plan_errdisable_recover(self, session: RestSession, interface: str) -> ChangePlan:
        """BPDU guard -> bridge port off/on, loop-protect -> off/previous value, 802.1X -> server off/on."""
        interface = self.validate_interface(interface)
        found = self._errdisabled(session).get(interface)
        if found is None:
            raise InvalidInputError(t("Der Port ist nicht durch eine Schutzfunktion deaktiviert."))
        if found["reason"] == "bpdu-guard":
            path, off, on = f"/interface/bridge/port/{_row_id(found['row'])}", {"disabled": "true"}, {"disabled": "false"}
        elif found["reason"] == "loop-protect":
            previous = str(found["row"].get("loop-protect") or "on")
            path = f"/interface/ethernet/{_row_id(found['row'])}"
            off, on = {"loop-protect": "off"}, {"loop-protect": previous if previous != "off" else "on"}
        else:
            server = next((row for row in self._dot1x_servers(session) if row.get("interface") == interface), None)
            if server is None:
                raise InvalidInputError(t("Der Port ist nicht durch eine Schutzfunktion deaktiviert."))
            path, off, on = f"/interface/dot1x/server/{_row_id(server)}", {"disabled": "true"}, {"disabled": "false"}
        return rest_plan([RestCall("PATCH", path, off), RestCall("PATCH", path, on)])

    def _dot1x_servers(self, session: RestSession) -> list[dict]:
        return self._cached(
            session, "dot1x_servers",
            lambda: self._list(session, "/interface/dot1x/server", missing_ok=True) or [],
        )

    def _dot1x_states(self, session: RestSession) -> list[dict]:
        """``/interface/dot1x/server/state`` (empty with a warning when unreadable)."""
        def read():
            try:
                return self._list(session, "/interface/dot1x/server/state", missing_ok=True) or []
            except SwitchConnectionError as exc:
                logger.warning("802.1X state read failed on switch %s: %s", session.switch.get("name"), exc)
                append_warning(session.warnings, t("Der 802.1X-Status konnte nicht gelesen werden."))
                return []

        return self._cached(session, "dot1x_states", read)

    # --- Configuration, reload ------------------------------

    def read_running_config(self, session: RestSession) -> str:
        """``/export show-sensitive`` as string (needs the ``sensitive`` policy for secrets)."""
        data = self.request(session, "POST", "/execute", {"script": "/export show-sensitive", "as-string": ""})
        if isinstance(data, list) and len(data) == 1:
            data = data[0]
        text = data.get("ret") if isinstance(data, dict) else None
        if not isinstance(text, str) or not text.strip():
            raise SwitchConnectionError(t("Der Switch hat für {path} keine lesbaren Daten geliefert.", path="/export"))
        return text

    def read_startup_config(self, session: RestSession) -> str | None:
        """RouterOS has no startup configuration."""
        return None

    def plan_reload(self, session: RestSession) -> ChangePlan:
        """``POST /system/reboot``; nothing to save, a dropped connection counts as success."""
        return rest_plan([REBOOT], reloads=True)

    # --- Port security ----------------------------

    def _storm_ports(self, session: RestSession) -> list[dict]:
        return self._cached(
            session, "storm_ports",
            lambda: self._list(session, "/interface/ethernet/switch/port", missing_ok=True) or [],
        )

    def _radius_rows(self, session: RestSession) -> list[dict]:
        return self._cached(session, "radius_rows", lambda: self._list(session, "/radius", missing_ok=True) or [])

    @staticmethod
    def _dot1x_radius(row: dict) -> bool:
        return "dot1x" in split_list(row.get("service")) and as_bool(row.get("disabled")) is not True

    def read_port_security(self, session: RestSession) -> dict:
        bridges, ports, _vlans = self._bridge(session)
        servers = {row.get("interface"): row for row in self._dot1x_servers(session)}
        states = {row.get("interface"): row.get("status") or None for row in self._dot1x_states(session)}
        storm = {row.get("name"): row for row in self._storm_ports(session)}
        result = {}
        for row in self._port_rows(session):
            name = row["name"]
            port = ports.get(name) or {}
            result[self.interface_key(name)] = {
                "port_security": dict.fromkeys(
                    ("enabled", "max_macs", "sticky", "violation", "violation_count", "secure_macs")),
                "dot1x": dot1x_state(servers.get(name), states.get(name)),
                "stp_guard": {"bpdu_guard": as_bool(port.get("bpdu-guard")),
                              "root_guard": as_bool(port.get("restricted-role")), "loop_guard": None},
                "storm_control": storm_state(storm.get(name)),
                "dhcp_snooping_trust": as_bool(port.get("trusted")),
                "arp_inspection_trust": None,
                "ip_source_guard": None,
            }
        snooping = [as_bool(row.get("dhcp-snooping")) for row in bridges.values()]
        return {
            "global": {
                "dhcp_snooping": {"enabled": any(snooping) if snooping else None, "vlans": []},
                "arp_inspection": {"vlans": []},
                "dot1x": {"enabled": any(self._dot1x_radius(row) for row in self._radius_rows(session))},
            },
            "ports": result,
        }

    def plan_port_security(self, session: RestSession, interface: str, change: SecurityChange,
                           detail: dict) -> ChangePlan:
        interface = self.validate_interface(interface)
        for value, reason in ((change.port_security, PORT_SECURITY_REASON),
                              (change.arp_inspection_trust, ARP_INSPECTION_REASON),
                              (change.ip_source_guard, IP_SOURCE_GUARD_REASON)):
            if value is not None:
                raise InvalidInputError(t(reason))
        steps: list[RestCall] = []
        if change.dot1x is not None:
            steps.extend(self._dot1x_steps(session, interface, change.dot1x))
        port_body: dict[str, str] = {}
        guard = change.stp_guard
        if guard is not None:
            if guard.loop_guard:
                raise InvalidInputError(t(LOOP_GUARD_REASON))
            if guard.bpdu_guard is not None:
                port_body["bpdu-guard"] = "yes" if guard.bpdu_guard else "no"
            if guard.root_guard is not None:
                port_body["restricted-role"] = "yes" if guard.root_guard else "no"
        if change.dhcp_snooping_trust is not None:
            port_body["trusted"] = "yes" if change.dhcp_snooping_trust else "no"
        if port_body:
            _bridge, port = self._bridge_port(session, interface)
            steps.append(RestCall("PATCH", f"/interface/bridge/port/{_row_id(port)}", port_body))
        if change.storm_control is not None:
            steps.append(self._storm_step(session, interface, change.storm_control))
        return rest_plan(steps)

    def _dot1x_steps(self, session: RestSession, interface: str, settings: Dot1xSettings) -> list[RestCall]:
        if settings.host_mode is not None or settings.guest_vlan or settings.auth_fail_vlan:
            raise InvalidInputError(t(DOT1X_OPTIONS_REASON))
        server = next((row for row in self._dot1x_servers(session) if row.get("interface") == interface), None)
        if settings.mode == "off":
            return [RestCall("DELETE", f"/interface/dot1x/server/{_row_id(server)}")] if server else []
        types = {"dot1x": "dot1x", "mab": "mac-auth", "dot1x_mab": "dot1x,mac-auth"}[settings.mode]
        body = {"auth-types": types}
        if "mac-auth" in types:
            body.update({"mac-auth-mode": "mac-as-username-and-password", "radius-mac-format": "XX:XX:XX:XX:XX:XX"})
        if server is None:
            return [RestCall("PUT", "/interface/dot1x/server", {"interface": interface, **body})]
        if as_bool(server.get("disabled")) is True:
            body["disabled"] = "no"
        return [RestCall("PATCH", f"/interface/dot1x/server/{_row_id(server)}", body)]

    def _storm_step(self, session: RestSession, interface: str, settings: StormControlSettings) -> RestCall:
        """One shared rate for all limited types; 0 switches a type off."""
        if settings.action == "shutdown":
            raise InvalidInputError(t(STORM_SHUTDOWN_REASON))
        row = next((item for item in self._storm_ports(session) if item.get("name") == interface), None)
        if row is None:
            raise InvalidInputError(t("Interface {interface} ist kein Ethernet-Interface dieses Switches.",
                                      interface=interface))
        current = storm_state(row)
        final = {}
        for field_name in STORM_FLAGS:
            value = getattr(settings, field_name)
            final[field_name] = current[field_name] if value is None else (float(value) or None)
        rates = {value for value in final.values() if value}
        if len(rates) > 1:
            raise InvalidInputError(t(STORM_RATE_MISMATCH))
        if rates:
            (rate,) = rates
            body = {"storm-rate": f"{rate:g}",
                    **{key: "yes" if final[name] else "no" for name, key in STORM_FLAGS.items()}}
        else:
            body = {"storm-rate": "100", "limit-broadcasts": "yes", "limit-unknown-multicasts": "no",
                    "limit-unknown-unicasts": "no"}
        return RestCall("PATCH", f"/interface/ethernet/switch/port/{_row_id(row)}", body)

    def plan_security_global(self, session: RestSession, change: SecurityGlobalChange) -> ChangePlan:
        """DHCP snooping per bridge (no VLAN list); 802.1X = RADIUS entries with service ``dot1x``."""
        if change.arp_inspection_vlans:
            raise InvalidInputError(t(ARP_INSPECTION_REASON))
        if change.dhcp_snooping_vlans:
            raise InvalidInputError(t(SNOOPING_VLANS_REASON))
        steps: list[RestCall] = []
        if change.dhcp_snooping_enabled is not None:
            for row in self._bridge(session)[0].values():
                if as_bool(row.get("dhcp-snooping")) is not change.dhcp_snooping_enabled:
                    steps.append(RestCall("PATCH", f"/interface/bridge/{_row_id(row)}",
                                          {"dhcp-snooping": "yes" if change.dhcp_snooping_enabled else "no"}))
        if change.dot1x_enabled is not None:
            rows = self._radius_rows(session)
            if change.dot1x_enabled and not rows:
                raise InvalidInputError(t("Für 802.1X muss zuerst ein RADIUS-Server konfiguriert werden."))
            for row in rows:
                services = split_list(row.get("service"))
                disabled = as_bool(row.get("disabled")) is True
                body = None
                if change.dot1x_enabled and "dot1x" not in services:
                    body = {"service": ",".join([*services, "dot1x"])}
                elif change.dot1x_enabled and disabled and services == ["dot1x"]:
                    body = {"disabled": "no"}
                elif not change.dot1x_enabled and "dot1x" in services and not disabled:
                    rest = [item for item in services if item != "dot1x"]
                    # A RADIUS entry only used for 802.1X is disabled, not deleted.
                    body = {"service": ",".join(rest)} if rest else {"disabled": "yes"}
                if body:
                    steps.append(RestCall("PATCH", f"/radius/{_row_id(row)}", body))
        return rest_plan(steps)

    # --- Link aggregation ----------------------------------

    def lag_interface_name(self, lag_id: int) -> str:
        return f"bond{int(lag_id)}"

    def read_lags(self, session: RestSession) -> list[dict]:
        lags = []
        for row in self._bonds(session):
            name = row["name"]
            mode = row.get("mode")
            if mode == "802.3ad":
                lag_mode = "lacp_passive" if row.get("lacp-mode") == "passive" else "lacp_active"
            else:
                lag_mode = "static" if mode == "balance-xor" else None
            members = split_list(row.get("slaves"))
            states = self._bond_member_states(session, name) if members else {}
            running = as_bool(row.get("running"))
            if as_bool(row.get("disabled")) is True:
                status = "disabled"
            else:
                status = None if running is None else "up" if running else "down"
            lags.append({
                "id": int(_BOND_RE.fullmatch(name).group(1)),
                "interface": name,
                "mode": lag_mode,
                "members": [{"interface": member, "state": states.get(member)} for member in members],
                "status": status,
            })
        return sorted(lags, key=lambda lag: lag["id"])

    def _bond_member_states(self, session: RestSession, bond: str) -> dict[str, str]:
        """``monitor-slaves``: flag ``A`` = active (bundled)."""
        try:
            data = self.request(session, "POST", "/interface/bonding/monitor-slaves", {"bond": bond, "once": ""},
                                missing_ok=True)
        except SwitchConnectionError as exc:
            logger.warning("Bond monitor failed on switch %s: %s", session.switch.get("name"), exc)
            data = None
        states = {}
        for item in data if isinstance(data, list) else ():
            if isinstance(item, dict) and item.get("port"):
                states[str(item["port"])] = "bundled" if "A" in str(item.get("flags") or "") else "down"
        return states

    def _bond(self, session: RestSession, lag_id: int) -> dict:
        name = self.lag_interface_name(lag_id)
        row = next((item for item in self._bonds(session) if item["name"] == name), None)
        if row is None:
            raise InvalidInputError(t("LAG {lag} existiert auf dem Switch nicht.", lag=lag_id))
        return row

    def _bridge_port_rows(self, session: RestSession, interface: str) -> list[dict]:
        """Every bridge-port row of ``interface`` (also disabled ones)."""
        rows = self._cached(session, "bridge_ports_all", lambda: self._list(session, "/interface/bridge/port"))
        return [row for row in rows if row.get("interface") == interface]

    @staticmethod
    def _port_copy(template: dict, interface: str) -> RestCall:
        """New bridge port for ``interface`` with the bridge/VLAN settings of ``template``."""
        body = {"bridge": str(template["bridge"]), "interface": interface}
        for key in ("pvid", "frame-types", "ingress-filtering"):
            if template.get(key):
                body[key] = str(template[key])
        return RestCall("PUT", "/interface/bridge/port", body)

    def _membership_steps(self, session: RestSession, remove: set[str], add: list[str],
                          template: str | None) -> list[RestCall]:
        """Static VLAN entries: drop ``remove`` from tagged/untagged and add ``add`` where ``template`` was."""
        steps = []
        for row in self._all_bridge_rows(session):
            if row["dynamic"]:
                continue
            body = {}
            for key in ("tagged", "untagged"):
                current = row[key]
                new = [item for item in current if item not in remove]
                if template is not None and template in current:
                    new += [item for item in add if item not in new]
                if new != current:
                    body[key] = ",".join(new)
            if body:
                steps.append(RestCall("PATCH", f"/interface/bridge/vlan/{_row_id(row['raw'])}", body))
        return steps

    def _lag_members(self, session: RestSession, members) -> list[str]:
        result = []
        for member in members:
            member = self.validate_interface(member)
            self._ethernet_row(session, member)
            result.append(member)
        return result

    def plan_lag_create(self, session: RestSession, lag_id: int, mode: str, members: tuple[str, ...]) -> ChangePlan:
        """Members leave the bridge, ``bond{n}`` joins it with the first member's VLAN settings."""
        name = self.lag_interface_name(lag_id)
        if any(row["name"] == name for row in self._bonds(session)):
            raise InvalidInputError(t("LAG {lag} existiert bereits.", lag=lag_id))
        if mode not in _LAG_MODES:
            raise InvalidInputError(t("Diese Einstellung wird vom Switch nicht unterstützt: {value}", value=mode))
        members = self._lag_members(session, members)
        _bridges, ports, _vlans = self._bridge(session)
        steps = [RestCall("DELETE", f"/interface/bridge/port/{_row_id(row)}")
                 for member in members for row in self._bridge_port_rows(session, member)]
        body = {"name": name, "slaves": ",".join(members), "mode": _LAG_MODES[mode]}
        if mode != "static":
            body.update({"lacp-mode": "passive" if mode == "lacp_passive" else "active", "lacp-rate": "30secs"})
        body.update({"transmit-hash-policy": "layer-2-and-3", "link-monitoring": "mii"})
        steps.append(RestCall("PUT", "/interface/bonding", body))
        first = next((member for member in members if member in ports), None)
        if first is not None:
            steps.append(self._port_copy(ports[first], name))
            steps.extend(self._membership_steps(session, set(members), [name], first))
        return rest_plan(steps)

    def plan_lag_update(self, session: RestSession, lag_id: int, add: tuple[str, ...],
                        remove: tuple[str, ...]) -> ChangePlan:
        bond = self._bond(session, lag_id)
        name = bond["name"]
        current = split_list(bond.get("slaves"))
        add = [member for member in self._lag_members(session, add) if member not in current]
        remove = [self.validate_interface(member) for member in remove]
        new = [member for member in current if member not in remove] + add
        if not new:
            raise InvalidInputError(t("Ein LAG braucht mindestens ein Mitglied; zum Entfernen bitte löschen."))
        steps = [RestCall("DELETE", f"/interface/bridge/port/{_row_id(row)}")
                 for member in add for row in self._bridge_port_rows(session, member)]
        steps.extend(self._membership_steps(session, set(add), [], None))
        steps.append(RestCall("PATCH", f"/interface/bonding/{_row_id(bond)}", {"slaves": ",".join(new)}))
        bond_port = self._bridge(session)[1].get(name)
        removed = [member for member in remove if member in current]
        if bond_port is not None and removed:
            steps.extend(self._port_copy(bond_port, member) for member in removed)
            steps.extend(self._membership_steps(session, set(), removed, name))
        return rest_plan(steps)

    def plan_lag_delete(self, session: RestSession, lag_id: int) -> ChangePlan:
        """Bond leaves the bridge and is removed; former members rejoin with the bond's VLAN settings."""
        bond = self._bond(session, lag_id)
        name = bond["name"]
        members = split_list(bond.get("slaves"))
        bond_port = self._bridge(session)[1].get(name)
        steps = [RestCall("DELETE", f"/interface/bridge/port/{_row_id(row)}")
                 for row in self._bridge_port_rows(session, name)]
        steps.append(RestCall("DELETE", f"/interface/bonding/{_row_id(bond)}"))
        if bond_port is not None:
            steps.extend(self._port_copy(bond_port, member) for member in members)
            steps.extend(self._membership_steps(session, {name}, members, name))
        return rest_plan(steps)

    # --- Spanning tree -----------------------------------------

    def _stp_bridge(self, session: RestSession) -> dict:
        """The VLAN-filtering bridge (or the only bridge)."""
        bridges = self._bridge(session)[0]
        candidates = [row for row in bridges.values() if as_bool(row.get("vlan-filtering")) is True]
        if not candidates and len(bridges) == 1:
            candidates = list(bridges.values())
        if len(candidates) != 1:
            raise InvalidInputError(t(STP_BRIDGE_REASON))
        return candidates[0]

    def _mstis(self, session: RestSession, bridge: str) -> list[dict]:
        rows = self._cached(session, "msti", lambda: self._list(session, "/interface/bridge/msti", missing_ok=True))
        return [row for row in rows or () if row.get("bridge") == bridge and _number(row.get("identifier"))]

    def _msti(self, session: RestSession, bridge: str, instance: int) -> dict:
        row = next((item for item in self._mstis(session, bridge) if _number(item.get("identifier")) == instance),
                   None)
        if row is None:
            raise InvalidInputError(t(MSTI_MISSING_REASON, instance=instance))
        return row

    def _monitor(self, session: RestSession, path: str, numbers: str) -> list[dict]:
        try:
            data = self.request(session, "POST", path, {"numbers": numbers, "once": ""}, missing_ok=True)
        except SwitchConnectionError as exc:
            logger.warning("Monitor %s failed on switch %s: %s", path, session.switch.get("name"), exc)
            data = None
        if not isinstance(data, list):
            append_warning(session.warnings, t("Der Spanning-Tree-Zustand konnte nicht gelesen werden."))
            return []
        return [item for item in data if isinstance(item, dict)]

    @staticmethod
    def _root(instance: int, item: dict) -> dict:
        return {"vlan_or_instance": instance, "root_bridge": item.get("root-bridge-id") or None,
                "root_port": item.get("root-port") or None, "root_cost": _number(item.get("root-path-cost")),
                "is_root": as_bool(item.get("root-bridge"))}

    def read_stp(self, session: RestSession) -> dict:
        bridge = self._stp_bridge(session)
        name = str(bridge["name"])
        mode = bridge.get("protocol-mode") or None
        mstis = sorted(self._mstis(session, name), key=lambda row: _number(row.get("identifier")))
        priority = [{"instance": 0, "priority": _number(bridge.get("priority"))}]
        priority += [{"instance": _number(row["identifier"]), "priority": _number(row.get("priority"))} for row in mstis]
        mst = None
        if mode == "mstp":
            mst = {"name": bridge.get("region-name") or None, "revision": _number(bridge.get("region-revision")) or 0,
                   "instances": [{"id": _number(row["identifier"]), "vlans": str(row.get("vlan-mapping") or "")}
                                 for row in mstis]}
        roots = [self._root(0, item) for item in self._monitor(session, "/interface/bridge/monitor", name)[:1]]
        if mst and mstis:
            monitor = self._monitor(session, "/interface/bridge/msti/monitor",
                                    ",".join(_row_id(row) for row in mstis))
            for row, item in zip(mstis, monitor, strict=False):
                roots.append(self._root(_number(item.get("identifier")) or _number(row["identifier"]), item))
        ports_rows = [row for row in self._bridge(session)[1].values() if row.get("bridge") == name]
        monitor = {item.get("interface"): item
                   for item in (self._port_monitor(session, ports_rows) if ports_rows else ())}
        ports = []
        for row in ports_rows:
            item = monitor.get(row["interface"], {})
            if as_bool(item.get("forwarding")) is True:
                state = "forwarding"
            elif as_bool(item.get("learning")) is True:
                state = "learning"
            else:
                state = "discarding" if item else None
            ports.append({"interface": row["interface"], "instance_or_vlan": 0, "cost": _number(row.get("path-cost")),
                          "priority": _number(row.get("priority")),
                          "role": _STP_ROLES.get(item.get("role"), item.get("role")), "state": state})
        if mst is not None:
            names = {row["interface"] for row in ports_rows}
            overrides = self._list(session, "/interface/bridge/port/mst-override", missing_ok=True) or []
            ports += [{"interface": row.get("interface"), "instance_or_vlan": _number(row.get("identifier")),
                       "cost": _number(row.get("internal-path-cost")), "priority": _number(row.get("priority")),
                       "role": None, "state": None}
                      for row in overrides if row.get("interface") in names]
        return {"mode": mode, "priority": priority, "mst": mst, "roots": roots, "ports": ports}

    def plan_stp_mode(self, session: RestSession, mode: str) -> ChangePlan:
        validate_choice(mode, _STP_MODES, "Spanning-Tree-Modus")
        bridge = self._stp_bridge(session)
        return rest_plan([RestCall("PATCH", f"/interface/bridge/{_row_id(bridge)}", {"protocol-mode": mode})])

    def plan_stp_priority(self, session: RestSession, priority: int, vlans: tuple[int, ...] | None,
                          instance: int | None) -> ChangePlan:
        if vlans:
            raise InvalidInputError(t(PVST_REASON))
        bridge = self._stp_bridge(session)
        if not instance:
            path = f"/interface/bridge/{_row_id(bridge)}"
        else:
            path = f"/interface/bridge/msti/{_row_id(self._msti(session, str(bridge['name']), instance))}"
        return rest_plan([RestCall("PATCH", path, {"priority": str(int(priority))})])

    def plan_stp_mst(self, session: RestSession, name: str, revision: int,
                     instances: tuple[tuple[int, tuple[int, ...]], ...]) -> ChangePlan:
        """Region name/revision and the complete MSTI mapping (missing instances are deleted)."""
        bridge = self._stp_bridge(session)
        bridge_name = str(bridge["name"])
        steps = [RestCall("PATCH", f"/interface/bridge/{_row_id(bridge)}",
                          {"region-name": name, "region-revision": str(int(revision))})]
        existing = {_number(row["identifier"]): row for row in self._mstis(session, bridge_name)}
        wanted = {int(instance): {validate_vlan_id(vlan) for vlan in vlans} for instance, vlans in instances}
        for instance, row in sorted(existing.items()):
            if instance not in wanted:
                steps.append(RestCall("DELETE", f"/interface/bridge/msti/{_row_id(row)}"))
        # Shrink changed instances first so a VLAN moving between instances is never mapped twice.
        for instance, row in sorted(existing.items()):
            old = parse_vlan_ids(row.get("vlan-mapping")) or set()
            kept = old & wanted.get(instance, set())
            if instance in wanted and kept and kept != old and kept != wanted[instance]:
                steps.append(RestCall("PATCH", f"/interface/bridge/msti/{_row_id(row)}",
                                      {"vlan-mapping": format_vlan_list(tuple(sorted(kept)))}))
        for instance, vlans in sorted(wanted.items()):
            mapping = format_vlan_list(tuple(sorted(vlans)))
            row = existing.get(instance)
            if row is None:
                steps.append(RestCall("PUT", "/interface/bridge/msti",
                                      {"bridge": bridge_name, "identifier": str(instance), "vlan-mapping": mapping}))
            elif parse_vlan_ids(row.get("vlan-mapping")) != vlans:
                steps.append(RestCall("PATCH", f"/interface/bridge/msti/{_row_id(row)}", {"vlan-mapping": mapping}))
        return rest_plan(steps)

    def plan_stp_port(self, session: RestSession, interface: str, instance_or_vlan: int | None, cost: int | None,
                      priority: int | None) -> ChangePlan:
        """CIST: bridge-port ``path-cost``/``priority``; MSTI: ``/interface/bridge/port/mst-override``."""
        interface = self.validate_interface(interface)
        bridge, port = self._bridge_port(session, interface)
        if not instance_or_vlan:
            body = {}
            if cost is not None:
                body["path-cost"] = str(int(cost))
            if priority is not None:
                body["priority"] = str(int(priority))
            return rest_plan([RestCall("PATCH", f"/interface/bridge/port/{_row_id(port)}", body)] if body else [])
        self._msti(session, bridge, instance_or_vlan)
        body = {}
        if cost is not None:
            body["internal-path-cost"] = str(int(cost))
        if priority is not None:
            body["priority"] = str(int(priority))
        if not body:
            return rest_plan([])
        rows = self._list(session, "/interface/bridge/port/mst-override", missing_ok=True) or []
        row = next((item for item in rows if item.get("interface") == interface
                    and _number(item.get("identifier")) == instance_or_vlan), None)
        if row is None:
            return rest_plan([RestCall("PUT", "/interface/bridge/port/mst-override",
                                       {"interface": interface, "identifier": str(instance_or_vlan), **body})])
        return rest_plan([RestCall("PATCH", f"/interface/bridge/port/mst-override/{_row_id(row)}", body)])
