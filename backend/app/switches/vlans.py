"""Vendor-neutral VLAN rules for the VLAN tab.

Drivers only send the VLAN commands (``create_vlan``, ``rename_vlan``,
``delete_vlan``) and report protected VLANs and layer-3 interfaces
(``read_vlan_constraints``). The service checks names, existence, port usage and
protection with these functions before a write and verifies the result with a
fresh VLAN read afterwards. This module must not import drivers.
"""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

from ..i18n import t
from .errors import InvalidInputError
from .validation import parse_vlan_list

NAME_MAX_LENGTH = 32
# One conservative rule for all vendors: no spaces or quotes, so no vendor quoting ambiguity.
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
NAME_RULE = (
    "Ungültiger VLAN-Name: 1–32 Zeichen, erlaubt sind Buchstaben, Ziffern, Punkt, Unterstrich und Bindestrich "
    "(nicht nur Ziffern)."
)

# Delete protection reasons (German message IDs without placeholders).
DEFAULT_REASON = "Standard-VLAN des Switches; kann nicht gelöscht werden."
RESERVED_REASON = "Reserviertes VLAN; kann nicht gelöscht werden."
PRIMARY_REASON = "Primary VLAN des Switches; kann nicht gelöscht werden."
MANAGEMENT_REASON = "Management-VLAN des Switches; kann nicht gelöscht werden."
DYNAMIC_REASON = "Automatisch erzeugtes VLAN (PVID oder VLAN-Interface); kann nicht gelöscht werden."
L3_REASON = "Für dieses VLAN existiert ein Layer-3-Interface; Löschen ist gesperrt."
L3_UNKNOWN_REASON = "Layer-3-Interfaces konnten nicht gelesen werden; Löschen ist gesperrt."
IN_USE_REASON = "Das VLAN wird noch von Ports verwendet: {ports}"
UNREADABLE_REASON = "Die VLAN-Konfiguration von {ports} konnte nicht gelesen werden; Löschen ist gesperrt."
# VTP locks (Cisco; ``status`` is a ``read_vtp`` dict).
VTP_CLIENT_REASON = (
    "VTP-Client: Die VLANs dieses Switches kommen per VTP aus der Domäne {domain}; Änderungen nur am VTP-Server "
    "bzw. Primary Server ({primary})."
)
VTP_SECONDARY_REASON = (
    "VTPv3-Secondary-Server: VLAN-Änderungen nimmt nur der Primary Server an (zuletzt {primary}). "
    "'Primary übernehmen' macht diesen Switch zum Primary Server."
)
VTP_EXTENDED_REASON = (
    "Mit VTP-Version {version} im Modus {mode} sind erweiterte VLANs (1006–4094) nicht möglich; dafür Modus "
    "Transparent/Aus oder VTP-Version 3 verwenden."
)
UNKNOWN_PRIMARY = "unbekannt"

USAGE_KINDS = ("access", "native", "voice", "trunk")
_MAX_LISTED_PORTS = 10
_FULL_RANGE = tuple(range(1, 4095))

_SUCCESS_MESSAGES = {
    ("create", False): "VLAN {vlan} angelegt (noch nicht dauerhaft gespeichert).",
    ("create", True): "VLAN {vlan} angelegt.",
    ("rename", False): "VLAN {vlan} umbenannt (noch nicht dauerhaft gespeichert).",
    ("rename", True): "VLAN {vlan} umbenannt.",
    ("delete", False): "VLAN {vlan} gelöscht (noch nicht dauerhaft gespeichert).",
    ("delete", True): "VLAN {vlan} gelöscht.",
}


@dataclass(frozen=True)
class VlanConstraints:
    """Device facts that block deleting a VLAN.

    ``protected``: VLAN id -> German reason message ID (no placeholders).
    ``l3_interfaces``: VLAN ids with a layer-3 interface; ``None`` = could not be read.
    ``max_vlans``: maximum number of VLANs the device accepts; ``None`` = no known limit.
    """

    protected: Mapping[int, str]
    l3_interfaces: frozenset[int] | None
    max_vlans: int | None = None


def validate_vlan_name(name: str) -> str:
    """Return the stripped name or raise ``InvalidInputError`` (name rule of all drivers)."""
    value = name.strip() if isinstance(name, str) else ""
    if not _NAME_RE.fullmatch(value) or value.isdigit():
        raise InvalidInputError(t(NAME_RULE))
    return value


def _vlan_number(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def vlan_usage(
    switchports: Mapping[str, dict], ports_without_detail: Iterable[str] = (),
) -> tuple[dict[int, dict[str, list[str]]], list[str]]:
    """VLAN id -> usage kind -> ports, and the ports whose VLAN configuration is unreadable.

    Unreadable are ``ports_without_detail`` (ports the driver could not read) and ports whose
    allowed VLAN list cannot be parsed. Trunks allowing ``all`` (or the full 1-4094 range) do not
    count as using a VLAN; explicitly listed trunk VLANs do. Only non-empty kinds are present.
    """
    usage: dict[int, dict[str, list[str]]] = {}
    unreadable: list[str] = list(dict.fromkeys(ports_without_detail))

    def add(vlan, kind: str, port: str) -> None:
        number = _vlan_number(vlan)
        if number is None:
            return
        ports = usage.setdefault(number, {}).setdefault(kind, [])
        if port not in ports:
            ports.append(port)

    for key, detail in switchports.items():
        port = detail.get("interface") or key
        mode = detail.get("mode")
        if mode == "routed":
            continue
        if mode != "trunk":
            add(detail.get("access_vlan"), "access", port)
        if mode != "access":
            add(detail.get("native_vlan"), "native", port)
        add(detail.get("voice_vlan"), "voice", port)
        allowed = detail.get("trunk_allowed_vlan")
        # Not only "trunk": e.g. Cisco DTP ports ("dynamic") may trunk with an explicit allowed list.
        if mode == "access" or allowed is None or not str(allowed).strip():
            continue
        try:
            selection = parse_vlan_list(str(allowed))
        except InvalidInputError:
            if port not in unreadable:
                unreadable.append(port)
            continue
        if isinstance(selection, str) or selection == _FULL_RANGE:
            continue
        for vlan in selection:
            add(vlan, "trunk", port)
    return usage, unreadable


def _ports_text(ports: Iterable[str]) -> str:
    unique = list(dict.fromkeys(ports))
    text = ", ".join(unique[:_MAX_LISTED_PORTS])
    return f"{text} …" if len(unique) > _MAX_LISTED_PORTS else text


def delete_blocker(
    vlan_id: int,
    usage: Mapping[int, Mapping[str, list[str]]],
    unreadable: list[str],
    constraints: VlanConstraints,
) -> str | None:
    """Translated reason why ``vlan_id`` must not be deleted, or ``None``; the first match wins."""
    reason = constraints.protected.get(vlan_id)
    if reason:
        return t(reason)
    if constraints.l3_interfaces is None:
        return t(L3_UNKNOWN_REASON)
    if vlan_id in constraints.l3_interfaces:
        return t(L3_REASON)
    kinds = usage.get(vlan_id) or {}
    ports = [port for kind in USAGE_KINDS for port in kinds.get(kind, ())]
    if ports:
        return t(IN_USE_REASON, ports=_ports_text(ports))
    if unreadable:
        return t(UNREADABLE_REASON, ports=_ports_text(unreadable))
    return None


def describe(
    rows: list[dict], switchports: Mapping[str, dict], constraints: VlanConstraints,
    ports_without_detail: Iterable[str] = (),
) -> list[dict]:
    """``read_vlans`` rows with port usage, layer-3 flag and delete blocker, sorted by id."""
    usage, unreadable = vlan_usage(switchports, ports_without_detail)
    l3 = constraints.l3_interfaces
    result = []
    for row in sorted(rows, key=lambda item: item["id"]):
        kinds = usage.get(row["id"]) or {}
        result.append({
            **row,
            "voice": row.get("voice"),
            "usage": {kind: list(kinds.get(kind, ())) for kind in USAGE_KINDS},
            "l3_interface": None if l3 is None else row["id"] in l3,
            "delete_blocked": delete_blocker(row["id"], usage, unreadable, constraints),
        })
    return result


def success_message(action: Literal["create", "rename", "delete"], vlan_id: int, *, persistent: bool = False) -> str:
    """Success text of an accepted VLAN plan; ``persistent`` for devices without a save step."""
    return t(_SUCCESS_MESSAGES[(action, persistent)], vlan=vlan_id)


def verify(result: dict, rows: list[dict], vlan_id: int, *, present: bool, name: str | None = None) -> dict:
    """Confirm an accepted VLAN write against a fresh ``read_vlans``; failed writes pass through."""
    if not result["ok"]:
        return result
    row = next((item for item in rows if item["id"] == vlan_id), None)
    if present:
        visible = row is not None and (name is None or (row.get("name") or "").strip() == name)
    else:
        visible = row is None
    if visible:
        return result
    return {
        "ok": False,
        "message": t("Der Switch hat keinen Fehler gemeldet, die VLAN-Änderung ist aber nicht sichtbar."),
        "raw": result["raw"],
    }


def _vtp_primary(status: Mapping) -> str:
    return status.get("primary_description") or status.get("primary_id") or t(UNKNOWN_PRIMARY)


def vtp_lock(status: Mapping | None) -> dict | None:
    """Why VLAN create/rename/delete is refused by VTP, and whether 'Primary übernehmen' lifts it."""
    if status is None or status.get("mode") is None:
        return None
    if status["mode"] == "client":
        reason = t(VTP_CLIENT_REASON, domain=status.get("domain") or "–", primary=_vtp_primary(status))
        return {"reason": reason, "takeover": False}
    if status.get("version") == 3 and status["mode"] == "server" and status.get("primary_server") is False:
        return {"reason": t(VTP_SECONDARY_REASON, primary=_vtp_primary(status)), "takeover": True}
    return None


def vtp_create_blocker(status: Mapping | None, vlan_id: int) -> str | None:
    """Lock reason, or why VTP v1/v2 server/client cannot create the extended VLAN ``vlan_id``."""
    lock = vtp_lock(status)
    if lock is not None:
        return lock["reason"]
    if status and status.get("version") in (1, 2) and status.get("mode") in ("server", "client") and vlan_id > 1005:
        return t(VTP_EXTENDED_REASON, version=status["version"], mode=status["mode"].capitalize())
    return None
