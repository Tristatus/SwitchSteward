"""Bounded Catalyst 9800 configuration model (Cisco IOS XE 17.12 YANG).

The paths and types below are taken from Cisco's 17121 published YANG modules:
https://github.com/YangModels/yang/tree/main/vendor/cisco/xe/17121
Only explicitly modelled values leave the parser. Secrets are write-only. The
transport additionally checks the controller's own schemas before any write.
Cloning deliberately derives a new *managed-field template*, not a full copy.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Iterator
from typing import Any

from ..i18n import t
from .models import WlanConfigurationError

NC = "urn:ietf:params:xml:ns:netconf:base:1.0"
PREFIX = "Cisco-IOS-XE-"
WLAN = PREFIX + "wireless-wlan-cfg"
SITE = PREFIX + "wireless-site-cfg"
RF = PREFIX + "wireless-rf-cfg"
AP = PREFIX + "wireless-ap-cfg"
FLEX = PREFIX + "wireless-flex-cfg"
CFG_RPC = PREFIX + "wireless-access-point-cfg-rpc"
CMD_RPC = PREFIX + "wireless-access-point-cmd-rpc"
NATIVE = PREFIX + "native"
BANDS = {"2.4": "dot11-2-dot-4-ghz-band", "5": "dot11-5-ghz-band", "6": "dot11-6-ghz-band"}
RPC_BANDS = {"2.4": "band-2-dot-4-ghz", "5": "band-5-ghz", "6": "band-6-ghz"}
BAND_IDS = {"2.4": 1, "5": 2, "6": 4}
CLONE_HELP = ("Ableitung der hier verwalteten Felder. Weitere Eigenschaften erhalten Geräte-Defaults; "
              "Sicherheit und Schlüssel müssen für das neue WLAN ausdrücklich angegeben werden.")


def ns(module: str) -> str:
    return "http://cisco.com/yang/cisco-ia" if module == "cisco-ia" else "http://cisco.com/ns/yang/" + module


def _f(name: str, label: str, path: str | None = None, kind: str = "string", **kw: Any) -> dict:
    return {"name": name, "label": label, "path": path, "type": kind, **kw}


def _options(*values: str) -> list[dict]:
    return [{"value": value, "label": value} for value in values]


def _ref(name: str, label: str, path: str, collection: str, **kw: Any) -> dict:
    return _f(name, label, path, "reference", reference=collection, **kw)


def _resource(resource: str, label: str, module: str, path: str, key: str, fields: list[dict]) -> dict:
    return {"resource": resource, "label": label, "module": module, "list_path": path,
            "collection": resource + ("es" if resource == "ap_tags" else "s"),
            "key_leaf": key, "key_label": "Ethernet-MAC" if resource == "ap_tags" else "Name",
            "kind": "config", "operations": ["create", "update", "delete", "clone"],
            "fields": fields, "clone_help": CLONE_HELP}


_RESOURCES = [
    _resource("wlan", "WLANs", WLAN, "wlan-cfg-data/wlan-cfg-entries/wlan-cfg-entry", "profile-name", [
        _f("wlan_id", "WLAN-ID", "wlan-id", "integer", required=True, min=1, max=4096, immutable=True),
        _f("ssid", "SSID", "apf-vap-id-data/ssid", required=True, min=1, max=32),
        _f("description", "Beschreibung", "description", max=256),
        _f("broadcast_ssid", "SSID sichtbar", "apf-vap-id-data/broadcast-ssid", "boolean"),
        _f("admin_state", "WLAN aktiviert", "apf-vap-id-data/wlan-status", "boolean"),
        _f("bands", "Funkbänder", None, "multiselect", options=_options("2.4", "5", "6")),
        _f("security", "Sicherheitsvorlage", None, "select", options=_options(
            "wpa2_enterprise", "wpa3_enterprise", "wpa2_personal", "wpa3_personal", "wpa2_wpa3_personal"),
           help="Eine Vorlage setzt AKM, AES, PMF und FT gemeinsam; Enterprise benötigt eine vorhandene AAA-Liste."),
        _ref("authentication_list", "802.1X-Authentifizierungsliste", "authentication-list", "authentication_lists"),
        _f("psk", "Neuer WLAN-Schlüssel", "psk", "password", secret=True, min=8, max=63,
           help="Nur schreibbar; leer lassen behält den vorhandenen Schlüssel. Ableitungen benötigen einen neuen Schlüssel."),
    ]),
    _resource("policy_profile", "Policy-Profile", WLAN, "wlan-cfg-data/wlan-policies/wlan-policy", "policy-profile-name", [
        _f("description", "Beschreibung", "description", max=256),
        _f("admin_state", "Profil aktiviert", "status", "boolean"),
        _ref("interface_name", "VLAN / Interface", "interface-name", "vlans", required=True),
        _f("central_switching", "Zentrales Switching", "wlan-switching-policy/central-switching", "boolean"),
        _f("central_authentication", "Zentrale Authentifizierung", "wlan-switching-policy/central-authentication", "boolean"),
        _f("central_dhcp", "Zentrales DHCP", "wlan-switching-policy/central-dhcp", "boolean"),
        _ref("ipv4_acl", "IPv4-ACL", "wlan-acl/ipv4-acl", "ipv4_acls"),
        _ref("ipv6_acl", "IPv6-ACL", "wlan-acl/ipv6-acl", "ipv6_acls"),
        _ref("ingress_qos", "QoS eingehend (SSID)", "per-ssid-qos/ingress-service-name", "qos_policies", max=80),
        _ref("egress_qos", "QoS ausgehend (SSID)", "per-ssid-qos/egress-service-name", "qos_policies", max=80),
    ]),
    _resource("policy_tag", "Policy-Tags", WLAN, "wlan-cfg-data/policy-list-entries/policy-list-entry", "tag-name", [
        _f("description", "Beschreibung", "description", max=256),
        _f("mappings", "WLAN → Policy-Profil", None, "mappings", max=16,
           references={"wlan_profile": "wlans", "policy_profile": "policy_profiles"}),
    ]),
    _resource("site_tag", "Site-Tags", SITE, "site-cfg-data/site-tag-configs/site-tag-config", "site-tag-name", [
        _f("description", "Beschreibung", "description", max=256),
        _f("is_local_site", "Local-Site (kein FlexConnect)", "is-local-site", "boolean"),
        _ref("ap_join_profile", "AP-Join-Profil", "ap-join-profile", "ap_join_profiles"),
        _ref("flex_profile", "FlexConnect-Profil", "flex-profile", "flex_profiles",
             help="Nur für nicht lokale Sites. Der Site-Wechsel kann einen AP-Rejoin auslösen."),
    ]),
    _resource("rf_tag", "RF-Tags", RF, "rf-cfg-data/rf-tags/rf-tag", "tag-name", [
        _f("description", "Beschreibung", "description", max=256),
        _ref("profile_24", "RF-Profil 2,4 GHz", "dot11b-rf-profile-name", "rf_profiles", band="2.4"),
        _ref("profile_5", "RF-Profil 5 GHz", "dot11a-rf-profile-name", "rf_profiles", band="5"),
        _ref("profile_6", "RF-Profil 6 GHz", "dot11-6ghz-rf-prof-name", "rf_profiles", band="6"),
    ]),
    _resource("rf_profile", "RF-Profile", RF, "rf-cfg-data/rf-profiles/rf-profile", "name", [
        _f("description", "Beschreibung", "description", max=256),
        _f("band", "Funkband", "band", "select", options=_options("2.4", "5", "6"), required=True, immutable=True),
        _f("admin_state", "Profil aktiviert", "status", "boolean"),
        _f("tx_power_min", "TPC-Untergrenze (dBm)", "tx-power-min", "integer", min=-10, max=30),
        _f("tx_power_max", "TPC-Obergrenze (dBm)", "tx-power-max", "integer", min=-10, max=30),
        _f("channel_width", "DCA-Kanalbreite", "rf-dca-chan-width", "select", options=_options("auto", "20", "40", "80", "160")),
        _f("channels", "DCA-Kanäle", None, "integer_list", help="Nur Kanäle, die alle betroffenen Radios unterstützen; bei unbekannter Regulierungsdomäne gesperrt."),
    ]),
    _resource("ap_join_profile", "AP-Join-Profile", SITE, "site-cfg-data/ap-cfg-profiles/ap-cfg-profile", "profile-name", [
        _f("description", "Beschreibung", "description", max=256),
        _f("led_enabled", "AP-LED aktiviert", "led-state/led-state", "boolean"),
        _f("syslog_host", "Syslog-Server", "syslog/host", "ip"),
        _f("syslog_level", "Syslog-Stufe", "syslog/log-level", "select", options=_options(*[
            "syslog-level-" + level for level in ("emergency", "alert", "critical", "errors", "warning", "notification", "information", "debug")
        ])),
        _f("capwap_preferred_mode", "CAPWAP-IP-Protokoll", "tunnel/preferred-mode", "select",
           options=_options("preferred-mode-unconfig", "preferred-mode-ipv4", "preferred-mode-ipv6")),
        _f("heartbeat_timeout", "CAPWAP-Heartbeat (s)", "capwap-timer/heart-beat-timeout", "integer", min=1, max=30),
        _f("discovery_timeout", "Discovery-Timeout (s)", "capwap-timer/discovery-timeout", "integer", min=1, max=10),
        _f("fallback_enabled", "Controller-Fallback", "backup-controllers/fallback-enabled", "boolean"),
        _f("primary_controller_name", "Primärer Backup-Controller: Name", "backup-controllers/primary-controller-name", max=32),
        _f("primary_controller_ip", "Primärer Backup-Controller: IP", "backup-controllers/primary-controller-ip", "ip"),
        _f("secondary_controller_name", "Sekundärer Backup-Controller: Name", "backup-controllers/secondary-controller-name", max=32),
        _f("secondary_controller_ip", "Sekundärer Backup-Controller: IP", "backup-controllers/secondary-controller-ip", "ip"),
    ]),
    _resource("flex_profile", "FlexConnect-Profile", FLEX, "flex-cfg-data/flex-policy-entries/flex-policy-entry", "policy-name", [
        _f("description", "Beschreibung", "description", max=256),
        _f("native_vlan_id", "Native VLAN", "native-vlan-id", "integer", min=1, max=4094),
        _f("vlan_enabled", "VLAN-Tagging", "vlan-enable", "boolean"),
        _f("arp_caching", "ARP-Cache", "arp-caching", "boolean"),
        _f("dhcp_broadcast", "DHCP-Broadcast (Local Switching)", "dhcp-bcast", "boolean"),
        _f("fallback_radio_shutdown", "Radios beim Fallback deaktivieren", "fallback-radio-shut", "boolean"),
        _f("vlan_mappings", "VLAN-Namen → IDs", None, "vlan_mappings"),
    ]),
    _resource("ap_tags", "AP-Tagzuweisung", AP, "ap-cfg-data/ap-tags/ap-tag", "ap-mac", [
        _ref("policy_tag", "Policy-Tag", "policy-tag", "policy_tags"),
        _ref("site_tag", "Site-Tag", "site-tag", "site_tags"),
        _ref("rf_tag", "RF-Tag", "rf-tag", "rf_tags"),
    ]),
]
_RESOURCES[-1]["collection"] = "ap_tags"
_RESOURCES[-1]["operations"] = ["create", "update", "delete"]


def _action(resource: str, label: str, rpc: str, fields: list[dict], module: str = CFG_RPC) -> dict:
    return {"resource": resource, "label": label, "module": module, "rpc_name": rpc,
            "collection": "access_points", "key_label": "AP-Radio-MAC", "kind": "action",
            "operations": ["rpc"], "fields": fields}


_RADIO_FIELDS = [_f("slot_id", "Radio-Slot", None, "integer", required=True, min=0, max=3),
                 _f("band", "Funkband", None, "select", required=True, options=_options("2.4", "5", "6"))]
_MODE = _f("mode", "Steuerung", None, "select", required=True, options=[
    {"value": "auto", "label": "Automatisch / RRM"}, {"value": "static", "label": "Lokaler Override"}])
_RESOURCES += [
    _action("ap_name", "AP umbenennen", "set-ap-name", [_f("name", "AP-Name", None, required=True, min=1, max=32)]),
    _action("ap_location", "AP-Standort", "set-ap-location", [_f("location", "Standort", None, required=True, min=1, max=256)]),
    _action("ap_admin", "AP-Adminstatus", "set-ap-admin-state", [_f("admin_state", "AP aktiviert", None, "boolean", required=True)]),
    _action("ap_mode", "AP-Betriebsmodus", "set-ap-mode", [
        _f("mode", "Betriebsmodus", None, "select", required=True, options=[
            {"value": "site", "label": "Aus Site-Tag übernehmen"},
            {"value": "local-mode", "label": "Local"},
            {"value": "mode-monitor", "label": "Monitor (keine Clients)"},
            {"value": "mode-flex-connect", "label": "FlexConnect"}],
           help="Ein Moduswechsel kann den AP neu verbinden oder neu starten. FlexConnect benötigt einen passenden Site-Tag.")]),
    _action("radio_admin", "Radio-Adminstatus", "set-ap-slot-admin-state", _RADIO_FIELDS + [
        _f("admin_state", "Radio aktiviert", None, "boolean", required=True)]),
    _action("radio_channel", "Radio-Kanal", "set-rad-slot-phy-ht-chan", _RADIO_FIELDS + [_MODE,
        _f("channel", "Kanal", None, "integer", min=1, max=233)]),
    _action("radio_width", "Radio-Kanalbreite", "set-slot-chan-width-label", _RADIO_FIELDS + [
        _f("width", "Kanalbreite", None, "select", required=True, options=_options("auto", "20", "40", "80", "160"),
           help="Automatisch stellt DCA wieder her; die Breite folgt dem RF-Profil.")]),
    _action("radio_power", "Radio-Sendeleistung", "set-ap-slot-tx-power-level", _RADIO_FIELDS + [_MODE,
        _f("power_level", "Leistungsstufe (modellabhängig)", None, "integer", min=1, max=8)]),
    _action("ap_restart", "AP neu starten", "ap-reset", [], CMD_RPC),
    _action("ap_persist_tags", "Tags auf AP speichern", "set-ap-tags", [], CMD_RPC),
    _action("save", "Running-Konfiguration speichern", "save-config", [], "cisco-ia"),
]
REGISTRY = {r["resource"]: r for r in _RESOURCES}
REGISTRY["save"]["key_label"] = "Controller"
# Validated inline for FlexConnect VLAN mappings; labels appear in error messages.
_VLAN_NAME = _f("interface_name", "VLAN-Name", min=1, max=32)
_VLAN_ID = _f("vlan_id", "VLAN-ID", kind="integer", min=1, max=4094)


def catalog() -> list[dict]:
    """GUI descriptors; returning copies prevents accidental global mutations."""
    return copy.deepcopy(_RESOURCES)


def _texts(descriptors: Iterable[dict]) -> Iterator[tuple[dict, str]]:
    """(container, key) slots holding German UI text; options that mirror their value stay technical."""
    for resource in descriptors:
        for key in ("label", "key_label", "clone_help"):
            if isinstance(resource.get(key), str):
                yield resource, key
        for field in resource.get("fields", []):
            for key in ("label", "help"):
                if isinstance(field.get(key), str):
                    yield field, key
            for option in field.get("options", []):
                if isinstance(option.get("label"), str) and option["label"] != option.get("value"):
                    yield option, "label"


def localize_catalog(descriptors: Iterable[dict]) -> list[dict]:
    """Copy of the (German) descriptors translated into the request language."""
    result = copy.deepcopy(list(descriptors))
    for container, key in _texts(result):
        container[key] = t(container[key])
    return result


def catalog_labels() -> set[str]:
    """Every German UI text that localize_catalog() and validation messages pass through t()."""
    return {container[key] for container, key in _texts([*_RESOURCES, {"fields": [_VLAN_NAME, _VLAN_ID]}])}


def _put(parent: ET.Element, module: str, path: str, value: Any = None) -> ET.Element:
    current = parent
    for part in path.split("/"):
        child = current.find(f"{{{ns(module)}}}{part}")
        if child is None:
            child = ET.SubElement(current, f"{{{ns(module)}}}{part}")
        current = child
    if value is not None:
        current.text = str(value).lower() if isinstance(value, bool) else str(value)
    return current


def config_filters() -> dict[str, ET.Element]:
    """Read configuration modules; native reads select names only, never AAA secrets."""
    result = {r["module"]: ET.Element(f"{{{ns(r['module'])}}}{r['list_path'].split('/')[0]}")
              for r in _RESOURCES if r["kind"] == "config"}
    native = ET.Element(f"{{{ns(NATIVE)}}}native")
    aaa = _put(native, NATIVE, "aaa")
    _put(aaa, PREFIX + "aaa", "authentication/dot1x/dot1x-list/name")
    _put(aaa, PREFIX + "aaa", "authentication/dot1x/default")
    acl = _put(native, NATIVE, "ip/access-list")
    _put(acl, PREFIX + "acl", "extended/name")
    _put(acl, PREFIX + "acl", "standard/name")
    ipv6 = _put(native, NATIVE, "ipv6/access-list")
    _put(ipv6, PREFIX + "acl", "named-acl/name")
    _put(_put(native, NATIVE, "policy"), PREFIX + "policy", "policy-map/name")
    vlan = _put(_put(native, NATIVE, "vlan"), PREFIX + "vlan", "vlan-list")
    _put(vlan, PREFIX + "vlan", "id")
    _put(vlan, PREFIX + "vlan", "name")
    result[NATIVE] = native
    return result


def _local(node: ET.Element) -> str:
    return node.tag.rsplit("}", 1)[-1]


def _xml(document: ET.Element | str) -> ET.Element:
    if not isinstance(document, str):
        return document
    if len(document.encode("utf-8")) > 8 * 1024 * 1024 or "\x00" in document or re.search(r"<!\s*(?:DOCTYPE|ENTITY)", document, re.IGNORECASE):
        raise WlanConfigurationError(t("Unzulässige oder zu große Konfigurationsantwort."))
    # Entity declarations are rejected above; no external/resource expansion.
    return ET.fromstring(document)  # noqa: S314


def _at(node: ET.Element, path: str) -> ET.Element | None:
    current = node
    for part in path.split("/"):
        child = next((n for n in current if _local(n) == part), None)
        if child is None:
            return None
        current = child
    return current


def _text(node: ET.Element, path: str) -> str | None:
    child = _at(node, path)
    return child.text or "" if child is not None else None


def _items(node: ET.Element, path: str) -> list[ET.Element]:
    parent_path, _, leaf = path.rpartition("/")
    parent = _at(node, parent_path) if parent_path else node
    return [n for n in parent if _local(n) == leaf] if parent is not None else []


def _convert(field: dict, value: str) -> Any:
    if field["type"] == "boolean":
        return value in ("true", "1")
    if field["type"] == "integer":
        try:
            return int(value)
        except ValueError:
            return None
    if field["name"] == "band":
        return next((key for key, mapped in BANDS.items() if value == mapped), value)
    if field["name"] == "channel_width":
        return "auto" if value == "rf-dca-chan-width-best" else value.removeprefix("rf-dca-chan-width-").removesuffix("-mhz")
    return value


def _security(node: ET.Element) -> str:
    enabled = lambda name: _text(node, name) == "true"  # noqa: E731
    if _text(node, "security-wpa") == "false" or any(enabled(name) for name in (
        "wep-enabled", "webauth-enabled", "wpa1-enabled", "osen", "easy-psk", "mpsk-enable",
    )):
        return "custom"
    wpa2 = _text(node, "wpa2-enabled") != "false"
    wpa3 = enabled("wpa3-enabled")
    if enabled("auth-key-mgmt-sae"):
        return "wpa2_wpa3_personal" if wpa2 and wpa3 else "wpa3_personal" if wpa3 else "custom"
    if enabled("auth-key-mgmt-psk") and wpa2:
        return "wpa2_personal"
    if wpa3 and enabled("auth-key-mgmt-dot1x-sha256"):
        return "wpa3_enterprise"
    if wpa2 and _text(node, "auth-key-mgmt-dot1x") != "false":
        return "wpa2_enterprise"
    return "custom"


def parse_configuration(documents: dict[str, ET.Element | str], operational: dict | None = None) -> dict:
    """Allowlisted public rows plus opaque internal hashes, never raw secrets/XML."""
    collections = {r["collection"]: [] for r in _RESOURCES if r["kind"] == "config"}
    for module, document in documents.items():
        root = _xml(document)
        for resource in (r for r in _RESOURCES if r["kind"] == "config" and r["module"] == module):
            parts = resource["list_path"].split("/")
            container = next((n for n in root.iter() if n.tag == f"{{{ns(module)}}}{parts[0]}"), None)
            if container is None:
                continue
            for node in _items(container, "/".join(parts[1:])):
                key = _text(node, resource["key_leaf"])
                if not key:
                    continue
                if resource["resource"] == "ap_tags":
                    key = key.lower()
                values = {}
                for field in resource["fields"]:
                    if field.get("secret") or not field.get("path"):
                        continue
                    value = _text(node, field["path"])
                    if value is not None:
                        values[field["name"]] = _convert(field, value)
                kind = resource["resource"]
                if kind == "wlan":
                    values["bands"] = [_convert({"name": "band", "type": "select"}, _text(n, "band") or "")
                                       for n in _items(node, "wlan-radio-policies/wlan-radio-policy")]
                    values["security"] = _security(node)
                elif kind == "policy_tag":
                    values["mappings"] = [{"wlan_profile": _text(n, "wlan-profile-name"),
                                           "policy_profile": _text(n, "policy-profile-name")}
                                          for n in _items(node, "wlan-policies/wlan-policy")]
                elif kind == "rf_profile":
                    values["channels"] = [int(_text(n, "channel")) for n in
                                           _items(node, "rf-dca-allowed-channels/rf-dca-allowed-channel")
                                           if (_text(n, "channel") or "").isdigit()]
                elif kind == "flex_profile":
                    values["vlan_mappings"] = [{"interface_name": _text(n, "interface-name"),
                                               "vlan_id": int(_text(n, "vlan-id")) if _text(n, "vlan-id") else None}
                                              for n in _items(node, "if-name-vlan-ids/if-name-vlan-id")]
                row = {"key": key, "values": values, "_revision": hashlib.sha256(ET.tostring(node)).hexdigest()}
                if kind == "policy_tag":
                    row["_rlan_count"] = len(_items(node, "tag-child-rlan-policy-configs/tag-child-rlan-policy-config"))
                collections[resource["collection"]].append(row)
        if module == NATIVE:
            _parse_native(root, collections)
    # Also include references outside the managed fields, e.g. RLAN and tag filters.
    ref_leaves = {"policy-profile-name": "policy_profiles", "wlan-profile-name": "wlans",
                  "policy-tag": "policy_tags", "site-tag": "site_tags", "rf-tag": "rf_tags",
                  "ap-join-profile": "ap_join_profiles", "flex-profile": "flex_profiles",
                  "dot11a-rf-profile-name": "rf_profiles", "dot11b-rf-profile-name": "rf_profiles",
                  "dot11-6ghz-rf-prof-name": "rf_profiles"}
    for module, document in documents.items():
        if module == NATIVE:
            continue
        root = _xml(document)
        for parent in root.iter():
            for child in parent:
                target = ref_leaves.get(_local(child))
                if target and child.text:
                    # Exclude list-key definitions themselves.
                    if (_local(parent), _local(child)) in {("wlan-policy", "policy-profile-name")}:
                        if _text(parent, "wlan-profile-name") is None:
                            continue
                    collections.setdefault("_references", []).append({"collection": target, "key": child.text,
                                                                       "parent": _local(parent)})
    return collections


def _parse_native(root: ET.Element, collections: dict) -> None:
    specs = {"authentication_lists": ("dot1x-list", "name"), "qos_policies": ("policy-map", "name"),
             "ipv4_acls": ("extended", "name"), "ipv6_acls": ("named-acl", "name"), "vlans": ("vlan-list", "id")}
    for collection, (tag, key_leaf) in specs.items():
        values = []
        for node in root.iter():
            if _local(node) != tag and not (collection == "ipv4_acls" and _local(node) == "standard"):
                continue
            key = _text(node, key_leaf)
            if key:
                values.append({"key": key, "values": {"name": _text(node, "name") or key}})
                if collection == "vlans" and _text(node, "name"):
                    values.append({"key": _text(node, "name"), "values": {"vlan_id": int(key)}})
        if collection == "authentication_lists" and any(_local(n) == "dot1x" and _at(n, "default") is not None for n in root.iter()):
            values.append({"key": "default", "values": {"name": "default"}})
        collections[collection] = values


def parse_snapshot(replies: Iterable[ET.Element | str] | dict) -> dict:
    if isinstance(replies, dict):
        return parse_configuration(replies)
    documents = {}
    for reply in replies:
        root = _xml(reply)
        for module in config_filters():
            if any(n.tag.startswith("{" + ns(module) + "}") for n in root.iter()):
                documents[module] = root
    return parse_configuration(documents)


def _error(message: str) -> None:
    raise WlanConfigurationError(message)


def _rows(snapshot: dict, collection: str) -> list[dict]:
    return snapshot.get("collections", {}).get(collection, [])


def _row(snapshot: dict, collection: str, key: str) -> dict | None:
    return next((r for r in _rows(snapshot, collection) if r.get("key") == key), None)


def _mac(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        _error(t("Eine eindeutige MAC-Adresse in Doppelpunktnotation ist erforderlich."))
    return value.lower()


def _check_field(field: dict, value: Any) -> Any:
    kind, name = field["type"], t(field["label"])
    if kind == "boolean":
        if not isinstance(value, bool):
            _error(t("{label}: Wahrheitswert erforderlich.", label=name))
    elif kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            _error(t("{label}: ganze Zahl erforderlich.", label=name))
        if value < field.get("min", -2147483648) or value > field.get("max", 2147483647):
            _error(t("{label}: Wert außerhalb des erlaubten Bereichs.", label=name))
    elif kind in ("multiselect", "integer_list", "mappings", "vlan_mappings"):
        if not isinstance(value, list) or len(value) > field.get("max", 256):
            _error(t("{label}: ungültige Liste.", label=name))
        if kind == "multiselect":
            if any(v not in [o["value"] for o in field["options"]] for v in value) or len(set(value)) != len(value):
                _error(t("{label}: ungültige oder doppelte Auswahl.", label=name))
        if kind == "integer_list":
            if any(isinstance(v, bool) or not isinstance(v, int) or v < 1 or v > 255 for v in value) or len(set(value)) != len(value):
                _error(t("{label}: gültige, eindeutige Kanalnummern erforderlich.", label=name))
    else:
        if not isinstance(value, str) or any(
            ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF or ord(c) in (0xFFFE, 0xFFFF)
            for c in value
        ):
            _error(t("{label}: ungültiger Text.", label=name))
        if len(value) < field.get("min", 0) or len(value) > field.get("max", 256):
            _error(t("{label}: ungültige Länge.", label=name))
        if kind == "select" and value not in [o["value"] for o in field["options"]]:
            _error(t("{label}: ungültige Auswahl.", label=name))
        if kind == "ip":
            try:
                ipaddress.ip_address(value)
            except ValueError:
                _error(t("{label}: gültige IP-Adresse erforderlich.", label=name))
    return value


def _exists(snapshot: dict, collection: str, key: str) -> None:
    if not _row(snapshot, collection, key):
        _error(t("Referenz {key} ist in {collection} nicht nachgewiesen. Konfiguration neu laden.",
                 key=repr(key), collection=collection))


def _band(value: Any) -> str | None:
    normalize = lambda text: str(text).lower().replace("ghz", "").replace(" ", "")  # noqa: E731
    text = normalize(value)
    for band in BANDS:
        if text in (normalize(band), normalize(BANDS[band]), normalize(RPC_BANDS[band])):
            return band
    return None


def find_ap(snapshot: dict, key: str) -> dict:
    ap = next((a for a in snapshot.get("access_points", []) if str(a.get("radio_mac", "")).lower() == key.lower()), None)
    if ap is None:
        _error(t("AP-Radio-MAC ist nicht eindeutig aus aktuellen Gerätedaten nachgewiesen."))
    return ap


def _validate_action(change: dict, snapshot: dict) -> None:
    kind, values = change["resource"], change["values"]
    if kind == "save":
        if change["key"] != "controller":
            _error(t("Speichern betrifft die gesamte Running-Konfiguration; das Ziel muss ausdrücklich der Controller sein."))
        return
    change["key"] = _mac(change["key"])
    ap = find_ap(snapshot, change["key"])
    if kind in ("ap_name", "ap_location"):
        value = values["name" if kind == "ap_name" else "location"]
        if not re.fullmatch(r"[!-~]+" if kind == "ap_name" else r"[ -~]+", value):
            _error(t("AP-Name/Standort erlaubt nur druckbares ASCII; der AP-Name darf keine Leerzeichen enthalten."))
    if kind == "ap_mode" and values["mode"] in ("local-mode", "mode-flex-connect"):
        site = _row(snapshot, "site_tags", ap.get("site_tag", ""))
        if site is None or site["values"].get("is_local_site", True) != (values["mode"] == "local-mode"):
            _error(t("Betriebsmodus und bestehender Site-Tag passen nicht zusammen; zuerst Site-/FlexConnect-Design prüfen."))
    if not kind.startswith("radio_"):
        return
    radio = next((r for r in ap.get("radios", []) if r.get("slot_id", r.get("slot")) == values["slot_id"]), None)
    if radio is None or _band(radio.get("band")) != values["band"]:
        _error(t("Radio-Slot und Funkband stimmen nicht mit den aktuellen AP-Daten überein."))
    band, slot = values["band"], values["slot_id"]
    if kind == "radio_admin" or (kind in ("radio_power", "radio_channel") and values["mode"] == "auto") or (kind == "radio_width" and values["width"] == "auto"):
        if slot not in {"2.4": (0,), "5": (1, 2), "6": (2, 3)}[band]:
            _error(t("Diese Band-/Slot-Kombination ist im angebotenen Cisco-RPC nicht erlaubt."))
    if kind == "radio_channel" and values["mode"] == "static":
        if "channel" not in values or values["channel"] not in radio.get("supported_channels", []):
            _error(t("Der Kanal ist für dieses Radio / diese Regulierungsdomäne nicht nachgewiesen."))
    if kind == "radio_power" and values["mode"] == "static":
        if "power_level" not in values or values["power_level"] not in radio.get("supported_power_levels", []):
            _error(t("Diese Leistungsstufe ist für das konkrete Radio nicht nachgewiesen."))
    if kind == "radio_width" and values["width"] != "auto":
        if band == "2.4" and values["width"] not in ("20", "40"):
            _error(t("2,4 GHz unterstützt diese Kanalbreite nicht."))
        supported = radio.get("supported_channel_widths", [])
        # Never infer hardware capabilities from a universal numeric range.
        if str(values["width"]) not in [str(w) for w in supported] and str(radio.get("channel_width")) != values["width"]:
            _error(t("Die gewünschte Kanalbreite ist für dieses AP-Radio nicht nachgewiesen."))


def validate_change(change: dict, snapshot: dict, aps: Iterable[dict] = ()) -> dict:
    """Validate a bounded requested mutation, immutable keys and dependencies."""
    if not isinstance(change, dict) or set(change) - {"resource", "operation", "key", "values", "source_key"}:
        _error(t("Ungültiger Änderungsauftrag."))
    resource = REGISTRY.get(change.get("resource"))
    if resource is None or change.get("operation") not in resource["operations"]:
        _error(t("Ressource oder Operation wird nicht unterstützt."))
    result = copy.deepcopy(change)
    result.setdefault("values", {})
    result.setdefault("key", "")
    values = result["values"]
    if not isinstance(values, dict):
        _error(t("Änderungswerte müssen ein Objekt sein."))
    fields = {f["name"]: f for f in resource["fields"]}
    if set(values) - set(fields):
        _error(t("Der Änderungsauftrag enthält unbekannte oder nicht bearbeitbare Felder."))
    for name, value in values.items():
        _check_field(fields[name], value)
    if aps:
        snapshot = {**snapshot, "access_points": list(aps)}
    if resource["kind"] == "action":
        for field in fields.values():
            if field.get("required") and field["name"] not in values:
                _error(t("{label} fehlt.", label=t(field["label"])))
        _validate_action(result, snapshot)
        return result
    key, operation, kind = result["key"], result["operation"], result["resource"]
    if kind == "ap_tags":
        result["key"] = key = _mac(key)
        if not any(str(a.get("ethernet_mac", "")).lower() == key for a in snapshot.get("access_points", [])):
            _error(t("AP-Tagzuweisung benötigt eine nachgewiesene Ethernet-MAC; die Radio-MAC genügt nicht."))
    elif not isinstance(key, str) or not re.fullmatch(r"[!-~](?:[ -~]{0,30}[!-~])?", key):
        _error(t("Profil-/Tagname muss 1–32 druckbare ASCII-Zeichen ohne äußere Leerzeichen enthalten."))
    existing = _row(snapshot, resource["collection"], key)
    if operation in ("update", "delete") and existing is None:
        _error(t("Das Zielobjekt existiert nicht mehr. Konfiguration neu laden."))
    if operation in ("create", "clone") and existing is not None:
        _error(t("Unter diesem Namen existiert bereits ein Objekt."))
    if operation == "delete":
        if values:
            _error(t("Löschen darf keine Feldänderungen enthalten."))
        if key.startswith("default"):
            _error(t("Standardprofile und Standardtags können nicht gelöscht werden."))
        _validate_delete(resource, key, snapshot)
        return result
    if operation == "clone":
        source = _row(snapshot, resource["collection"], result.get("source_key", ""))
        if source is None:
            _error(t("Die Ableitungsvorlage existiert nicht."))
        base = {k: v for k, v in source["values"].items() if k in fields and not fields[k].get("secret")}
        if kind == "wlan":
            base.pop("wlan_id", None)
            base.pop("security", None)
        values = result["values"] = {**base, **values}
        for name, value in values.items():
            _check_field(fields[name], value)
    if operation in ("create", "clone"):
        for field in fields.values():
            if field.get("required") and (field["name"] not in values or values[field["name"]] == ""):
                _error(t("{label} fehlt für das neue Objekt.", label=t(field["label"])))
    if operation == "update":
        if not values:
            _error(t("Keine Änderungen angegeben."))
        for name, field in fields.items():
            if field.get("immutable") and name in values and values[name] != existing["values"].get(name):
                _error(t("{label} ist unveränderlich; ein neues Profil ableiten.", label=t(field["label"])))
    effective = {**(existing["values"] if existing else {}), **values}
    for name, field in fields.items():
        value = values.get(name)
        if field.get("reference") and value:
            _exists(snapshot, field["reference"], value)
            if field.get("band") and _row(snapshot, field["reference"], value)["values"].get("band") != field["band"]:
                _error(t("{label}: Das referenzierte Profil hat ein anderes Funkband.", label=t(field["label"])))
    _validate_resource(kind, operation, key, values, effective, existing, snapshot)
    _validate_forwarding_design(result, snapshot)
    return result


def _validate_forwarding_design(change: dict, snapshot: dict) -> None:
    """Local switching follows the actual AP's policy/site/Flex association."""
    kind, key = change["resource"], change["key"]
    if kind not in {"policy_profile", "policy_tag", "site_tag", "flex_profile", "ap_tags"}:
        return
    collection = REGISTRY[kind]["collection"]

    def projected(which: str, name: str) -> dict | None:
        row = _row(snapshot, which, name)
        value = dict(row["values"]) if row else None
        if which == collection and name == key:
            value = {**(value or {}), **change["values"]}
        return value

    for ap in snapshot.get("access_points", []):
        if kind == "ap_tags" and str(ap.get("ethernet_mac", "")).lower() != key:
            continue
        assignment = projected("ap_tags", str(ap.get("ethernet_mac", "")).lower()) or {}
        policy_name = assignment.get("policy_tag") or ap.get("policy_tag", "")
        site_name = assignment.get("site_tag") or ap.get("site_tag", "")
        policy_tag = projected("policy_tags", policy_name) or {}
        site_tag = projected("site_tags", site_name)
        if kind == "policy_tag" and policy_name != key:
            continue
        if kind == "site_tag" and site_name != key:
            continue
        if kind == "flex_profile" and (site_tag or {}).get("flex_profile") != key:
            continue
        for mapping in policy_tag.get("mappings", []):
            profile_name = mapping.get("policy_profile", "")
            if kind == "policy_profile" and profile_name != key:
                continue
            policy = projected("policy_profiles", profile_name) or {}
            if policy.get("central_switching", True) is not False:
                continue
            if site_tag is None or site_tag.get("is_local_site", True):
                _error(t("Local Switching benötigt bei allen betroffenen APs einen nachgewiesenen FlexConnect-Site-Tag."))
            flex = projected("flex_profiles", site_tag.get("flex_profile", ""))
            if flex is None:
                _error(t("Das FlexConnect-Profil eines betroffenen APs ist nicht nachgewiesen."))
            interface = policy.get("interface_name", "")
            if interface and not interface.isdigit() and not any(
                m.get("interface_name") == interface and m.get("vlan_id")
                for m in flex.get("vlan_mappings", [])
            ):
                _error(t("Das benannte VLAN muss im FlexConnect-Profil jedes betroffenen APs einer VLAN-ID zugeordnet sein."))


def _validate_delete(resource: dict, key: str, snapshot: dict) -> None:
    collection = resource["collection"]
    for r in _RESOURCES:
        if r["kind"] != "config":
            continue
        for row in _rows(snapshot, r["collection"]):
            for f in r["fields"]:
                if f.get("reference") == collection and row["values"].get(f["name"]) == key:
                    _error(t("Das Objekt wird von {resource} / {key} verwendet.", resource=t(r["label"]), key=row["key"]))
            for mapping in row["values"].get("mappings", []):
                if (collection == "wlans" and mapping.get("wlan_profile") == key) or (collection == "policy_profiles" and mapping.get("policy_profile") == key):
                    _error(t("Das Objekt wird in einer WLAN-/Policy-Zuordnung verwendet."))
    ap_field = {"policy_tags": "policy_tag", "site_tags": "site_tag", "rf_tags": "rf_tag"}.get(collection)
    if ap_field and any(a.get(ap_field) == key for a in snapshot.get("access_points", [])):
        _error(t("Der Tag wird von mindestens einem AP verwendet."))
    if any(ref.get("collection") == collection and ref.get("key") == key for ref in _rows(snapshot, "_references")):
        _error(t("Das Objekt besitzt weitere Referenzen in der Controllerkonfiguration."))
    if snapshot.get("complete") is False:
        _error(t("Löschen benötigt eine vollständige, aktuelle Referenzübersicht."))


def _validate_resource(kind: str, operation: str, key: str, values: dict, effective: dict,
                       existing: dict | None, snapshot: dict) -> None:
    if kind == "wlan":
        if "ssid" in values and len(values["ssid"].encode("utf-8")) > 32:
            _error(t("Eine SSID darf maximal 32 UTF-8-Bytes belegen."))
        if any(r["key"] != key and r["values"].get("wlan_id") == effective.get("wlan_id") for r in _rows(snapshot, "wlans")):
            _error(t("Die WLAN-ID wird bereits verwendet."))
        security = effective.get("security", "custom")
        if operation in ("create", "clone") and "security" not in values:
            _error(t("Neue WLANs benötigen eine ausdrückliche Sicherheitsvorlage."))
        if "security" in values:
            if "personal" in security and not values.get("psk"):
                _error(t("Eine Personal-Sicherheitsvorlage benötigt einen neu angegebenen WLAN-Schlüssel."))
            if "enterprise" in security and not effective.get("authentication_list"):
                _error(t("Enterprise benötigt eine vorhandene 802.1X-Authentifizierungsliste."))
        if "psk" in values and (not re.fullmatch(r"[ -~]{8,63}", values["psk"]) or "personal" not in security):
            _error(t("WLAN-Schlüssel benötigen 8–63 druckbare ASCII-Zeichen und eine Personal-Vorlage."))
        if "6" in effective.get("bands", []) and "wpa3" not in security:
            _error(t("6 GHz benötigt eine WPA3-Sicherheitsvorlage mit PMF."))
        if effective.get("bands") == ["6"] and security == "wpa2_wpa3_personal":
            _error(t("Ein ausschließliches 6-GHz-WLAN muss WPA2 deaktivieren."))
    elif kind == "policy_tag" and "mappings" in values:
        mappings = values["mappings"]
        if len(mappings) + (existing or {}).get("_rlan_count", 0) > 16:
            _error(t("WLAN- und RLAN-Zuordnungen dürfen zusammen höchstens 16 Einträge enthalten."))
        seen = set()
        for mapping in mappings:
            if not isinstance(mapping, dict) or set(mapping) != {"wlan_profile", "policy_profile"}:
                _error(t("Jede Zuordnung benötigt WLAN-Profil und Policy-Profil."))
            if not all(isinstance(v, str) for v in mapping.values()):
                _error(t("Profilreferenzen müssen Namen sein."))
            if mapping["wlan_profile"] in seen:
                _error(t("Ein WLAN darf im Tag nur einmal zugeordnet sein."))
            seen.add(mapping["wlan_profile"])
            _exists(snapshot, "wlans", mapping["wlan_profile"])
            _exists(snapshot, "policy_profiles", mapping["policy_profile"])
    elif kind == "site_tag":
        if effective.get("is_local_site", True) and values.get("flex_profile"):
            _error(t("Ein Local-Site-Tag darf kein FlexConnect-Profil verwenden."))
        if effective.get("is_local_site") is False and not effective.get("flex_profile"):
            _error(t("Ein FlexConnect-Site-Tag benötigt ein vorhandenes Flex-Profil."))
        if values.get("is_local_site") is True and (existing or {}).get("values", {}).get("flex_profile"):
            values["flex_profile"] = ""
    elif kind == "rf_profile":
        if effective.get("tx_power_min", -10) > effective.get("tx_power_max", 30):
            _error(t("Die minimale Sendeleistung darf die maximale nicht überschreiten."))
        if effective.get("band") == "2.4" and effective.get("channel_width", "auto") not in ("auto", "20", "40"):
            _error(t("Diese Kanalbreite ist für 2,4 GHz nicht geeignet."))
        if values.get("channels"):
            radios = [r for a in snapshot.get("access_points", []) for r in a.get("radios", [])
                      if _band(r.get("band")) == effective.get("band")]
            if not radios or any(not r.get("supported_channels") for r in radios):
                _error(t("Kanalauswahl benötigt bekannte erlaubte Kanäle der Radios in diesem Funkband."))
            if any(not set(values["channels"]).issubset(set(r["supported_channels"])) for r in radios):
                _error(t("Mindestens ein AP unterstützt die gewählte Kanalliste nicht."))
    elif kind == "ap_join_profile":
        for prefix in ("primary", "secondary"):
            address = effective.get(prefix + "_controller_ip")
            if address and not ipaddress.ip_address(address).is_unspecified and not effective.get(prefix + "_controller_name"):
                _error(t("Eine Backup-Controller-IP benötigt den zugehörigen Controllernamen."))
    elif kind == "flex_profile" and "vlan_mappings" in values:
        seen = set()
        for item in values["vlan_mappings"]:
            if not isinstance(item, dict) or set(item) != {"interface_name", "vlan_id"}:
                _error(t("VLAN-Zuordnungen benötigen interface_name und vlan_id."))
            _check_field(_VLAN_NAME, item["interface_name"])
            _check_field(_VLAN_ID, item["vlan_id"])
            if item["interface_name"] in seen:
                _error(t("VLAN-Namen dürfen nur einmal vorkommen."))
            seen.add(item["interface_name"])
    if kind == "policy_profile":
        if values.get("ipv4_acl") in ("preauth_v4", "preauth_v6") or values.get("ipv6_acl") in ("preauth_v4", "preauth_v6"):
            _error(t("Reservierte Preauth-ACLs können nicht als Policy-ACL verwendet werden."))


def _security_values(template: str) -> dict:
    wpa3, personal = "wpa3" in template, "personal" in template
    result = {"security-wpa": True, "wep-enabled": False, "webauth-enabled": False,
              "wpa1-enabled": False, "wpa1-tkip": False, "wpa1-aes": False,
              "wpa2-enabled": "wpa2" in template, "wpa3-enabled": wpa3, "wpa2-aes": True,
              "auth-key-mgmt-dot1x": not personal and not wpa3,
              "auth-key-mgmt-dot1x-sha256": not personal and wpa3,
              "auth-key-mgmt-psk": personal and "wpa2" in template,
              "auth-key-mgmt-sae": personal and wpa3,
              "auth-key-mgmt-cckm": False, "auth-key-mgmt-ft-dot1x": False, "auth-key-mgmt-ft-psk": False,
              "auth-key-mgmt-ft-sae": False, "auth-key-mgmt-psk-sha256": False, "akm-owe": False,
              "rsn-cipher-suite-gcmp128": False, "rsn-cipher-suite-gcmp256": False,
              "rsn-cipher-suite-ccmp256": False, "osen": False, "easy-psk": False, "mpsk-enable": False,
              "ft-mode": "dot11r-disabled", "pmf-options": "apf-vap-pmf-required" if wpa3 else "apf-vap-pmf-optional",
              "sae-pwe-mode": "both-h2e-hnp", "vap-dot11ax-cfg/he-dot11-ax": True}
    return result


def _list_delta(node: ET.Element, module: str, path: str, key_leaf: str,
                before: list[dict], after: list[dict]) -> None:
    parent_path, leaf = path.rsplit("/", 1)
    parent = _put(node, module, parent_path)
    old = {str(row[key_leaf]): row for row in before}
    new = {str(row[key_leaf]): row for row in after}
    for key in old.keys() - new.keys():
        item = ET.SubElement(parent, f"{{{ns(module)}}}{leaf}", {f"{{{NC}}}operation": "delete"})
        _put(item, module, key_leaf, key)
    for row in new.values():
        item = ET.SubElement(parent, f"{{{ns(module)}}}{leaf}", {f"{{{NC}}}operation": "merge"})
        for name, value in row.items():
            _put(item, module, name, value)


def build_edit(change: dict, snapshot: dict) -> ET.Element:
    """Build a minimal, explicit merge/create/delete; never replace unknown subtrees."""
    resource = REGISTRY[change["resource"]]
    module, values = resource["module"], change["values"]
    config = ET.Element(f"{{{NC}}}config")
    item = _put(config, module, resource["list_path"])
    operation = change["operation"]
    item.set(f"{{{NC}}}operation", "create" if operation in ("create", "clone") else "delete" if operation == "delete" else "merge")
    _put(item, module, resource["key_leaf"], change["key"])
    if operation == "delete":
        return config
    old = (_row(snapshot, resource["collection"], change["key"]) or {}).get("values", {})
    for field in resource["fields"]:
        name = field["name"]
        if name not in values or not field.get("path"):
            continue
        value = values[name]
        if name == "band":
            value = BANDS[value]
        elif name == "channel_width":
            value = "rf-dca-chan-width-best" if value == "auto" else "rf-dca-chan-width-" + value + "-mhz"
        # A local site's flex-profile is a YANG when-node and must be removed.
        if resource["resource"] == "site_tag" and name == "flex_profile" and not value:
            if old.get(name):
                _put(item, module, field["path"]).set(f"{{{NC}}}operation", "delete")
        else:
            _put(item, module, field["path"], value)
    kind = resource["resource"]
    if kind == "wlan":
        if "security" in values:
            for path, value in _security_values(values["security"]).items():
                _put(item, module, path, value)
        if "psk" in values:
            _put(item, module, "psk-type", "clear")
            _put(item, module, "psk-key-type", "key-ascii")
        if "bands" in values:
            _list_delta(item, module, "wlan-radio-policies/wlan-radio-policy", "band",
                        [{"band": BANDS[b]} for b in old.get("bands", []) if b in BANDS],
                        [{"band": BANDS[b]} for b in values["bands"]])
    elif kind == "policy_tag" and "mappings" in values:
        convert = lambda entries: [{"wlan-profile-name": e["wlan_profile"], "policy-profile-name": e["policy_profile"]} for e in entries]  # noqa: E731
        _list_delta(item, module, "wlan-policies/wlan-policy", "wlan-profile-name", convert(old.get("mappings", [])), convert(values["mappings"]))
    elif kind == "rf_profile" and "channels" in values:
        _list_delta(item, module, "rf-dca-allowed-channels/rf-dca-allowed-channel", "channel",
                    [{"channel": c} for c in old.get("channels", [])], [{"channel": c} for c in values["channels"]])
    elif kind == "flex_profile" and "vlan_mappings" in values:
        convert = lambda entries: [{"interface-name": e["interface_name"], "vlan-id": e["vlan_id"]} for e in entries]  # noqa: E731
        _list_delta(item, module, "if-name-vlan-ids/if-name-vlan-id", "interface-name", convert(old.get("vlan_mappings", [])), convert(values["vlan_mappings"]))
    elif kind == "site_tag" and values.get("is_local_site") is True and old.get("flex_profile") and "flex_profile" not in values:
        _put(item, module, "flex-profile").set(f"{{{NC}}}operation", "delete")
    return config


def build_rpc(change: dict, ap: dict | None = None) -> ET.Element:
    resource = REGISTRY[change["resource"]]
    kind, values = change["resource"], change["values"]
    rpc_name, payload = resource["rpc_name"], {}
    if kind == "ap_name":
        payload["name"] = values["name"]
    elif kind == "ap_location":
        payload["location"] = values["location"]
    elif kind in ("ap_admin", "radio_admin"):
        payload["mode"] = "admin-state-enabled" if values["admin_state"] else "admin-state-disabled"
    elif kind == "ap_mode":
        payload["clear-mode"] = values["mode"] == "site"
        if values["mode"] != "site":
            payload["mode"] = values["mode"]
    if kind.startswith("radio_"):
        payload["slot-id"] = values["slot_id"]
        payload["band"] = BAND_IDS[values["band"]] if kind in ("radio_admin", "radio_power") else RPC_BANDS[values["band"]]
        if kind == "radio_channel":
            if values["mode"] == "auto":
                rpc_name = "set-ap-slot-phy-ht-customize"
            else:
                payload["band"] = BAND_IDS[values["band"]]
                payload["chan"] = values["channel"]
        elif kind == "radio_width":
            if values["width"] == "auto":
                rpc_name = "set-ap-slot-phy-ht-customize"
            else:
                payload["chan-width"] = "chan-width-" + values["width"] + "mhz"
        elif kind == "radio_power":
            if values["mode"] == "auto":
                rpc_name = "set-ap-slot-tx-power-customize"
                payload["mode"] = "config-auto"
            else:
                payload["tx-power-level"] = values["power_level"]
    rpc = ET.Element(f"{{{ns(resource['module'])}}}{rpc_name}")
    if kind != "save":
        payload["mac-addr"] = change["key"]
    for name, value in payload.items():
        _put(rpc, resource["module"], name, value)
    return rpc


def build_change(change: dict, snapshot: dict) -> dict:
    normalized = validate_change(change, snapshot)
    if REGISTRY[normalized["resource"]]["kind"] == "config":
        return {"config": build_edit(normalized, snapshot), "operations": [], "change": normalized}
    return {"config": None, "operations": [build_rpc(normalized)], "change": normalized}


def revision_for_change(snapshot: dict, change: dict) -> str:
    """Include object, references and relevant AP identity, excluding volatile counters."""
    resource = REGISTRY[change["resource"]]
    if resource["kind"] == "config":
        baseline = {"object": _row(snapshot, resource["collection"], change.get("key", "")),
                    "source": _row(snapshot, resource["collection"], change.get("source_key", "")),
                    "references": snapshot.get("collections", {})}
    else:
        baseline = {"collections": snapshot.get("collections", {})} if change["resource"] == "save" else {
            "ap": {k: v for k, v in find_ap(snapshot, change["key"]).items()
                   if k in ("radio_mac", "ethernet_mac", "name", "location", "policy_tag", "site_tag", "rf_tag", "admin_state", "mode")},
            "radios": [{k: v for k, v in r.items() if k in ("slot_id", "band", "admin_state", "channel_mode", "power_mode", "power_level", "channel_width", "channel", "supported_channels", "supported_power_levels")}
                       for r in find_ap(snapshot, change["key"]).get("radios", [])]}
    return hashlib.sha256(json.dumps(baseline, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
