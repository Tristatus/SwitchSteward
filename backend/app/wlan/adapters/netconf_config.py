"""Guarded Catalyst configuration workflow, separate from monitoring collection.

Raw configuration and schemas are local to a request. Only an allowlisted
catalogue projection and a keyed revision digest leave this module. No mutation
is retried, including operational actions whose replies may be lost during rejoin.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import time
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from typing import Any

from ...config import settings
from ...i18n import t
from .. import config_catalog
from ..models import WlanAuthenticationError, WlanCapabilityError, WlanError, utc_timestamp
from .catalyst_9800 import AP_MODULE, AP_SUBTREES, _normalise_access_points, _normalise_mac
from .catalyst_9800_netconf import (
    AP_ROOT,
    CISCO_NAMESPACE_PREFIX,
    NETCONF_BASE_NAMESPACE,
    WlanWriteConflict,
    WlanWriteOutcomeUnknown,
    WlanWriteRejected,
    _local_name,
    _xml_value,
)

logger = logging.getLogger("switchsteward.wlan.netconf_config")
_REVISION_KEY = (
    getattr(settings, "session_secret_key", None)
    or getattr(settings, "secret_key", None)
    or secrets.token_hex(32)
).encode()
_DEVICE_MODULE = "Cisco-IOS-XE-device-hardware-oper"
_AP_RPC_MODULE = "Cisco-IOS-XE-wireless-access-point-cfg-rpc"
_AP_CMD_MODULE = "Cisco-IOS-XE-wireless-access-point-cmd-rpc"
_AP_TYPES_MODULE = "Cisco-IOS-XE-wireless-ap-types"
_AP_RESOURCES = frozenset({
    "ap_name", "ap_location", "ap_admin", "ap_mode", "radio_admin", "radio_channel",
    "radio_width", "radio_power", "ap_restart", "ap_persist_tags",
})
_ACK_ONLY_RESOURCES = frozenset({"ap_restart", "ap_persist_tags"})


def _first(record: Any, *names: str) -> Any:
    if isinstance(record, Mapping):
        for name in names:
            if name in record:
                return record[name]
        for value in record.values():
            found = _first(value, *names)
            if found is not None:
                return found
    elif isinstance(record, list):
        for value in record:
            found = _first(value, *names)
            if found is not None:
                return found
    return None


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None and not isinstance(value, bool) else None
    except (TypeError, ValueError):
        return None


def _admin_state(value: Any) -> bool | None:
    value = str(value or "").rsplit(":", 1)[-1]
    if value in {"enabled", "adminstate-enabled", "true"}:
        return True
    if value in {"disabled", "adminstate-disabled", "false"}:
        return False
    return None


def _config_mode(value: Any) -> str | None:
    value = str(value or "").rsplit(":", 1)[-1]
    if value in {"config-auto", "auto"}:
        return "auto"
    if value in {"config-static", "config-custom", "static", "custom", "customized"}:
        return "static"
    return None


def _records(value: Any) -> list[dict]:
    if isinstance(value, dict):
        return [value]
    return [item for item in (value or []) if isinstance(item, dict)]


def _supported_widths(current: Any) -> list[str]:
    # Cisco's 17.12 RRM guide defines bonded width limits cumulatively (an
    # 80-MHz limit allows 20/40/80). A currently operating bonded channel proves
    # only its own width and narrower constituent channels, never larger ones.
    # https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-12/config-guide/b_wl_17_12_cg/m_rrm_c9800.html
    if current not in {20, 40, 80, 160}:
        return []
    return [str(width) for width in (20, 40, 80, 160) if width <= current]


def _enrich_access_points(payload: dict) -> list[dict]:
    """Preserve explicit MAC semantics and the radio's reported capabilities."""

    access_points = _normalise_access_points(payload).items
    root = payload.get(AP_ROOT, {})
    by_radio = {item["mac"]: item for item in access_points if item.get("mac")}
    for item in access_points:
        item.update(radio_mac=None, ethernet_mac=None, admin_state=None)
    for record in _records(root.get("capwap-data")):
        radio_mac = _normalise_mac(record.get("wtp-mac"))
        if radio_mac in by_radio:
            by_radio[radio_mac]["radio_mac"] = radio_mac
            by_radio[radio_mac]["admin_state"] = _admin_state(_first(record, "ap-admin-state"))
            by_radio[radio_mac]["mode"] = "site" if _first(record, "clear-mode") == "true" else _first(record, "wtp-mode")
            by_radio[radio_mac]["effective_mode"] = _first(record, "wtp-mode")
    for record in _records(root.get("ethernet-mac-wtp-mac-map")):
        radio_mac = _normalise_mac(record.get("wtp-mac"))
        ethernet_mac = _normalise_mac(record.get("ethernet-mac"))
        if radio_mac in by_radio and ethernet_mac:
            by_radio[radio_mac]["ethernet_mac"] = ethernet_mac
    for record in _records(root.get("radio-oper-data")):
        item = by_radio.get(_normalise_mac(record.get("wtp-mac")))
        slot = _integer(record.get("radio-slot-id", record.get("slot-id")))
        if not item or slot is None:
            continue
        radio = next((radio for radio in item["radios"] if radio.get("slot") == slot), None)
        if radio is None:
            continue
        active_band = _first(record, "current-active-band")
        radio_type = _first(record, "radio-type")
        # current-band-id=1 does not identify 6 GHz reliably on all IOS versions.
        if radio_type == "radio-80211-6ghz":
            active_band = "dot11-6-ghz-band"
        elif not active_band:
            active_band = {"radio-80211bg": "dot11-2-dot-4-ghz-band", "radio-80211a": "dot11-5-ghz-band"}.get(radio_type)
        if active_band:
            radio["band"] = active_band
        channel_entries = _records(_first(record.get("chan-pwr-info", {}), "chan-pwr"))
        channels = sorted({value for entry in channel_entries if (value := _integer(entry.get("chan"))) is not None})
        if record.get("reg-domain-check-status") == "regulatory-domain-check-status-not-set":
            channels = []
        band_records = _records(record.get("radio-band-info"))
        if band_records:
            current_band_id = _integer(record.get("current-band-id"))
            active_band_info = next((item for item in band_records if current_band_id is not None and _integer(item.get("band-id")) == current_band_id), {})
        else:
            active_band_info = record
        levels = _integer(_first(active_band_info, "num-supp-power-levels"))
        radio.update(
            admin_state=_admin_state(record.get("admin-state")),
            channel_mode=_config_mode(_first(record, "phy-ht-cfg-config-type")),
            power_mode=_config_mode(_first(active_band_info, "phy-tx-power-config-type")),
            power_level=_integer(_first(active_band_info, "current-tx-power-level")),
            power_dbm=_integer(_first(active_band_info, "curr-tx-power-in-dbm")),
            regulatory_domain=_first(active_band_info, "regulatory-domain"),
            supported_channels=channels,
            supported_power_levels=list(range(1, min(levels, 8) + 1)) if levels and levels > 0 else [],
            slot_id=slot,
            supported_channel_widths=_supported_widths(radio.get("channel_width")),
        )
    return access_points


def _stable_ap_configuration(access_points: list[dict]) -> list[dict]:
    result = []
    for ap in access_points:
        item = {key: ap.get(key) for key in (
            "radio_mac", "ethernet_mac", "name", "location", "policy_tag", "site_tag", "rf_tag", "admin_state", "mode",
        )}
        item["radios"] = []
        for radio in ap.get("radios", []):
            stable = {key: radio.get(key) for key in ("slot", "band", "admin_state", "channel_mode", "power_mode")}
            # RRM can alter channel, width and power between preview and apply.
            # Explicit local overrides, however, are part of the baseline.
            if radio.get("channel_mode") == "static":
                stable.update(channel=radio.get("channel"), channel_width=radio.get("channel_width"))
            if radio.get("power_mode") == "static":
                stable["power_level"] = radio.get("power_level")
            item["radios"].append(stable)
        item["radios"].sort(key=lambda value: str(value.get("slot")))
        result.append(item)
    return sorted(result, key=lambda value: str(value.get("radio_mac")))


def _canonical_element(element: ET.Element) -> Any:
    # XML namespace prefixes and server ordering must not cause false conflicts.
    return [
        element.tag, (element.text or "").strip(), sorted(element.attrib.items()),
        sorted((_canonical_element(child) for child in element), key=lambda child: json.dumps(child, sort_keys=True)),
    ]


def _revision(documents: dict[str, ET.Element], access_points: list[dict]) -> str:
    baseline = {
        "config": {module: _canonical_element(document) for module, document in documents.items()},
        "access_points": _stable_ap_configuration(access_points),
    }
    payload = json.dumps(baseline, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hmac.new(_REVISION_KEY, payload, hashlib.sha256).hexdigest()


def _device_filter() -> ET.Element:
    namespace = f"{CISCO_NAMESPACE_PREFIX}{_DEVICE_MODULE}"
    root = ET.Element(f"{{{namespace}}}device-hardware-data")
    hardware = ET.SubElement(root, f"{{{namespace}}}device-hardware")
    system = ET.SubElement(hardware, f"{{{namespace}}}device-system-data")
    ET.SubElement(system, f"{{{namespace}}}software-version")
    inventory = ET.SubElement(hardware, f"{{{namespace}}}device-inventory")
    for name in ("hw-type", "part-number", "serial-number", "hw-description"):
        ET.SubElement(inventory, f"{{{namespace}}}{name}")
    return root


def _read_device(session: Any, modules: dict, warnings: list[str]) -> dict:
    if _DEVICE_MODULE not in modules:
        return {}
    try:
        data = _xml_value(session.get(_device_filter()))
    except WlanError:
        warnings.append(t("Modell und Softwareversion konnten nicht gelesen werden."))
        return {}
    inventories = _records(_first(data, "device-inventory"))
    chassis = next((item for item in inventories if "chassis" in str(item.get("hw-type", ""))), {})
    if not chassis:
        chassis = next((item for item in inventories if str(item.get("part-number", "")).startswith("C9800")), {})
    version = _first(data, "software-version")
    match = re.search(r"\bVersion\s+([^,\s]+)", version or "")
    version = match.group(1) if match else version
    return {
        "model": chassis.get("part-number"),
        "serial_number": chassis.get("serial-number"),
        "software_version": version,
        "version": version,
    }


def _schema_name(descriptor: dict) -> str | None:
    return descriptor.get("module") or descriptor.get("yang_module")


def _read_schema(adapter: Any, session: Any, module: str, revision: str | None) -> str:
    """Bounded five-minute schema cache; never caches a configuration baseline."""

    key = (session.endpoint, tuple(sorted(session.capabilities)), module, revision)
    now = time.monotonic()
    if revision and session.endpoint:
        with adapter._schema_cache_lock:
            cached = adapter._schema_cache.get(key)
            if cached and now - cached[0] < 300:
                return cached[1]
    schema = session.get_schema(module, revision)
    if revision and session.endpoint:
        with adapter._schema_cache_lock:
            if len(adapter._schema_cache) >= 128:
                oldest = min(adapter._schema_cache, key=lambda entry: adapter._schema_cache[entry][0])
                del adapter._schema_cache[oldest]
            adapter._schema_cache[key] = (now, schema)
    return schema


def _module_write_reason(module: str, schema: str, metadata: dict) -> str | None:
    if metadata.get("conformance") == "import":
        return t("Das Modul wird nur als Schemaimport angeboten, nicht als implementierte Konfiguration.")
    if metadata.get("deviations"):
        return t("Das Gerät meldet Modellabweichungen; diese Ressource ist bis zur Prüfung nur lesbar.")
    features = set(metadata.get("features", []))
    for condition in re.findall(r'\bif-feature\s+(?:"([^";]+)"|([A-Za-z0-9_.:-]+))\s*;', schema):
        expression = condition[0] or condition[1]
        if expression not in features:
            return t("Optionale Schemafunktionen sind für dieses Modul nicht vollständig nachgewiesen.")
    return None


def _read_configuration(adapter: Any, session: Any) -> tuple[dict, dict[str, str]]:
    modules = adapter._discover_modules(session)
    warnings: list[str] = []
    documents: dict[str, ET.Element] = {}
    failures: dict[str, str] = {}
    for module, filter_node in config_catalog.config_filters().items():
        if module not in modules:
            failures[module] = t("Das benötigte YANG-Modul fehlt auf diesem Controller.")
            continue
        try:
            documents[module] = session.get_config(filter_node)
        except (WlanCapabilityError, WlanAuthenticationError):
            failures[module] = t("Die Konfiguration ist mit diesem Konto nicht lesbar.")
            warnings.append(t("Das Konfigurationsmodul {module} konnte nicht gelesen werden.", module=module))
    descriptors = config_catalog.catalog()
    schemas: dict[str, str] = {}
    schema_modules = {_schema_name(descriptor) for descriptor in descriptors}
    schema_modules.update({_AP_RPC_MODULE, _AP_CMD_MODULE, "cisco-ia"})
    if "Cisco-IOS-XE-wireless-site-cfg" in schema_modules:
        schema_modules.add(_AP_TYPES_MODULE)
    for module in sorted(value for value in schema_modules if value and value in modules):
        try:
            schemas[module] = _read_schema(adapter, session, module, modules[module])
        except (WlanCapabilityError, WlanAuthenticationError):
            warnings.append(
                t("Das Geräteschema {module} konnte nicht geprüft werden; Bearbeitung ist gesperrt.", module=module)
            )
    access_points: list[dict] = []
    ap_complete = False
    if AP_MODULE in modules:
        try:
            subtrees = (*AP_SUBTREES, ("ethernet-mac-wtp-mac-map", False))
            payload, ap_warnings, ap_complete = adapter._read_subtrees(session, modules, AP_MODULE, AP_ROOT, subtrees)
            access_points = _enrich_access_points(payload)
            warnings.extend(ap_warnings)
        except (WlanCapabilityError, WlanAuthenticationError):
            warnings.append(t("Die aktuellen AP-Werte konnten nicht gelesen werden; AP-Aktionen sind gesperrt."))
    capabilities = {
        "netconf": True,
        "writable_running": session.supports("writable-running"),
        "candidate": session.supports("candidate"),
        "confirmed_commit": session.supports("confirmed-commit"),
        "rollback_on_error": session.supports("rollback-on-error"),
        "validate": session.supports("validate"),
        "startup": session.supports("startup"),
        "modules": modules,
        "module_metadata": getattr(session, "module_metadata", {}),
        "schemas": {module: {"available": module in schemas, "revision": modules.get(module)} for module in sorted(value for value in schema_modules if value)},
        "supported_resources": [],
        "resource_reasons": {},
        "write_permissions": "unverified",
    }
    for descriptor in descriptors:
        resource = descriptor.get("resource", descriptor.get("name"))
        module = _schema_name(descriptor)
        reason = None
        if module not in modules:
            reason = t("Das benötigte YANG-Modul wird nicht angeboten.")
        elif module not in schemas:
            reason = t("Das aktuelle Geräteschema konnte nicht geprüft werden.")
        elif resource == "ap_join_profile" and _AP_TYPES_MODULE not in schemas:
            reason = t("Das vom AP-Join-Profil verwendete AP-Typschema konnte nicht geprüft werden.")
        elif _module_write_reason(module, schemas[module], getattr(session, "module_metadata", {}).get(module, {})):
            reason = _module_write_reason(module, schemas[module], getattr(session, "module_metadata", {}).get(module, {}))
        elif resource in _AP_RESOURCES:
            if not access_points:
                reason = t("Keine eindeutig identifizierbaren aktuellen Access Points verfügbar.")
        elif resource != "save":
            reason = failures.get(module)
            if not reason and not capabilities["writable_running"]:
                reason = t("Der Controller bietet keinen beschreibbaren Running-Datastore an.")
            if not reason and not capabilities["rollback_on_error"]:
                reason = t("Der Controller bietet kein rollback-on-error für sichere Änderungen an.")
        rpc_name = descriptor.get("rpc_name")
        if not reason and rpc_name and not re.search(r"\brpc\s+" + re.escape(rpc_name) + r"\s*\{", schemas[module]):
            reason = t("Der benötigte RPC ist im aktuellen Geräteschema nicht enthalten.")
        if reason:
            capabilities["resource_reasons"][resource] = reason
        else:
            capabilities["supported_resources"].append(resource)
    collections = config_catalog.parse_configuration(documents)
    snapshot = {
        "capabilities": capabilities,
        "device": _read_device(session, modules, warnings),
        "collections": collections,
        "catalog": descriptors,
        "access_points": access_points,
        "warnings": warnings,
        "complete": not failures and ap_complete,
        "revision": _revision(documents, access_points),
        "collected_at": utc_timestamp(),
    }
    return snapshot, schemas


def read_configuration(adapter: Any, session: Any) -> dict:
    snapshot, _ = _read_configuration(adapter, session)
    return snapshot


def _check_schema_operation(operation: ET.Element, schemas: dict[str, str]) -> None:
    namespace = operation.tag.split("}", 1)[0].lstrip("{")
    module = "cisco-ia" if namespace == "http://cisco.com/yang/cisco-ia" else namespace.removeprefix(CISCO_NAMESPACE_PREFIX)
    schema = schemas.get(module, "")
    if not re.search(r"\brpc\s+" + re.escape(_local_name(operation.tag)) + r"\s*\{", schema):
        raise WlanCapabilityError(t("Die Aktion ist im aktuellen Geräteschema nicht nachgewiesen."))


def _check_schema_config(config: ET.Element, schemas: dict[str, str]) -> None:
    for element in config.iter():
        if element.tag == f"{{{NETCONF_BASE_NAMESPACE}}}config":
            continue
        namespace = element.tag.split("}", 1)[0].lstrip("{")
        module = namespace.removeprefix(CISCO_NAMESPACE_PREFIX)
        schema = schemas.get(module, "")
        if re.search(r"\bimport\s+" + re.escape(_AP_TYPES_MODULE) + r"\s*\{", schema):
            schema += "\n" + schemas.get(_AP_TYPES_MODULE, "")
        declaration = r"\b(?:container|list|leaf|leaf-list)\s+" + re.escape(_local_name(element.tag)) + r"\s*(?:\{|;)"
        if not re.search(declaration, schema):
            raise WlanCapabilityError(
                t("Ein angefordertes Konfigurationsfeld ist im aktuellen Geräteschema nicht nachgewiesen.")
            )


def _save_reply(reply: ET.Element) -> None:
    result = reply.find("{http://cisco.com/yang/cisco-ia}result")
    text = " ".join((result.text or "").split()).casefold() if result is not None else ""
    # The model defines a free-form string, not a boolean. Never infer success
    # merely from the presence of rpc-reply, nor echo arbitrary device messages.
    if text in {"startup config saved successfully", "startup config saved successfully."}:
        return
    if any(word in text for word in ("failed", "error", "denied")):
        raise WlanWriteRejected(t("Der Controller hat das dauerhafte Speichern abgelehnt."))
    raise WlanWriteOutcomeUnknown(
        t("Das Ergebnis des dauerhaften Speicherns konnte nicht eindeutig bestätigt werden.")
    )


def _values_match(change: dict, snapshot: dict) -> bool:
    resource = change["resource"]
    values = change.get("values", {})
    key = change.get("key")
    if resource in _AP_RESOURCES:
        ap = next((ap for ap in snapshot.get("access_points", []) if ap.get("radio_mac") == key), None)
        if not ap or resource in _ACK_ONLY_RESOURCES:
            return False
        if resource.startswith("radio_"):
            radio = next((radio for radio in ap.get("radios", []) if radio.get("slot") == values.get("slot_id")), None)
            if not radio:
                return False
            if resource == "radio_channel":
                return radio.get("channel_mode") == values.get("mode") and (values.get("mode") == "auto" or radio.get("channel") == values.get("channel"))
            if resource == "radio_power":
                return radio.get("power_mode") == values.get("mode") and (values.get("mode") == "auto" or radio.get("power_level") == values.get("power_level"))
            if resource == "radio_width":
                if values.get("width") == "auto":
                    return radio.get("channel_mode") == "auto"
                return str(radio.get("channel_width")) == str(values.get("width"))
            return radio.get("admin_state") == values.get("admin_state")
        field = {"ap_name": "name", "ap_location": "location", "ap_admin": "admin_state", "ap_mode": "mode"}.get(resource)
        return bool(field) and ap.get(field) == values.get(field)
    descriptor = next((item for item in config_catalog.catalog() if item.get("resource") == resource), {})
    collection_name = descriptor.get("collection") or resource + "s"
    entry = next((item for item in snapshot.get("collections", {}).get(collection_name, []) if item.get("key") == key), None)
    if change.get("operation") == "delete":
        return entry is None
    if not entry:
        return False
    actual = entry.get("values", {})
    # Secret material is intentionally redacted by the catalogue. A successful
    # edit is acknowledged, but cannot claim a verified secret from masked data.
    for name, expected in values.items():
        if expected is None and name not in actual:
            continue
        if resource == "site_tag" and name == "flex_profile" and expected == "" and name not in actual and actual.get("is_local_site") is True:
            continue
        if name not in actual or _comparison_value(actual[name]) != _comparison_value(expected):
            return False
    return True


def _comparison_value(value: Any) -> Any:
    if isinstance(value, list):
        return sorted((_comparison_value(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, dict):
        return {key: _comparison_value(item) for key, item in value.items()}
    return value


def _only_secret_unverified(change: dict, snapshot: dict) -> bool:
    descriptor = next((item for item in config_catalog.catalog() if item.get("resource") == change["resource"]), {})
    secret_fields = {field["name"] for field in descriptor.get("fields", []) if field.get("secret")}
    if not secret_fields.intersection(change.get("values", {})):
        return False
    public_change = {**change, "values": {key: value for key, value in change.get("values", {}).items() if key not in secret_fields}}
    return _values_match(public_change, snapshot)


def read_back_unknown(adapter: Any, controller: dict, credentials: dict, change: dict, result: dict) -> dict:
    """Read once in a fresh session after an uncertain write; never resend it.

    The original session may still contain a late, mismatched reply, so reusing
    it is unsafe. A matching value proves observed state, not causality or that
    the original operation completed. Saving cannot be inferred from running.
    """

    result = {**result, "verified": False, "verification": "unavailable"}
    if change.get("resource") == "save":
        return result
    try:
        with adapter._session(controller, credentials) as read_session:
            snapshot = read_configuration(adapter, read_session)
    except WlanError:
        return result
    if change.get("resource") in _ACK_ONLY_RESOURCES:
        result["verification"] = "observed_after_unknown"
        result["message"] = t(
            "{message} Die aktuellen AP-Werte wurden erneut gelesen; der Aktionsabschluss bleibt unbestätigt.",
            message=result["message"],
        )
    elif _values_match(change, snapshot):
        result["verification"] = "matched_after_unknown"
        result["message"] = t(
            "{message} Die gewünschten Werte sind jetzt am Gerät sichtbar; "
            "die ursprüngliche Ausführung bleibt unbestätigt.",
            message=result["message"],
        )
    else:
        result["verification"] = "different_after_unknown" if snapshot.get("complete") else "incomplete_after_unknown"
        result["message"] = t(
            "{message} Die erneut gelesenen Gerätewerte bestätigen die Änderung nicht vollständig.",
            message=result["message"],
        )
    return result


def apply_configuration(adapter: Any, session: Any, change: dict, expected_revision: str) -> dict:
    resource = change.get("resource")
    is_edit = resource not in _AP_RESOURCES and resource != "save"
    locked = False
    result: dict | None = None
    try:
        if is_edit:
            session.lock()
            locked = True
        before, schemas = _read_configuration(adapter, session)
        if not expected_revision or not hmac.compare_digest(before["revision"], expected_revision):
            raise WlanWriteConflict(
                t("Die Gerätekonfiguration hat sich seit der Vorschau geändert. Vorschau neu erstellen.")
            )
        if resource not in before["capabilities"]["supported_resources"]:
            raise WlanCapabilityError(
                before["capabilities"]["resource_reasons"].get(resource, t("Diese Funktion wird nicht unterstützt."))
            )
        plan = config_catalog.build_change(change, before)
        normalized = plan.get("change", change)
        config = plan.get("config")
        operations = plan.get("operations", [])
        if config is not None:
            if not is_edit or operations:
                raise WlanWriteRejected(
                    t("Konfigurationsänderung und Betriebsaktion müssen getrennt ausgeführt werden.")
                )
            _check_schema_config(config, schemas)
            session.edit_config(config)
        else:
            if len(operations) != 1:
                raise WlanWriteRejected(t("Eine Vorschau darf genau eine Betriebsaktion ausführen."))
            operation = operations[0]
            _check_schema_operation(operation, schemas)
            reply = session.action(operation)
            if resource == "save":
                _save_reply(reply)
            else:
                session._require_ok(reply)
        result = {
            "status": "applied", "message": t("Die Änderung wurde vom Controller bestätigt."),
            "verified": False, "verification": "pending",
            "persistence": "saved" if resource == "save" else "unsaved",
        }
        if resource == "save":
            result.update(
                verified=True, verification="acknowledged",
                message=t("Die gesamte Running-Konfiguration wurde dauerhaft gespeichert."),
            )
        else:
            try:
                after, _ = _read_configuration(adapter, session)
                result["verified"] = _values_match(normalized, after)
                result["verification"] = "matched" if result["verified"] else "pending"
                result["revision"] = after["revision"]
                if resource in _ACK_ONLY_RESOURCES:
                    result["message"] = t(
                        "Die Betriebsaktion wurde bestätigt. Abschluss und Persistenz am AP erneut prüfen."
                    )
                    result["persistence"] = "unknown"
                elif not result["verified"]:
                    if _only_secret_unverified(normalized, after):
                        result["verification"] = "secret_unverifiable"
                        result["message"] = t(
                            "Die Änderung und die lesbaren Werte wurden bestätigt. "
                            "Geheime Schlüssel sind nicht rücklesbar."
                        )
                    else:
                        result["status"] = "partial"
                        result["verification"] = "mismatch"
                        result["message"] = t(
                            "Die Änderung wurde bestätigt, aber die aktuellen Gerätewerte weichen "
                            "von der Vorschau ab. Erneut prüfen."
                        )
            except WlanError:
                result.update(
                    status="applied" if resource in _ACK_ONLY_RESOURCES else "unknown",
                    persistence="unknown", verification="unavailable",
                    message=t(
                        "Die Aktion wurde bestätigt; aktuelle Werte und Abschluss konnten danach nicht geprüft werden."
                    ),
                )
        return result
    except WlanWriteOutcomeUnknown as exc:
        result = {"status": "unknown", "message": exc.message, "verified": False, "verification": "unavailable", "persistence": "unknown"}
        return result
    finally:
        if locked:
            try:
                session.unlock()
            except WlanError:
                # Session close releases NETCONF locks. Never mask the write
                # result with a second exception or retry the original mutation.
                logger.warning("NETCONF running unlock failed; session will close")
                if result is not None:
                    result.setdefault("warnings", []).append(
                        t("Die Sperre wird durch das Schließen der NETCONF-Sitzung freigegeben.")
                    )
