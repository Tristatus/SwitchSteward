"""Reviewed, single-use WLC changes with per-controller execution and audit.

Preview secrets live only in a bounded, expiring server-side store. Persisted
state describes this application's changes, never a global startup/running diff.
An OS lock serializes writes across backend processes and is released on crash;
the durable 'unknown' marker survives a crash after dispatching an operation.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import secrets
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .. import database as db
from ..audit import record
from ..auth import Principal
from ..device_locks import write_lock
from ..i18n import t
from . import config_catalog, service
from .models import WlanAuthenticationError, WlanCapabilityError, WlanConfigurationError, WlanError, utc_timestamp

_HIDDEN = "[verborgen]"
_PREVIEW_SECONDS = 300
_RESULT_SECONDS = 900
_MAX_PREVIEWS = 256
_GUARD = threading.RLock()
_PREVIEWS: OrderedDict[str, _Preview] = OrderedDict()


class ConfigurationConflict(WlanError):
    code = "configuration_conflict"


@dataclass
class _Preview:
    controller_id: int
    owner: str
    fingerprint: str
    revision: str
    change: dict
    public: dict
    expires: float
    result: dict | None = None
    used: bool = False


def _owner(principal: Principal) -> str:
    return hashlib.sha256(f"{principal.username}\0{principal.csrf_token}".encode()).hexdigest()


def _connection(controller_id: int) -> tuple[dict, dict]:
    connection = db.get_wlan_controller_connection(controller_id)
    if not connection:
        raise ConfigurationConflict(t("Der Controller ist nicht mehr im Inventar vorhanden."))
    if not connection["credentials"]:
        raise WlanConfigurationError(t("Für diesen Controller fehlen Zugangsdaten."))
    return connection["controller"], connection["credentials"]


def _fingerprint(controller: dict, credentials: dict) -> str:
    source = service._cache_fingerprint(controller, credentials) + str(controller.get("revision_token", ""))
    return hashlib.sha256(source.encode()).hexdigest()


def controller_write_lock(controller_id: int):
    return write_lock(
        "wlan", controller_id, t("Für diesen Controller wird bereits eine Änderung ausgeführt."),
        t("Ein anderer Serverprozess bearbeitet diesen Controller."), ConfigurationConflict,
    )


def persistence(controller_id: int, fingerprint: str) -> dict:
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT status, last_change_id, last_saved_at, updated_at FROM wlan_config_state "
            "WHERE controller_id=? AND connection_fingerprint=?", (controller_id, fingerprint),
        ).fetchone()
    value = dict(row) if row else {"status": "untracked", "last_change_id": None, "last_saved_at": None}
    value["dirty"] = True if value["status"] == "dirty" else False if value["status"] == "saved" else None
    value["scope"] = "application"
    status = value["status"]
    if status == "untracked":
        value["message"] = t("Der globale Speicherstand ist unbekannt. Noch keine Änderungen über diese Anwendung erfasst.")
    elif status == "dirty":
        value["message"] = t("Über diese Anwendung vorgenommene Änderungen wurden noch nicht am WLC gespeichert.")
    elif status == "saved":
        value["message"] = t("Die Running-Konfiguration wurde zuletzt über diese Anwendung gespeichert. Fremdänderungen sind nicht erfasst.")
    elif status == "unknown":
        value["message"] = t("Der letzte Änderungsausgang oder Speicherstand ist unklar. Gerätewerte vor weiteren Aktionen prüfen.")
    else:
        value["message"] = t("Speicherstand unbekannt.")
    return value


def _store_state(controller_id: int, fingerprint: str, status: str, change_id: str, saved_at=None):
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO wlan_config_state "
            "(controller_id,connection_fingerprint,status,last_change_id,last_saved_at,updated_at) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(controller_id) DO UPDATE SET connection_fingerprint=excluded.connection_fingerprint, "
            "status=excluded.status,last_change_id=excluded.last_change_id, "
            "last_saved_at=excluded.last_saved_at,updated_at=excluded.updated_at",
            (controller_id, fingerprint, status, change_id, saved_at, utc_timestamp()),
        )


def _catalog(snapshot: dict) -> list[dict]:
    return snapshot.get("catalog") or config_catalog.catalog()


def _descriptor(snapshot: dict, resource: str) -> dict:
    return next((item for item in _catalog(snapshot) if item["resource"] == resource), {})


def _redact(values: dict, descriptor: dict, hidden: str = _HIDDEN) -> dict:
    fields = {field["name"]: field for field in descriptor.get("fields", [])}
    return {
        name: hidden if fields.get(name, {}).get("secret") and value is not None else copy.deepcopy(value)
        for name, value in values.items() if name in fields
    }


def public_snapshot(snapshot: dict) -> dict:
    # Explicit top-level allowlist excludes raw XML, secret-aware hashes and
    # adapter internals. Collection values are additionally field-allowlisted.
    result = {key: copy.deepcopy(snapshot[key]) for key in (
        "capabilities", "device", "access_points", "warnings", "complete", "collected_at",
    ) if key in snapshot}
    # Descriptors stay German in snapshots/caches; translate per request.
    result["catalog"] = config_catalog.localize_catalog(_catalog(snapshot))
    result["collections"] = {}
    hidden = t("[verborgen]")
    for descriptor in result["catalog"]:
        collection = descriptor.get("collection")
        if collection:
            result["collections"][collection] = [
                {"key": row["key"], "values": _redact(row.get("values", {}), descriptor, hidden)}
                for row in snapshot.get("collections", {}).get(collection, [])
            ]
    result["references"] = {
        collection: [str(row["key"]) for row in snapshot.get("collections", {}).get(collection, [])]
        for collection in ("authentication_lists", "qos_policies", "ipv4_acls", "ipv6_acls", "vlans")
    }
    return result


def get_configuration(controller: dict, credentials: dict) -> dict:
    snapshot = service.adapter_for(controller).get_configuration(controller, credentials)
    result = public_snapshot(snapshot)
    result["persistence"] = persistence(controller["id"], _fingerprint(controller, credentials))
    return result


def _row(snapshot: dict, descriptor: dict, key: str) -> dict:
    return next((row.get("values", {}) for row in snapshot.get("collections", {}).get(
        descriptor.get("collection"), [],
    ) if str(row["key"]) == key), {})


def _ap(snapshot: dict, key: str) -> dict:
    return next((ap for ap in snapshot.get("access_points", []) if key in {
        ap.get("radio_mac"), ap.get("ethernet_mac"), ap.get("id"),
    }), {})


def _diff(snapshot: dict, change: dict, descriptor: dict) -> list[dict]:
    old = _row(snapshot, descriptor, change["key"])
    if descriptor.get("kind") == "action":
        old = _ap(snapshot, change["key"])
        action_fields = {"ap_name": "name", "ap_location": "location", "ap_admin": "admin_state", "ap_mode": "mode"}
        source = action_fields.get(change["resource"])
        if source:
            value = "site" if source == "mode" and old.get("mode_from_site") else old.get(source)
            old = {field["name"]: value for field in descriptor.get("fields", [])}
        elif change["resource"].startswith("radio_"):
            radio = next((item for item in old.get("radios", []) if item.get("slot_id", item.get("slot"))
                          == change.get("values", {}).get("slot_id")), {})
            old = {
                "slot_id": radio.get("slot_id", radio.get("slot")),
                "band": change.get("values", {}).get("band") if radio else None,
                "admin_state": radio.get("admin_state"), "channel": radio.get("channel"),
                "width": str(radio["channel_width"]) if radio.get("channel_width") is not None else None,
                "power_level": radio.get("power_level"),
                "mode": radio.get("power_mode" if change["resource"] == "radio_power" else "channel_mode"),
            }
        else:
            old = {}
    new = change.get("values", {})
    if change["operation"] == "delete":
        new = {field: None for field in old}
    if change["operation"] == "clone":
        source = _row(snapshot, descriptor, change.get("source_key", ""))
        new = {**source, **new}
        old = {}
    old, new = _redact(old, descriptor), _redact(new, descriptor)
    labels = {field["name"]: field.get("label", field["name"]) for field in descriptor.get("fields", [])}
    return [{"field": field, "label": labels.get(field, field), "before": old.get(field), "after": value}
            for field, value in new.items() if old.get(field) != value or value == _HIDDEN]


def _localized_preview(public: dict) -> dict:
    """Stored previews keep German labels for the audit; responses follow the request language."""
    result = copy.deepcopy(public)
    hidden = t("[verborgen]")
    localize = lambda value: hidden if value == _HIDDEN else value  # noqa: E731
    result["change"]["values"] = {name: localize(value) for name, value in result["change"]["values"].items()}
    for entry in result["diff"]:
        entry.update(label=t(entry["label"]), before=localize(entry["before"]), after=localize(entry["after"]))
    return result


def _strings(value):
    if isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)
    elif isinstance(value, str):
        yield value


def _impact(snapshot: dict, change: dict, descriptor: dict) -> dict:
    aps = snapshot.get("access_points", [])
    key, resource = change["key"], change["resource"]
    if (descriptor.get("kind") == "action" and resource != "save") or resource == "ap_tags":
        selected = [ap for ap in aps if key in {ap.get("radio_mac"), ap.get("ethernet_mac"), ap.get("id")}]
        scope = "access_point"
    elif resource == "save":
        selected, scope = aps, "controller_persistence"
    elif change["operation"] in {"create", "clone"}:
        selected, scope = [], "unassigned_profile"
    else:
        # Traverse references to determine all tags affected by a shared object.
        targets = {(descriptor.get("collection", resource), key), (resource, key)}
        changed = True
        while changed:
            changed = False
            for item in _catalog(snapshot):
                for row in snapshot.get("collections", {}).get(item.get("collection"), []):
                    identity = (item.get("collection"), str(row["key"]))
                    if identity in targets:
                        continue
                    for field in item.get("fields", []):
                        reference = field.get("reference")
                        if isinstance(reference, dict):
                            reference = reference.get("collection", reference.get("resource"))
                        field_value = row.get("values", {}).get(field["name"])
                        matched = reference and any((reference, value) in targets for value in _strings(field_value))
                        for column, collection in field.get("references", {}).items():
                            if any((collection, mapping.get(column)) in targets
                                   for mapping in (field_value or []) if isinstance(mapping, dict)):
                                matched = True
                        if matched:
                            targets.update({identity, (item["resource"], str(row["key"]))})
                            changed = True
                            break
        tags = {(kind.removesuffix("s"), key) for kind, key in targets if kind in {
            "policy_tag", "policy_tags", "site_tag", "site_tags", "rf_tag", "rf_tags",
        }}
        selected = [ap for ap in aps if tags.intersection({
            (field, ap.get(field)) for field in ("policy_tag", "site_tag", "rf_tag")
        })]
        scope = "referenced_profiles"
        if not tags or not snapshot.get("complete", False):
            selected, scope = aps, "controller_estimate"
    warnings = []
    if resource == "save":
        warnings.append(t("Speichert die gesamte Running-Konfiguration einschließlich Änderungen anderer Administratoren."))
    elif resource in {"ap_restart", "ap_admin", "ap_mode", "ap_tags", "site_tag", "ap_join_profile", "flex_profile"}:
        warnings.append(t("Die Änderung kann AP-Verbindungen neu aufbauen und verbundene Clients unterbrechen."))
    elif resource not in {"ap_name", "ap_location", "ap_persist_tags"}:
        warnings.append(t("Gemeinsam verwendete WLAN-/Funk-Einstellungen können die Verbindung betroffener Clients unterbrechen."))
    if scope == "controller_estimate":
        warnings.append(t("Die Auswirkungen sind nicht vollständig eingrenzbar; angezeigt werden vorsorglich alle bekannten APs."))
    if change["operation"] == "delete":
        warnings.append(t("Das gesamte Konfigurationsobjekt einschließlich hier nicht dargestellter Eigenschaften wird entfernt."))
    if change["operation"] == "clone":
        clone_help = descriptor.get("clone_help")
        warnings.append(t(clone_help) if clone_help else t("Die Ableitung übernimmt nur die hier verwalteten Felder."))
    if resource == "wlan" and "security" in change.get("values", {}):
        warnings.append(t("Die Sicherheitsvorlage setzt AKM, Verschlüsselung, PMF und FT gemeinsam; weitere bisherige Sicherheitsoptionen werden zurückgesetzt."))
    if resource == "radio_width" and change.get("values", {}).get("width") == "auto":
        warnings.append(t("Die Rückkehr zu DCA hebt auch einen individuell konfigurierten Kanal auf."))
    counts = [ap.get("client_count") for ap in selected]
    return {
        "scope": scope,
        "access_points": [{key: ap.get(key) for key in ("name", "radio_mac", "ethernet_mac", "client_count")} for ap in selected],
        "client_count": sum(counts) if snapshot.get("complete", False) and all(isinstance(count, int) for count in counts) else None,
        "warnings": warnings,
    }


def _purge():
    now = time.monotonic()
    for token in list(_PREVIEWS):
        if _PREVIEWS[token].expires <= now:
            del _PREVIEWS[token]


def preview(controller_id: int, principal: Principal, requested: dict) -> dict:
    if not principal.can_edit:
        raise WlanAuthenticationError(t("Gerätekonfiguration erfordert Administratorrechte."))
    controller, credentials = _connection(controller_id)
    snapshot = service.adapter_for(controller).get_configuration(controller, credentials)
    descriptor = _descriptor(snapshot, requested["resource"])
    if not descriptor or requested["resource"] not in snapshot.get("capabilities", {}).get("supported_resources", []):
        raise WlanCapabilityError(t("Diese Änderung wird von den verfügbaren Controller-Fähigkeiten nicht unterstützt."))
    change = config_catalog.validate_change(requested, snapshot, snapshot.get("access_points", []))
    revision = snapshot.get("revision")
    if not revision:
        raise WlanCapabilityError(t("Es ist keine belastbare Konfigurationsbaseline verfügbar."))
    safe_change = {key: value for key, value in change.items() if key in {"resource", "operation", "key", "source_key"}}
    safe_change["values"] = _redact(change.get("values", {}), descriptor)
    public = {
        "change": safe_change, "diff": _diff(snapshot, change, descriptor),
        "impact": _impact(snapshot, change, descriptor), "warnings": list(snapshot.get("warnings", [])),
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=_PREVIEW_SECONDS)).isoformat(timespec="seconds"),
        "persistence": persistence(controller_id, _fingerprint(controller, credentials)),
    }
    token = secrets.token_urlsafe(32)
    with _GUARD:
        _purge()
        if len(_PREVIEWS) >= _MAX_PREVIEWS:
            _PREVIEWS.popitem(last=False)
        _PREVIEWS[token] = _Preview(
            controller_id, _owner(principal), _fingerprint(controller, credentials),
            revision, copy.deepcopy(change), copy.deepcopy(public), time.monotonic() + _PREVIEW_SECONDS,
        )
    return {**_localized_preview(public), "preview_token": token}


def apply(controller_id: int, principal: Principal, token: str) -> dict:
    if not principal.can_edit:
        raise WlanAuthenticationError(t("Gerätekonfiguration erfordert Administratorrechte."))
    with controller_write_lock(controller_id):
        with _GUARD:
            _purge()
            entry = _PREVIEWS.get(token)
            if not entry or entry.controller_id != controller_id or not hmac.compare_digest(entry.owner, _owner(principal)):
                raise ConfigurationConflict(t("Die Vorschau ist abgelaufen oder gehört zu einer anderen Sitzung. Bitte erneut prüfen."))
            if entry.result is not None:
                return copy.deepcopy(entry.result)
            if entry.used:
                raise ConfigurationConflict(t("Diese Vorschau wurde bereits verwendet. Gerätewerte neu laden."))
            entry.used = True
        try:
            controller, credentials = _connection(controller_id)
            fingerprint = _fingerprint(controller, credentials)
            if not hmac.compare_digest(fingerprint, entry.fingerprint):
                raise ConfigurationConflict(t("Controller oder Zugangsdaten wurden seit der Vorschau geändert."))
            change_id = uuid.uuid4().hex
            previous = persistence(controller_id, fingerprint)
            _store_state(controller_id, fingerprint, "unknown", change_id, previous.get("last_saved_at"))
            audit_detail = {"change_id": change_id, "change": entry.public["change"], "diff": entry.public["diff"]}
            # Journal before dispatch. A process crash leaves a visible pending audit
            # record and unknown persistence status, rather than a false success.
            record(
                "wlan-config-start",
                username=principal.username,
                target=controller["name"],
                interface=entry.change["key"],
                detail=json.dumps(audit_detail, ensure_ascii=False),
                status="pending",
            )
            service.clear_cache(controller_id)
            try:
                result = service.adapter_for(controller).apply_configuration(
                    controller, credentials, entry.change, entry.revision,
                )
                if result.get("status") not in {"applied", "rejected", "partial", "unknown"}:
                    result = {"status": "unknown", "verified": False, "message": t("Der Änderungsausgang ist nicht eindeutig.")}
            except WlanError as exc:
                unknown = exc.code in {"write_outcome_unknown", "outcome_unknown", "connection_failed", "invalid_response"}
                result = {"status": "unknown" if unknown else "rejected", "verified": False,
                          "message": exc.message, "code": exc.code}
            except Exception:
                # Do not echo library errors, XML values or secret-bearing payloads.
                result = {"status": "unknown", "verified": False,
                          "message": t("Die Ausführung wurde unerwartet unterbrochen. Gerätewerte neu lesen.")}
            state = "unknown"
            saved_at = previous.get("last_saved_at")
            if result["status"] == "rejected":
                state = previous["status"]
            elif result["status"] == "applied":
                if entry.change["resource"] == "save":
                    state, saved_at = "saved", utc_timestamp()
                elif entry.change["resource"] in {"ap_restart", "ap_persist_tags"}:
                    state = previous["status"]
                else:
                    state = "dirty"
            _store_state(controller_id, fingerprint, state, change_id, saved_at)
            result = {key: result[key] for key in ("status", "message", "verified", "verification", "code", "warnings") if key in result}
            result.update(change_id=change_id, persistence=persistence(controller_id, fingerprint))
            audit_detail.update(status=result["status"], verified=result.get("verified", False),
                                verification=result.get("verification"), persistence=state)
            record(
                "wlan-config-result",
                username=principal.username,
                target=controller["name"],
                interface=entry.change["key"],
                detail=json.dumps(audit_detail, ensure_ascii=False),
                status=result["status"],
            )
            with _GUARD:
                entry.result = copy.deepcopy(result)
                entry.expires = time.monotonic() + _RESULT_SECONDS
            return result
        finally:
            entry.change.clear()
            service.clear_cache(controller_id)


def clear_previews(controller_id: int | None = None):
    with _GUARD:
        for token in list(_PREVIEWS):
            if controller_id is None or _PREVIEWS[token].controller_id == controller_id:
                del _PREVIEWS[token]
