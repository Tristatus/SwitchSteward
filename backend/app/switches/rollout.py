"""VLAN rollout to a switch group: create a VLAN and add it to selected trunks on every switch.

Preview reads all switches of the group in parallel and proposes the trunks that do not carry
the VLAN yet (detected uplinks pre-selected). Apply runs switch by switch under the switch
write lock; it re-plans each switch and refuses it (only it) when its lines or trunk lists
changed since the preview. A failing switch never stops the others.
"""

import contextvars
import hmac
import logging
import secrets
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from fastapi import HTTPException

from .. import database as db
from ..audit import audited_write, record
from ..auth import Principal
from ..device_locks import write_lock
from ..i18n import t
from . import config_state, features, previews, service, uplinks, vlans
from .coalescing import invalidates_reads
from .drivers import get_driver
from .drivers.base import PortChange
from .drivers.plans import combine_plans
from .errors import ChangeConflict, InvalidInputError, UnsupportedFeatureError
from .validation import parse_vlan_list

logger = logging.getLogger("switchsteward.switches.rollout")

_ROLLOUT_SECONDS = 300
_MAX_ROLLOUTS = 64
_MAX_WORKERS = 8
_FULL_RANGE = tuple(range(1, 4095))
_GUARD = threading.Lock()
_ROLLOUTS: "OrderedDict[str, Rollout]" = OrderedDict()

STALE_MESSAGE = "Der Switch-Zustand hat sich seit der Vorschau geändert. Bitte Vorschau neu erstellen."


@dataclass
class SwitchPreview:
    switch_id: int
    name: str
    fingerprint: str
    vlan_exists: bool
    vlan_lines: tuple[str, ...]
    # interface key -> {"interface", "allowed" (list), "lines" (list)}
    candidates: dict[str, dict] = field(default_factory=dict)


@dataclass
class Rollout:
    group_id: int
    owner: str
    vlan_id: int
    name: str | None
    switches: dict[int, SwitchPreview]
    expires: float
    used: bool = False


def _error_text(exc: Exception) -> str:
    if isinstance(exc, UnsupportedFeatureError):
        return t(exc.reason, **exc.params)
    if isinstance(exc, ChangeConflict):
        return exc.message
    if isinstance(exc, HTTPException):
        return str(exc.detail)
    if isinstance(exc, InvalidInputError):
        return str(exc)
    return str(exc) or type(exc).__name__


def _allowed(detail: dict) -> tuple[int, ...] | None:
    """Explicit allowed VLANs of a trunk; None for "all", the full range or unreadable lists."""
    value = detail.get("trunk_allowed_vlan")
    if value is None or not str(value).strip():
        return None
    try:
        selection = parse_vlan_list(str(value))
    except InvalidInputError:
        return None
    if selection == "none":
        return ()
    if isinstance(selection, str) or selection == _FULL_RANGE:
        return None
    return selection


def _port_plan(driver, session, interface: str, allowed: tuple[int, ...], vlan_id: int):
    change = PortChange(trunk_allowed_vlans=tuple(sorted({*allowed, vlan_id})))
    detail = driver.read_port_state(session, interface, change) or {}
    return driver.plan_port_change(session, interface, change, detail)


def _trunks(driver, session, vlan_id: int) -> dict[str, dict]:
    """Interface key -> {"interface", "allowed"} of trunks with an explicit list lacking ``vlan_id``."""
    switchports, _missing = service.read_vlan_ports(driver, session)
    result = {}
    for key, detail in switchports.items():
        if detail.get("mode") != "trunk":
            continue
        allowed = _allowed(detail)
        if allowed is None or vlan_id in allowed:
            continue
        result[driver.interface_key(detail.get("interface") or key)] = {
            "interface": detail.get("interface") or key, "allowed": list(allowed),
        }
    return result


def _check_switch(driver, switch: dict, vlan_id: int, name: str | None) -> None:
    if driver is None:
        raise InvalidInputError(t("Unbekannter Gerätetyp."))
    capabilities = features.for_switch(driver, switch)
    features.require(capabilities, "vlan_create")
    features.require(capabilities, "trunk_allowed_vlans")
    if name:
        features.require(capabilities, "vlan_rename")
    if vlan_id > driver.max_vlan_id:
        raise InvalidInputError(t(
            "VLAN-ID außerhalb des gültigen Bereichs 1-{max}: {value}", max=driver.max_vlan_id, value=vlan_id,
        ))


def _vlan_plan(driver, session, vlan_id: int, name: str | None):
    """(exists, create plan or None)."""
    exists = any(row["id"] == vlan_id for row in driver.read_vlans(session))
    return exists, None if exists else driver.plan_vlan_create(session, vlan_id, name)


def _preview_switch(switch: dict, vlan_id: int, name: str | None) -> tuple[dict, SwitchPreview | None]:
    report = {
        "switch_id": switch["id"], "name": switch["name"], "status": "ok", "reason": None,
        "vlan_exists": False, "vlan_lines": [], "candidates": [], "warnings": [],
    }
    try:
        driver = get_driver(switch.get("device_type"))
        try:
            _check_switch(driver, switch, vlan_id, name)
        except (UnsupportedFeatureError, InvalidInputError) as exc:
            return {**report, "status": "skipped", "reason": _error_text(exc)}, None
        connection = db.get_switch_connection(switch["id"])
        if not connection or not connection["credentials"]:
            return {**report, "status": "skipped", "reason": t(
                "Für diesen Switch fehlen Zugangsdaten für die gewählte Quelle (global/eigen).",
            )}, None
        switch, credentials = connection["switch"], connection["credentials"]
        fingerprint = previews.fingerprint(switch["id"])
        with driver.session(switch, credentials) as session:
            exists, create = _vlan_plan(driver, session, vlan_id, name)
            if create is not None:
                reason = vlans.vtp_create_blocker(service.vtp_status_for_vlans(driver, switch, session), vlan_id)
                if reason is not None:
                    return {**report, "status": "skipped", "reason": reason}, None
            found = uplinks.detect(driver, session, switch)
            trunks = _trunks(driver, session, vlan_id)
            for trunk in trunks.values():
                plan = _port_plan(driver, session, trunk["interface"], tuple(trunk["allowed"]), vlan_id)
                trunk["lines"] = list(plan.lines)
            warnings = list(session.warnings)
        entry = SwitchPreview(
            switch_id=switch["id"], name=switch["name"], fingerprint=fingerprint, vlan_exists=exists,
            vlan_lines=tuple(create.lines) if create else (), candidates=trunks,
        )
        report.update(
            vlan_exists=exists, vlan_lines=list(entry.vlan_lines), warnings=warnings,
            candidates=[
                {
                    "interface": trunk["interface"], "uplink": key in found, "selected": key in found,
                    "reason": found.get(key), "lines": trunk["lines"],
                }
                for key, trunk in trunks.items()
            ],
        )
        return report, entry
    except Exception as exc:
        logger.warning("VLAN rollout preview failed for switch %s: %s", switch.get("name"), exc)
        return {**report, "status": "error", "reason": _error_text(exc)}, None


def _group_switches(group_id: int) -> list[dict]:
    if not db.get_switch_group(group_id):
        raise HTTPException(404, t("Gruppe nicht gefunden"))
    return db.list_switches_in_group(group_id)


def preview(group_id: int, principal: Principal, vlan_id: int, name: str | None) -> dict:
    name = vlans.validate_vlan_name(name) if name else None
    switches = _group_switches(group_id)
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = [
            pool.submit(contextvars.copy_context().run, _preview_switch, switch, vlan_id, name)
            for switch in switches
        ]
        outcomes = [future.result() for future in futures]
    entry = Rollout(
        group_id=group_id, owner=previews.owner(principal), vlan_id=vlan_id, name=name,
        switches={item.switch_id: item for _report, item in outcomes if item is not None},
        expires=time.monotonic() + _ROLLOUT_SECONDS,
    )
    token = secrets.token_urlsafe(32)
    with _GUARD:
        now = time.monotonic()
        for old in [key for key, value in _ROLLOUTS.items() if value.expires <= now]:
            del _ROLLOUTS[old]
        while len(_ROLLOUTS) >= _MAX_ROLLOUTS:
            _ROLLOUTS.popitem(last=False)
        _ROLLOUTS[token] = entry
    return {"rollout_token": token, "vlan_id": vlan_id, "switches": [report for report, _item in outcomes]}


def _claim(token: str, group_id: int, principal: Principal) -> Rollout:
    with _GUARD:
        entry = _ROLLOUTS.get(token)
        if (
            entry is None or entry.used or entry.expires <= time.monotonic() or entry.group_id != group_id
            or not hmac.compare_digest(entry.owner, previews.owner(principal))
        ):
            raise ChangeConflict("preview_invalid", t(previews.INVALID_MESSAGE))
        entry.used = True
    return entry


def _apply_switch(rollout: Rollout, item: SwitchPreview, interfaces: list[str], principal: Principal) -> dict:
    result = {"switch_id": item.switch_id, "name": item.name, "ok": False, "message": "", "lines": []}
    with write_lock(
        "switch", item.switch_id, t("Für diesen Switch wird bereits eine Änderung ausgeführt."),
        t("Ein anderer Serverprozess bearbeitet diesen Switch."), lambda message: ChangeConflict("busy", message),
    ):
        pending = config_state.pending(item.switch_id)
        if pending and not pending["expired"]:
            raise ChangeConflict("rollback_pending", t("Erst die laufende Änderung bestätigen oder zurücksetzen."))
        if previews.fingerprint(item.switch_id) != item.fingerprint:
            raise ChangeConflict("preview_stale", t(STALE_MESSAGE))
        connection = db.get_switch_connection(item.switch_id)
        if not connection or not connection["credentials"]:
            raise InvalidInputError(t("Für diesen Switch fehlen Zugangsdaten für die gewählte Quelle (global/eigen)."))
        switch, credentials = connection["switch"], connection["credentials"]
        driver = get_driver(switch.get("device_type"))
        _check_switch(driver, switch, rollout.vlan_id, rollout.name)
        keys = list(dict.fromkeys(driver.interface_key(interface) for interface in interfaces))
        unknown = [interface for interface in interfaces if driver.interface_key(interface) not in item.candidates]
        if unknown:
            raise InvalidInputError(t("Kein Kandidat der Vorschau: {interfaces}", interfaces=", ".join(unknown)))
        with driver.session(switch, credentials) as session:
            exists, create = _vlan_plan(driver, session, rollout.vlan_id, rollout.name)
            if create is not None:
                reason = vlans.vtp_create_blocker(
                    service.vtp_status_for_vlans(driver, switch, session), rollout.vlan_id,
                )
                if reason is not None:
                    raise InvalidInputError(reason)
            trunks = _trunks(driver, session, rollout.vlan_id) if keys else {}
            plans = [create]
            stale = exists != item.vlan_exists or (tuple(create.lines) if create else ()) != item.vlan_lines
            for key in keys:
                expected = item.candidates[key]
                current = trunks.get(key)
                if current is None or current["allowed"] != expected["allowed"]:
                    stale = True
                    break
                plan = _port_plan(driver, session, expected["interface"], tuple(current["allowed"]), rollout.vlan_id)
                if list(plan.lines) != expected["lines"]:
                    stale = True
                    break
                plans.append(plan)
            if stale:
                raise ChangeConflict("preview_stale", t(STALE_MESSAGE))
            plan = combine_plans(*plans)
            ports = ",".join(item.candidates[key]["interface"] for key in keys) or "-"
            result["lines"] = list(plan.lines)
            if not plan.steps:
                result.update(ok=True, message=t("Keine Änderung nötig."))
                return result
            try:
                outcome = audited_write(
                    "vlan-rollout", target=switch["name"],
                    detail=f"vlan={rollout.vlan_id} ports={ports} commands={len(plan.lines)}",
                    operation=lambda: driver.execute_plan(session, plan),
                )
            except Exception as exc:  # already audited by audited_write
                result["message"] = _error_text(exc)
                return result
        if outcome["ok"] and not plan.persistent:
            config_state.mark_dirty(item.switch_id, principal.username)
        result.update(ok=outcome["ok"], message=outcome["message"])
    return result


@invalidates_reads
def apply(group_id: int, principal: Principal, token: str, selections: dict[int, list[str]]) -> dict:
    rollout = _claim(token, group_id, principal)
    results = []
    for switch_id, item in rollout.switches.items():
        if switch_id not in selections:
            continue
        try:
            results.append(_apply_switch(rollout, item, selections[switch_id], principal))
        except Exception as exc:
            logger.warning("VLAN rollout failed for switch %s: %s", item.name, exc)
            message = _error_text(exc)
            record("vlan-rollout", target=item.name, detail=f"vlan={rollout.vlan_id} -> {message}", status="error")
            results.append({"switch_id": switch_id, "name": item.name, "ok": False, "message": message, "lines": []})
    return {"results": results}
