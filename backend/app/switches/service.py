"""Public facade for the switch routes: selects the driver, checks capabilities, coalesces reads."""

import logging
from collections.abc import Callable
from dataclasses import replace

from fastapi import HTTPException, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

from .. import database as db
from ..audit import audited_write, record
from ..auth import Principal, Role, sessions
from ..device_locks import write_lock
from ..i18n import t
from . import (  # noqa: F401 (ops registers)
    clients,
    config_state,
    features,
    operations,
    ops,
    previews,
    transport,
    uplinks,
    vlans,
)
from .coalescing import coalesced_read, invalidates_reads
from .drivers import get_driver, list_drivers
from .drivers.base import (
    PortChange,
    SwitchDriver,
    WriteResult,
    empty_poe_summary,
    merge_interface_details,
    merge_poe_details,
)
from .drivers.plans import ChangePlan, CliLines
from .errors import ChangeConflict, InvalidInputError, SwitchConnectionError, UnsupportedFeatureError, append_warning

logger = logging.getLogger("switchsteward.switches.service")

# PortChange field -> feature that must be supported to set it.
CHANGE_FEATURES = (
    ("description", "port_description"),
    ("mode", "port_mode"),
    ("access_vlan", "access_vlan"),
    ("native_vlan", "native_vlan"),
    ("trunk_allowed_vlans", "trunk_allowed_vlans"),
    ("voice_vlan", "voice_vlan"),
    ("edge_port", "edge_port"),
    ("speed", "speed"),
    ("duplex", "duplex"),
    ("shutdown", "port_state"),
    ("poe_mode", "poe_mode"),
    ("poe_standard", "poe_limit"),
)
_FEATURE_FIELDS = {feature: field for field, feature in CHANGE_FEATURES}
UNSUPPORTED_OPTION_REASON = "Der Wert {value} wird von diesem Gerät nicht unterstützt."
SPEED_DUPLEX_REASON = "Speed und Duplex müssen gemeinsam gesetzt werden."


# --- Drivers and capabilities ----------------------------------------------------------


def driver_for(switch: dict) -> SwitchDriver | None:
    return get_driver(switch.get("device_type"))


def _require(switch: dict, feature: str) -> tuple[SwitchDriver, dict[str, features.FeatureSupport]]:
    """Driver and effective capabilities; raises before any session is opened."""
    driver = driver_for(switch)
    capabilities = features.for_switch(driver, switch)
    features.require(capabilities, feature)
    return driver, capabilities


def get_capabilities(switch: dict) -> dict:
    return features.to_json(features.for_switch(driver_for(switch), switch))


def describe_switch(switch: dict) -> dict:
    """Switch API representation with driver, model and effective capabilities."""
    values = dict(switch)
    selected_id = values.pop("model_id", None)
    detected = values.pop("detected_model", None)
    detected_id = values.pop("detected_model_id", None)
    values.pop("detected_at", None)
    driver = driver_for(switch)
    profile = features.selected_profile(driver, switch)
    return {
        **values,
        "driver": None if driver is None else {
            "id": driver.id,
            "vendor": driver.vendor,
            "label": driver.label,
            "transport": driver.transport,
            "experimental": driver.experimental,
        },
        "model": {
            "selected_id": selected_id,
            "detected": detected,
            "detected_id": detected_id,
            "effective_label": profile.label if profile else detected,
        },
        "capabilities": features.to_json(features.for_switch(driver, switch)),
    }


def list_driver_info() -> list[dict]:
    return [
        {
            "id": driver.id,
            "vendor": driver.vendor,
            "label": driver.label,
            "transport": driver.transport,
            "default_port": driver.default_port,
            "experimental": driver.experimental,
            "features": features.to_json({
                feature: driver.features.get(feature) or features.unsupported(features.NOT_IMPLEMENTED_REASON)
                for feature in features.FEATURES
            }),
            "models": [{"id": profile.id, "label": profile.label} for profile in driver.catalog.models],
        }
        for driver in list_drivers()
    ]


def _record_detected_model(driver: SwitchDriver, switch: dict, model: str | None) -> None:
    if not model or switch.get("id") is None:
        return
    profile = driver.catalog.match(model)
    db.set_detected_model(switch["id"], model, profile.id if profile else None)


def check_port_change(capabilities: dict[str, features.FeatureSupport], change: PortChange) -> None:
    """Every set field must be supported with an allowed option; coupled fields together."""
    for field, feature in CHANGE_FEATURES:
        value = getattr(change, field)
        if value is None:
            continue
        support = features.require(capabilities, feature)
        if support.options is not None and isinstance(value, str) and value not in support.options:
            raise features.unsupported(UNSUPPORTED_OPTION_REASON, value=value).error(feature)
        for required in support.requires:
            if getattr(change, _FEATURE_FIELDS[required]) is None and not (feature == "speed" and value == "auto"):
                raise InvalidInputError(t(SPEED_DUPLEX_REASON))


# --- Device operations -------------------------------------------------------------------


def check_connection(switch: dict, credentials: dict) -> dict:
    driver = driver_for(switch)
    if driver is None:
        raise features.unsupported(features.UNKNOWN_DRIVER_REASON).error("device_summary")
    result = driver.check_connection(switch, credentials)
    if result["ok"]:
        _record_detected_model(driver, switch, result.get("model"))
    else:
        logger.error("Connection test failed for switch %s (%s)", switch.get("name"), driver.id)
    return result


@coalesced_read
def get_interface_inventory(switch: dict, credentials: dict) -> dict:
    """Status, VLANs, switchport details and PoE values in one session."""
    driver, capabilities = _require(switch, "interfaces")
    with driver.session(switch, credentials) as session:
        interfaces = [{"errdisabled_reason": None, **item} for item in driver.read_interfaces(session)]
        vlans = driver.read_vlans(session)
        switchports = driver.read_switchports(session, interfaces)
        poe_ports = driver.read_poe_ports(session) if capabilities["poe"].supported else {}
    return {
        "interfaces": merge_poe_details(merge_interface_details(interfaces, switchports, driver), poe_ports, driver),
        "vlans": vlans,
        "warnings": session.warnings,
    }


@coalesced_read
def get_interface_detail(switch: dict, credentials: dict, interface: str) -> dict:
    driver, _capabilities = _require(switch, "port_detail")
    interface = driver.validate_interface(interface)
    with driver.session(switch, credentials) as session:
        detail = driver.read_port_detail(session, interface)
    overrides = driver.runtime_overrides(detail)
    effective = features.for_switch(driver, switch, overrides)
    port_options = detail.pop("port_options", None) or {}
    detail["capability_overrides"] = {feature: t(reason) for feature, reason in overrides.items()}
    detail["port_options"] = {}
    for feature in ("speed", "duplex"):
        allowed = effective[feature].options
        values = port_options.get(feature) or list(allowed or ())
        detail["port_options"][feature] = [value for value in values if allowed is None or value in allowed]
    return detail


# --- VLAN tab ----------------------------------------------------------------------------


def read_vlan_ports(driver: SwitchDriver, session) -> tuple[dict[str, dict], list[str]]:
    """Switchport details and the VLAN-carrying ports (``has_switchport``) without details (their VLANs are unknown)."""
    interfaces = driver.read_interfaces(session)
    switchports = driver.read_switchports(session, interfaces)
    missing = [
        item["port"] for item in interfaces
        if driver.has_switchport(item["port"]) and driver.interface_key(item["port"]) not in switchports
    ]
    return switchports, missing


def vtp_status_for_vlans(driver, switch: dict, session) -> dict | None:
    """VTP status for the VLAN lock; None when the driver has no VTP or it cannot be read (the device then decides)."""
    if not features.for_switch(driver, switch)["vtp"].supported or getattr(session, "broken", False):
        return None
    try:
        return driver.read_vtp(session)
    except (SwitchConnectionError, UnsupportedFeatureError):
        return None
    except transport.SSH_TIMEOUT_ERRORS:
        session.broken = True
        return None


@coalesced_read
def get_vlan_inventory(switch: dict, credentials: dict) -> dict:
    """VLANs with port usage, layer-3 flag, delete blocker and VTP lock in one session."""
    driver, _capabilities = _require(switch, "vlans")
    with driver.session(switch, credentials) as session:
        rows = driver.read_vlans(session)
        switchports, missing = read_vlan_ports(driver, session)
        constraints = driver.read_vlan_constraints(session)
        lock = vlans.vtp_lock(vtp_status_for_vlans(driver, switch, session))
    return {
        "vlans": vlans.describe(rows, switchports, constraints, missing), "vtp": lock, "warnings": session.warnings,
    }


# --- Change framework (preview → apply) ----------------------------------------------------

ROLLBACK_UNAVAILABLE = "Für diese Änderung ist kein automatisches Rollback möglich."


def _require_role(spec: operations.OperationSpec, principal: Principal) -> None:
    if not principal.can_operate or (spec.role is Role.ADMIN and not principal.can_edit):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=t("Administratorrechte erforderlich"))


def parse_params(spec: operations.OperationSpec, params: dict):
    try:
        return spec.body.model_validate(params)
    except ValidationError as exc:
        # Errors keep their location but never the rejected input (it can be a secret).
        raise RequestValidationError([
            {**error, "loc": ("body", "params", *error["loc"])} for error in exc.errors(include_url=False)
        ]) from None


def _context(spec, switch: dict, credentials: dict, principal: Principal, body, *, applying: bool):
    driver = driver_for(switch)
    capabilities = features.for_switch(driver, switch)
    for feature in spec.features:
        features.require(capabilities, feature)
    ctx = operations.OperationContext(
        driver=driver, session=None, switch=switch, credentials=credentials, body=body, principal=principal,
        applying=applying,
    )
    if spec.check is not None:
        spec.check(ctx)
    return ctx, capabilities


def _with_config_mode(plan: ChangePlan, command: str | None) -> ChangePlan:
    """Change lines run in the config mode of an armed rollback (Cisco ``configure terminal revert timer``)."""
    if not command:
        return plan
    steps = tuple(
        replace(step, config_mode_command=command)
        if isinstance(step, CliLines) and step.enter and step.config_mode_command is None else step
        for step in plan.steps
    )
    return replace(plan, steps=steps)


def _merge_warnings(*groups) -> list[str]:
    return list(dict.fromkeys(warning for group in groups for warning in group))


def preview_change(switch: dict, credentials: dict, principal: Principal, change: operations.ChangeIn) -> dict:
    """Build the plan of ``change`` in a device session and keep it as a single-use preview."""
    spec = operations.OPERATIONS[change.kind]
    _require_role(spec, principal)
    body = parse_params(spec, change.params)
    ctx, capabilities = _context(spec, switch, credentials, principal, body, applying=False)
    if change.rollback_minutes is not None:
        features.require(capabilities, "config_rollback")
    driver = ctx.driver
    with driver.session(switch, credentials) as session:
        ctx.session = session
        plan = spec.plan(ctx)
        if not plan.steps and not plan.warnings and not spec.deferred and spec.job is None:
            # Nothing would be sent: no preview, no audit line, no "unsaved changes".
            raise InvalidInputError(t("Keine Änderung nötig."))
        risk = plan.risk
        interface = spec.interface(body)
        if interface and risk is None:
            risk = uplinks.detect(driver, session, switch).get(driver.interface_key(interface))
        if risk and not principal.can_edit:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=t(
                "Operatoren dürfen diese Änderung nicht ausführen: {reason}", reason=risk,
            ))
        rollback_available = (
            capabilities["config_rollback"].supported and not plan.persistent and not plan.reloads
            and not spec.deferred and spec.job is None and spec.rollback_supported
        )
        lines = plan.lines
        if change.rollback_minutes is not None:
            if not rollback_available:
                raise ChangeConflict("incompatible", t(ROLLBACK_UNAVAILABLE))
            lines = driver.plan_rollback_arm(session, change.rollback_minutes).lines + lines
        warnings = _merge_warnings(plan.warnings, ctx.warnings, session.warnings)
    token, entry = previews.store(
        switch_id=switch.get("id"), principal=principal, kind=spec.kind, params=body.model_dump(),
        lines=tuple(lines), basis=dict(ctx.basis), risk=risk, persistent=plan.persistent, reloads=plan.reloads,
        rollback_minutes=change.rollback_minutes, rollback_available=rollback_available,
    )
    return {
        "preview_token": token,
        "kind": spec.kind,
        "lines": list(entry.lines),
        "warnings": warnings,
        "risk": risk,
        "persistent": plan.persistent,
        "reloads": plan.reloads,
        "rollback": {
            "available": rollback_available,
            "minutes": change.rollback_minutes,
            "default_minutes": operations.ROLLBACK_DEFAULT_MINUTES,
            "min": operations.ROLLBACK_MIN_MINUTES,
            "max": operations.ROLLBACK_MAX_MINUTES,
        },
        "expires_at": entry.expires_at,
    }


def _connection(switch_id: int) -> tuple[dict, dict]:
    connection = db.get_switch_connection(switch_id)
    if not connection:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=t("Switch nicht gefunden"))
    if not connection["credentials"]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=t(
            "Für diesen Switch fehlen Zugangsdaten für die gewählte Quelle (global/eigen).",
        ))
    return connection["switch"], connection["credentials"]


def _run_hook(hook, ctx, *args) -> None:
    """``before``/``after`` never abort a change; failures become warnings."""
    try:
        hook(ctx, *args)
    except Exception as exc:
        logger.error("Change hook %s failed for switch %s", getattr(hook, "__name__", hook), ctx.switch.get("name"),
                     exc_info=exc)
        append_warning(ctx.warnings, t("Zusatzschritt fehlgeschlagen: {error}", error=str(exc)))


def _mark_state(spec: operations.OperationSpec, plan: ChangePlan, switch_id: int, username: str) -> None:
    if spec.actions_only or spec.marks is None:
        return
    if spec.marks == "saved":
        config_state.mark_saved(switch_id)
    elif spec.marks == "unknown":
        config_state.mark_unknown(switch_id)
    elif not plan.persistent:
        config_state.mark_dirty(switch_id, username)


@invalidates_reads
def apply_change(switch_id: int, principal: Principal, apply_in: operations.ApplyIn) -> dict:
    """Re-plan the previewed change, refuse it when the lines differ, otherwise execute it once."""
    with write_lock(
        "switch", switch_id, t("Für diesen Switch wird bereits eine Änderung ausgeführt."),
        t("Ein anderer Serverprozess bearbeitet diesen Switch."), lambda message: ChangeConflict("busy", message),
    ):
        entry = previews.claim(apply_in.preview_token, switch_id, principal)
        spec = operations.OPERATIONS[entry.kind]
        _require_role(spec, principal)
        if entry.risk:
            if not principal.can_edit:
                raise HTTPException(status.HTTP_403_FORBIDDEN, detail=t(
                    "Operatoren dürfen diese Änderung nicht ausführen: {reason}", reason=entry.risk,
                ))
            if not apply_in.confirm_risk:
                raise ChangeConflict("risk_confirmation_required", t(
                    "Diese Änderung muss ausdrücklich bestätigt werden: {reason}", reason=entry.risk,
                ))
        pending = config_state.pending(switch_id)
        if pending and not pending["expired"]:
            raise ChangeConflict("rollback_pending", t("Erst die laufende Änderung bestätigen oder zurücksetzen."))
        previews.consume(apply_in.preview_token, entry)
        switch, credentials = _connection(switch_id)
        body = parse_params(spec, entry.params)
        ctx, _capabilities = _context(spec, switch, credentials, principal, body, applying=True)
        driver = ctx.driver
        with driver.session(switch, credentials) as session:
            ctx.session = session
            plan = spec.plan(ctx)
            arm = driver.plan_rollback_arm(session, entry.rollback_minutes) if entry.rollback_minutes else None
            lines = (arm.lines if arm else ()) + plan.lines
            if lines != entry.lines or ctx.basis != entry.basis:
                raise ChangeConflict("preview_stale", t(
                    "Der Switch-Zustand hat sich seit der Vorschau geändert. Bitte Vorschau neu erstellen.",
                ))
            action = spec.action_for(body)
            interface = spec.interface(body)
            detail = " ".join(part for part in (spec.detail_for(body), f"commands={len(plan.lines)}") if part)
            job = spec.job(ctx) if spec.job is not None else None
            if spec.deferred or job is not None:
                return _defer(spec, entry, switch, plan, action, interface, detail, principal, job, ctx.warnings)
            change_backups = ops.backup.wants_change_backups(ctx, spec, plan)
            if change_backups:
                ops.backup.take_change_backup(ctx, "before-change")
            if spec.before is not None:
                _run_hook(spec.before, ctx)
            rollback = None
            if arm is not None:
                armed = driver.execute_plan(session, arm)
                if not armed["ok"]:
                    message = t("Das automatische Rollback konnte nicht aktiviert werden: {error}", error=armed["message"])
                    record(action, target=switch["name"], interface=interface, detail=f"{detail} -> {message}",
                           status="error")
                    return {"ok": False, "message": message, "warnings": ctx.warnings, "rollback": None}
                state = config_state.arm(switch_id, driver.id, entry.rollback_minutes, principal.username)
                rollback = {"armed": True, "expires_at": state["expires_at"]}
                plan = _with_config_mode(plan, arm.config_mode_command)
                detail += f" rollback={entry.rollback_minutes}m"

            def execute() -> WriteResult:
                result = driver.execute_plan(session, plan)
                return spec.verify(ctx, result) if spec.verify is not None and result["ok"] else result

            result = audited_write(action, target=switch["name"], interface=interface, detail=detail, operation=execute)
            if result["ok"]:
                _mark_state(spec, plan, switch_id, principal.username)
            if spec.after is not None:
                _run_hook(spec.after, ctx, result)
            if change_backups and result["ok"]:
                ops.backup.take_change_backup(ctx, "after-change")
            warnings = _merge_warnings(ctx.warnings)
    return {"ok": result["ok"], "message": result["message"], "warnings": warnings, "rollback": rollback}


def _defer(
    spec, entry, switch: dict, plan: ChangePlan, action: str, interface, detail: str, principal,
    job: tuple[str, str, dict] | None, warnings: list[str],
) -> dict:
    """Deferred operations (firmware transfer, scheduled reload) become a scheduler job."""
    from .. import scheduler

    kind, run_at, params = job or (spec.kind, sessions.timestamp(), entry.params)
    job_id = scheduler.create_job(kind, switch["id"], run_at, params, principal.username)
    message = plan.message or t("Auftrag wurde angelegt.")
    record(action, target=switch["name"], interface=interface, detail=f"{detail} job={job_id} run_at={run_at}")
    return {"ok": True, "message": message, "warnings": _merge_warnings(warnings), "rollback": None, "job_id": job_id}


def get_config_status(switch_id: int) -> dict:
    """Save state of the app's changes and the armed rollback (``None`` if none)."""
    return {"app": config_state.state(switch_id), "rollback": config_state.pending(switch_id)}



@coalesced_read
def get_device_summary(switch: dict, credentials: dict) -> dict:
    """Device info, port counters and the PoE budget in one session."""
    driver, capabilities = _require(switch, "device_summary")
    with driver.session(switch, credentials) as session:
        info = driver.read_device_info(session)
        interfaces = driver.read_interfaces(session) if capabilities["interfaces"].supported else []
        poe = driver.read_poe_budget(session, info) if capabilities["poe_budget"].supported else empty_poe_summary()
    _record_detected_model(driver, switch, info.get("model"))
    ports_disabled = sum(1 for interface in interfaces if interface["admin_state"] == "disabled")
    ports_up = sum(
        1 for interface in interfaces if interface["link_state"] == "up" and interface["admin_state"] != "disabled"
    )
    return {
        **info,
        "ports_up": ports_up,
        "ports_disabled": ports_disabled,
        # Everything that is neither up nor administratively disabled.
        "ports_down": len(interfaces) - ports_up - ports_disabled,
        "ports_total": len(interfaces),
        "poe": poe,
    }


@coalesced_read
def get_neighbors(switch: dict, credentials: dict) -> list[dict]:
    driver, _capabilities = _require(switch, "neighbors")
    with driver.session(switch, credentials) as session:
        return driver.read_neighbors(session)


@coalesced_read
def read_client_snapshot(switch: dict, credentials: dict) -> dict:
    driver = driver_for(switch)
    with driver.session(switch, credentials) as session:
        return driver.read_client_snapshot(session, switch)


def get_client_inventory(switch: dict, credentials: dict) -> dict:
    driver, _capabilities = _require(switch, "clients")
    return clients.build_client_inventory(read_client_snapshot(switch, credentials), driver)


def search_clients(switches: list[dict], query: str, *, connection_resolver: Callable[[int], dict | None]) -> dict:
    """Global client search; switches without ``client_search`` are reported in ``skipped_switches``."""
    eligible = []
    skipped = []
    for switch in switches:
        support = features.for_switch(driver_for(switch), switch)["client_search"]
        if support.supported:
            eligible.append(switch)
        else:
            skipped.append({"id": switch.get("id"), "name": switch.get("name"), "reason": support.message()})

    def read(switch: dict):
        connection = connection_resolver(switch["id"])
        if not connection or not connection["credentials"]:
            raise SwitchConnectionError(t("Für diesen Switch fehlen Zugangsdaten."))
        selected = connection["switch"]
        driver, _capabilities = _require(selected, "client_search")
        return read_client_snapshot(selected, connection["credentials"]), driver

    result = clients.search_clients(eligible, query, read)
    skipped.sort(key=lambda item: (item.get("name") or "").casefold())
    return {**result, "switches_total": len(switches), "skipped_switches": skipped}
