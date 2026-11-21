"""Maintenance operations: firmware transfer and activation, reload, counters, cable test.

``firmware-stage`` and ``reload-schedule`` are deferred: the apply creates a scheduler job
(``firmware-stage`` / ``reload``) whose handler opens its own session. ``firmware-activate``
with ``reload="at"`` schedules a ``reload`` job after setting the boot image; in Cisco install
mode the activation itself reloads, so the job runs the activation at that time instead.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import Field, model_validator

from ... import database as db
from ... import firmware, scheduler, transfer
from ...auth import Role, sessions
from ...device_locks import write_lock
from ...i18n import t
from .. import config_state, features
from ..coalescing import invalidates_reads
from ..drivers import get_driver
from ..drivers.plans import ChangePlan, CliCommand, FirmwareImage
from ..errors import InvalidInputError, UnsupportedFeatureError
from ..operations import ApiModel, OperationContext, OperationSpec, port_basis, register

JOB_TIMEOUT_SECONDS = 3600
RELOAD_MIN_AHEAD = timedelta(minutes=2)
RELOAD_MAX_AHEAD = timedelta(days=30)
RELOAD_RISK = "Der Switch startet neu; alle Ports sind kurz offline."
ACTIVATE_RISK = "Der Switch startet mit der neuen Firmware; bis zum Neustart bleibt die aktuelle Firmware aktiv."
DIRTY_WARNING = "Ungespeicherte Änderungen gehen beim Neustart verloren."
CABLE_TEST_WARNING = "Der Kabeltest unterbricht die Verbindung am Port für einige Sekunden."
COUNTERS_CLEAR_UNSUPPORTED = "AOS-CX bietet kein Zurücksetzen der Port-Zähler."


# --- Shared helpers ----------------------------------------------------------------------


def parse_run_at(value: str) -> str:
    """ISO 8601 time (UTC; ``Z``/offset or naive = UTC) between 2 minutes and 30 days ahead → UTC timestamp."""
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        raise InvalidInputError(t("Ungültiger Zeitpunkt: bitte ISO-Format in UTC angeben.")) from None
    moment = moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)
    current = sessions.now()
    if moment < current + RELOAD_MIN_AHEAD or moment > current + RELOAD_MAX_AHEAD:
        raise InvalidInputError(t("Der Zeitpunkt muss mindestens 2 Minuten und höchstens 30 Tage in der Zukunft liegen."))
    return sessions.timestamp(moment)


def _warn_unsaved(ctx: OperationContext) -> None:
    switch_id = ctx.switch.get("id")
    if switch_id is not None and config_state.state(switch_id)["status"] == "dirty":
        ctx.warnings.append(t(DIRTY_WARNING))


def _image(image_id: int, driver_id: str) -> FirmwareImage:
    image = firmware.get_image(image_id)
    if image is None:
        raise InvalidInputError(t("Firmware-Image nicht gefunden."))
    if driver_id not in image["platforms"]:
        raise InvalidInputError(t("Das Firmware-Image ist für diese Plattform nicht freigegeben."))
    return FirmwareImage(
        id=image["id"], filename=image["filename"], size=image["size"], sha256=image["sha256"], md5=image["md5"],
    )


def _check_free_space(image: FirmwareImage, state: dict) -> None:
    free = state.get("free_bytes")
    if free is not None and free < image.size:
        raise InvalidInputError(t("Nicht genug freier Speicher auf dem Switch."))


def stage_plan(driver, session, switch: dict, image: FirmwareImage, *, applying: bool) -> ChangePlan:
    """Download plan of ``image``; ``applying`` issues a real transfer ticket (job), else placeholders."""
    state = driver.read_firmware(session)
    _check_free_space(image, state)
    location = transfer.location_for(driver, "firmware", image.id, switch["id"], image.filename, applying=applying)
    plan = driver.plan_firmware_stage(session, image, location, state)
    return replace(plan, secrets=plan.secrets + transfer.location_secrets(location))


def _long_running(plan: ChangePlan) -> ChangePlan:
    """Transfers and installs may take long: every exec command gets ``JOB_TIMEOUT_SECONDS``."""
    steps = tuple(
        replace(step, timeout=max(step.timeout, JOB_TIMEOUT_SECONDS)) if isinstance(step, CliCommand) else step
        for step in plan.steps
    )
    return replace(plan, steps=steps)


# --- Firmware -----------------------------------------------------------------------------


class FirmwareStageIn(ApiModel):
    image_id: int = Field(ge=1)


def _check_stage(ctx: OperationContext) -> None:
    ctx.data["image"] = _image(ctx.body.image_id, ctx.driver.id)


def _plan_stage(ctx: OperationContext) -> ChangePlan:
    # The preview and the apply never issue a ticket; the job does when it runs.
    plan = stage_plan(ctx.driver, ctx.session, ctx.switch, ctx.data["image"], applying=False)
    return replace(plan, message=t("Übertragung gestartet."))


class FirmwareActivateIn(ApiModel):
    image_id: int = Field(ge=1)
    reload: Literal["none", "now", "at"] = "none"
    reload_at: str | None = Field(default=None, max_length=40)

    @model_validator(mode="after")
    def reload_time(self):
        if (self.reload == "at") != (self.reload_at is not None):
            raise ValueError("reload_at is required exactly for reload='at'")
        return self


def _check_activate(ctx: OperationContext) -> None:
    body: FirmwareActivateIn = ctx.body
    if body.reload != "none":
        features.require(features.for_switch(ctx.driver, ctx.switch), "reload")
    ctx.data["image"] = _image(body.image_id, ctx.driver.id)
    ctx.data["run_at"] = parse_run_at(body.reload_at) if body.reload == "at" else None


def _plan_activate(ctx: OperationContext) -> ChangePlan:
    body: FirmwareActivateIn = ctx.body
    state = ctx.driver.read_firmware(ctx.session)
    install = state.get("install_mode") is True
    ctx.basis["install_mode"] = install
    if install and body.reload == "none":
        raise InvalidInputError(t(
            "Im Install-Modus startet die Aktivierung den Switch neu; bitte „jetzt“ oder einen Zeitpunkt wählen.",
        ))
    # Install mode + "at": the reload job runs the activation (it reloads by itself).
    reload_now = body.reload == "now" or (install and body.reload == "at")
    plan = ctx.driver.plan_firmware_activate(ctx.session, ctx.data["image"], state, reload_now)
    ctx.data["install"] = install
    if body.reload != "none":
        _warn_unsaved(ctx)
    if body.reload == "at":
        ctx.warnings.append(t("Neustart ist für {run_at} UTC geplant.", run_at=ctx.data["run_at"]))
    return replace(plan, risk=t(RELOAD_RISK) if reload_now else t(ACTIVATE_RISK))


def _activate_job(ctx: OperationContext):
    if ctx.body.reload == "at" and ctx.data.get("install"):
        return "reload", ctx.data["run_at"], {"image_id": ctx.body.image_id}
    return None


def _after_activate(ctx: OperationContext, result) -> None:
    if not result["ok"]:
        return
    if ctx.body.reload == "now":
        config_state.mark_unknown(ctx.switch["id"])
    elif ctx.body.reload == "at":
        scheduler.create_job("reload", ctx.switch["id"], ctx.data["run_at"], {}, ctx.principal.username)


# --- Reload -------------------------------------------------------------------------------


class ReloadNowIn(ApiModel):
    pass


class ReloadScheduleIn(ApiModel):
    run_at: str = Field(min_length=10, max_length=40)


def _plan_reload(ctx: OperationContext) -> ChangePlan:
    _warn_unsaved(ctx)
    return replace(ctx.driver.plan_reload(ctx.session), risk=t(RELOAD_RISK))


def _check_schedule(ctx: OperationContext) -> None:
    ctx.data["run_at"] = parse_run_at(ctx.body.run_at)


def _plan_schedule(ctx: OperationContext) -> ChangePlan:
    plan = _plan_reload(ctx)
    return replace(plan, message=t("Neustart geplant für {run_at} UTC.", run_at=ctx.data["run_at"]))


# --- Diagnostics actions --------------------------------------------------------------------


class PortDiagIn(ApiModel):
    interface: str = Field(min_length=1, max_length=100)


def _check_port(ctx: OperationContext) -> None:
    ctx.data["interface"] = ctx.driver.validate_interface(ctx.body.interface)


def _check_counters(ctx: OperationContext) -> None:
    if not ctx.driver.can_clear_counters:
        raise UnsupportedFeatureError("diag_counters", COUNTERS_CLEAR_UNSUPPORTED)
    _check_port(ctx)


def _plan_counters_clear(ctx: OperationContext) -> ChangePlan:
    port_basis(ctx, ctx.data["interface"])
    return ctx.driver.plan_counters_clear(ctx.session, ctx.data["interface"])


def _plan_cable_test(ctx: OperationContext) -> ChangePlan:
    port_basis(ctx, ctx.data["interface"])
    plan = ctx.driver.plan_cable_test(ctx.session, ctx.data["interface"])
    return replace(plan, warnings=tuple(dict.fromkeys((*plan.warnings, t(CABLE_TEST_WARNING)))))


register(OperationSpec(
    kind="firmware-stage",
    audit_action="firmware-stage",
    role=Role.ADMIN,
    features=("firmware",),
    body=FirmwareStageIn,
    interface=lambda body: None,
    check=_check_stage,
    plan=_plan_stage,
    deferred=True,
    marks=None,
))

register(OperationSpec(
    kind="firmware-activate",
    audit_action="firmware-activate",
    role=Role.ADMIN,
    features=("firmware",),
    body=FirmwareActivateIn,
    interface=lambda body: None,
    check=_check_activate,
    plan=_plan_activate,
    after=_after_activate,
    job=_activate_job,
    marks=None,
))

register(OperationSpec(
    kind="reload-now",
    audit_action="reload",
    role=Role.ADMIN,
    features=("reload",),
    body=ReloadNowIn,
    interface=lambda body: None,
    plan=_plan_reload,
    audit_detail=lambda body: "",
    marks="unknown",
))

register(OperationSpec(
    kind="reload-schedule",
    audit_action="schedule-reload",
    role=Role.ADMIN,
    features=("reload",),
    body=ReloadScheduleIn,
    interface=lambda body: None,
    check=_check_schedule,
    plan=_plan_schedule,
    deferred=True,
    job=lambda ctx: ("reload", ctx.data["run_at"], {}),
    marks=None,
))

register(OperationSpec(
    kind="counters-clear",
    audit_action="clear-counters",
    role=Role.OPERATOR,
    features=("diag_counters",),
    body=PortDiagIn,
    interface=lambda body: body.interface,
    check=_check_counters,
    plan=_plan_counters_clear,
    audit_detail=lambda body: "",
    actions_only=True,
))

register(OperationSpec(
    kind="cable-test",
    audit_action="cable-test",
    role=Role.OPERATOR,
    features=("cable_test",),
    body=PortDiagIn,
    interface=lambda body: body.interface,
    check=_check_port,
    plan=_plan_cable_test,
    audit_detail=lambda body: "",
    actions_only=True,
))


# --- Scheduler jobs -----------------------------------------------------------------------


def _run_job(job: dict, feature: str, build) -> dict:
    """Open a session for the job's switch under its write lock and execute ``build(driver, session, switch)``."""
    connection = db.get_switch_connection(job["switch_id"]) if job.get("switch_id") is not None else None
    if not connection:
        return {"ok": False, "message": t("Switch nicht gefunden")}
    switch, credentials = connection["switch"], connection["credentials"]
    if not credentials:
        return {"ok": False, "message": t(
            "Für diesen Switch fehlen Zugangsdaten für die gewählte Quelle (global/eigen).",
        )}
    driver = get_driver(switch.get("device_type"))
    features.require(features.for_switch(driver, switch), feature)
    with write_lock(
        "switch", switch["id"], t("Für diesen Switch wird bereits eine Änderung ausgeführt."),
        t("Ein anderer Serverprozess bearbeitet diesen Switch."),
    ), driver.session(switch, credentials) as session:
        plan = _long_running(build(driver, session, switch))
        result = driver.execute_plan(session, plan)
    return {"ok": result["ok"], "message": result["message"], "switch_id": switch["id"]}


@invalidates_reads
def run_firmware_stage_job(job: dict) -> dict:
    """Job ``firmware-stage``: issue the transfer ticket, download and verify the image."""
    image_id = job["params"].get("image_id")

    def build(driver, session, switch):
        return stage_plan(driver, session, switch, _image(image_id, driver.id), applying=True)

    result = _run_job(job, "firmware", build)
    return {"ok": result["ok"], "message": result["message"]}


@invalidates_reads
def run_reload_job(job: dict) -> dict:
    """Job ``reload``: plain reload, or (``params.image_id``) the install-mode activation that reloads."""
    image_id = job["params"].get("image_id")

    def build(driver, session, switch):
        if image_id is None:
            return driver.plan_reload(session)
        state = driver.read_firmware(session)
        return driver.plan_firmware_activate(session, _image(image_id, driver.id), state, True)

    result = _run_job(job, "reload", build)
    if result["ok"]:
        config_state.mark_unknown(result["switch_id"])
    return {"ok": result["ok"], "message": result["message"] or t("Neustart ausgelöst.")}


scheduler.JOB_HANDLERS["firmware-stage"] = run_firmware_stage_job
scheduler.JOB_HANDLERS["reload"] = run_reload_job
