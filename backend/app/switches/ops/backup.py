"""Configuration backups around changes and the ``config-restore`` operation.

Backups never abort a change: a failure becomes a warning in the result and an audit
record ``config-backup`` with status ``error``; stored backups are audited with
``trigger=… id=…``. ``save-config`` backs up the startup configuration before and after
saving (``ops.config``); platforms without a save step (``CHANGE_BACKUP_DRIVERS``, MikroTik)
back up the running configuration before and after every configuration change
(``service.apply_change`` calls ``take_change_backup``).
"""

import logging
from dataclasses import replace

from fastapi import HTTPException, status
from pydantic import Field

from ... import backups, transfer
from ...audit import record
from ...auth import Role
from ...i18n import t
from .. import features
from ..errors import InvalidInputError, append_warning
from ..operations import ApiModel, OperationContext, OperationSpec, register

logger = logging.getLogger("switchsteward.switches.backups")

# Drivers without running/startup split: every applied configuration change is backed up.
CHANGE_BACKUP_DRIVERS = frozenset({"mikrotik_routeros"})
RESTORE_RISK = "Der Switch übernimmt die Konfiguration aus dem Backup und startet neu."


def take_backup(ctx: OperationContext, trigger: str, source: str) -> dict | None:
    """Back up the device's ``source`` configuration; never raises (failures become warnings)."""
    driver, switch = ctx.driver, ctx.switch
    if not features.for_switch(driver, switch)["config_backup"].supported:
        return None
    try:
        text = driver.read_startup_config(ctx.session) if source == "startup" else driver.read_running_config(
            ctx.session,
        )
        if text is None:
            return None
        created = backups.create(
            switch, text, trigger, source, ctx.principal.username,
            volatile_patterns=driver.volatile_config_patterns,
        )
    except Exception as exc:
        logger.error("Backup (%s) of switch %s failed", trigger, switch.get("name"), exc_info=exc)
        append_warning(ctx.warnings, t("Backup konnte nicht erstellt werden: {error}", error=str(exc)))
        record("config-backup", target=switch["name"], detail=f"trigger={trigger} error={exc}", status="error")
        return None
    if created is not None:
        record("config-backup", target=switch["name"], detail=f"trigger={trigger} id={created['id']}")
    return created


def wants_change_backups(ctx: OperationContext, spec: OperationSpec, plan) -> bool:
    """Running-config backups around a change: only platforms without save step, only real config changes."""
    return (
        ctx.driver.id in CHANGE_BACKUP_DRIVERS and not spec.actions_only and not spec.deferred and not plan.reloads
    )


def take_change_backup(ctx: OperationContext, trigger: str) -> None:
    take_backup(ctx, trigger, "running")


# --- config-restore ---------------------------------------------------------------------


class ConfigRestoreIn(ApiModel):
    backup_id: int = Field(ge=1)


def _check_restore(ctx: OperationContext) -> None:
    backup = backups.get_backup(ctx.switch["id"], ctx.body.backup_id)
    if backup is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=t("Backup nicht gefunden."))
    try:
        backups.read_text(backup["id"])
    except (LookupError, ValueError) as exc:
        raise InvalidInputError(str(exc)) from None


def _plan_restore(ctx: OperationContext):
    driver = ctx.driver
    location = transfer.location_for(
        driver, "backup", ctx.body.backup_id, ctx.switch["id"], driver.restore_filename, applying=ctx.applying,
    )
    plan = driver.plan_config_restore(ctx.session, location)
    return replace(
        plan, risk=t(RESTORE_RISK), reloads=True,
        secrets=tuple(dict.fromkeys(plan.secrets + transfer.location_secrets(location))),
    )


def _before_restore(ctx: OperationContext) -> None:
    take_backup(ctx, "before-restore", "startup")


register(OperationSpec(
    kind="config-restore",
    audit_action="config-restore",
    role=Role.ADMIN,
    features=("config_restore",),
    body=ConfigRestoreIn,
    interface=lambda body: None,
    check=_check_restore,
    plan=_plan_restore,
    before=_before_restore,
    marks="unknown",
))
