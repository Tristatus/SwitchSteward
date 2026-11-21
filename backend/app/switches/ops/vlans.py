"""VLAN tab operations: vlan-create, vlan-rename, vlan-delete."""

from dataclasses import replace
from typing import Optional

from pydantic import Field

from ...auth import Role
from ...i18n import t
from .. import features, service, vlans
from ..errors import InvalidInputError
from ..operations import ApiModel, OperationContext, OperationSpec, register
from ..validation import validate_vlan_id

MANAGEMENT_VLAN_RISK = "VLAN {vlan} ist das Management-VLAN; SwitchSteward kann den Switch danach eventuell nicht mehr erreichen."


class VlanCreateIn(ApiModel):
    vlan_id: int = Field(ge=1, le=4094)
    name: Optional[str] = Field(default=None, max_length=32)


class VlanRenameIn(ApiModel):
    vlan_id: int = Field(ge=1, le=4094)
    name: str = Field(min_length=1, max_length=32)


class VlanDeleteIn(ApiModel):
    vlan_id: int = Field(ge=1, le=4094)


def _require_existing(rows: list[dict], vlan_id: int) -> None:
    if not any(row["id"] == vlan_id for row in rows):
        raise InvalidInputError(t("VLAN {vlan} existiert auf dem Switch nicht.", vlan=vlan_id))


def _refuse_vtp_lock(ctx: OperationContext) -> None:
    lock = vlans.vtp_lock(service.vtp_status_for_vlans(ctx.driver, ctx.switch, ctx.session))
    if lock is not None:
        raise InvalidInputError(lock["reason"])


def _verify(present: bool):
    def verify(ctx: OperationContext, result):
        name = getattr(ctx.body, "name", None) or None
        return vlans.verify(result, ctx.driver.read_vlans(ctx.session), ctx.body.vlan_id, present=present, name=name)
    return verify


# --- vlan-create -----------------------------------------------------------------------


def _check_create(ctx: OperationContext) -> None:
    vlan_id = validate_vlan_id(ctx.body.vlan_id)
    if vlan_id > ctx.driver.max_vlan_id:
        raise InvalidInputError(t(
            "VLAN-ID außerhalb des gültigen Bereichs 1-{max}: {value}", max=ctx.driver.max_vlan_id, value=vlan_id,
        ))
    if ctx.body.name:
        vlans.validate_vlan_name(ctx.body.name)
        features.require(features.for_switch(ctx.driver, ctx.switch), "vlan_rename")


def _plan_create(ctx: OperationContext):
    driver, session, vlan_id = ctx.driver, ctx.session, ctx.body.vlan_id
    rows = driver.read_vlans(session)
    if any(row["id"] == vlan_id for row in rows):
        raise InvalidInputError(t("VLAN {vlan} existiert bereits.", vlan=vlan_id))
    max_vlans = driver.read_vlan_constraints(session).max_vlans
    if max_vlans is not None and len(rows) >= max_vlans:
        raise InvalidInputError(t("Die maximale Anzahl von {count} VLANs ist erreicht.", count=max_vlans))
    blocker = vlans.vtp_create_blocker(service.vtp_status_for_vlans(driver, ctx.switch, session), vlan_id)
    if blocker is not None:
        raise InvalidInputError(blocker)
    name = vlans.validate_vlan_name(ctx.body.name) if ctx.body.name else None
    return driver.plan_vlan_create(session, vlan_id, name)


def _create_detail(body: VlanCreateIn) -> str:
    return f"vlan={body.vlan_id}" + (f" name={body.name!r}" if body.name else "")


# --- vlan-rename -----------------------------------------------------------------------


def _check_rename(ctx: OperationContext) -> None:
    validate_vlan_id(ctx.body.vlan_id)
    vlans.validate_vlan_name(ctx.body.name)


def _plan_rename(ctx: OperationContext):
    _refuse_vtp_lock(ctx)
    _require_existing(ctx.driver.read_vlans(ctx.session), ctx.body.vlan_id)
    return ctx.driver.plan_vlan_rename(ctx.session, ctx.body.vlan_id, vlans.validate_vlan_name(ctx.body.name))


# --- vlan-delete -----------------------------------------------------------------------


def _check_delete(ctx: OperationContext) -> None:
    validate_vlan_id(ctx.body.vlan_id)


def _management_vlan(ctx: OperationContext) -> int | None:
    if not features.for_switch(ctx.driver, ctx.switch)["management_path"].supported:
        return None
    try:
        return ctx.driver.read_management_path(ctx.session).get("management_vlan")
    except Exception:
        ctx.warnings.append(t("Das Management-VLAN konnte nicht ermittelt werden."))
        return None


def _plan_delete(ctx: OperationContext):
    driver, session, vlan_id = ctx.driver, ctx.session, ctx.body.vlan_id
    _refuse_vtp_lock(ctx)
    _require_existing(driver.read_vlans(session), vlan_id)
    usage, unreadable = vlans.vlan_usage(*service.read_vlan_ports(driver, session))
    reason = vlans.delete_blocker(vlan_id, usage, unreadable, driver.read_vlan_constraints(session))
    if reason is not None:
        raise InvalidInputError(reason)
    plan = driver.plan_vlan_delete(session, vlan_id)
    if not ctx.applying and _management_vlan(ctx) == vlan_id:
        plan = replace(plan, risk=t(MANAGEMENT_VLAN_RISK, vlan=vlan_id))
    return plan


register(OperationSpec(
    kind="vlan-create",
    audit_action="create-vlan",
    role=Role.ADMIN,
    features=("vlan_create",),
    body=VlanCreateIn,
    interface=lambda body: None,
    check=_check_create,
    plan=_plan_create,
    verify=_verify(present=True),
    audit_detail=_create_detail,
))

register(OperationSpec(
    kind="vlan-rename",
    audit_action="rename-vlan",
    role=Role.ADMIN,
    features=("vlan_rename",),
    body=VlanRenameIn,
    interface=lambda body: None,
    check=_check_rename,
    plan=_plan_rename,
    verify=_verify(present=True),
    audit_detail=lambda body: f"vlan={body.vlan_id} name={body.name!r}",
))

register(OperationSpec(
    kind="vlan-delete",
    audit_action="delete-vlan",
    role=Role.ADMIN,
    features=("vlan_delete",),
    body=VlanDeleteIn,
    interface=lambda body: None,
    check=_check_delete,
    plan=_plan_delete,
    verify=_verify(present=False),
    audit_detail=lambda body: f"vlan={body.vlan_id}",
))


# --- vlan-voice -------------------------------------------------------------


class VlanVoiceIn(ApiModel):
    vlan_id: int = Field(ge=1, le=4094)
    voice: bool


def _plan_voice(ctx: OperationContext):
    _require_existing(ctx.driver.read_vlans(ctx.session), ctx.body.vlan_id)
    return ctx.driver.plan_vlan_voice(ctx.session, ctx.body.vlan_id, ctx.body.voice)


register(OperationSpec(
    kind="vlan-voice",
    audit_action="set-vlan-voice",
    role=Role.ADMIN,
    features=("vlan_voice",),
    body=VlanVoiceIn,
    interface=lambda body: None,
    check=_check_delete,
    plan=_plan_voice,
    audit_detail=lambda body: f"vlan={body.vlan_id} voice={body.voice}",
))
