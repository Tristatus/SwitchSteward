"""Layer-2 operations: link aggregation (lag-create|update|delete) and spanning tree (stp-*)."""

from dataclasses import replace
from typing import Literal, Optional

from pydantic import Field, field_validator, model_validator

from ...auth import Role
from ...i18n import t
from .. import features, uplinks
from ..errors import InvalidInputError
from ..operations import ApiModel, OperationContext, OperationSpec, register
from ..validation import MAX_VLAN_LIST_LENGTH, parse_vlan_list

MAX_LAG_MEMBERS = 8
LAG_UPLINK_RISK = "Die Link-Aggregation betrifft Uplink-Ports: {ports}"
STP_RISK = "Spanning-Tree-Änderungen können das Netz kurzzeitig unterbrechen."

LagMode = Literal["static", "lacp_active", "lacp_passive"]
StpMode = Literal["stp", "rstp", "pvst", "rapid_pvst", "mstp"]


def _vlans(value: str) -> tuple[int, ...]:
    """A non-empty explicit VLAN list (``all``/``none`` are not allowed here)."""
    selection = parse_vlan_list(value)
    if not isinstance(selection, tuple) or not selection:
        raise InvalidInputError(t("Bitte eine VLAN-Liste wie 10,20-30 angeben."))
    return selection


def _require_option(ctx: OperationContext, feature: str, value: str) -> None:
    options = features.for_switch(ctx.driver, ctx.switch)[feature].options
    if options is not None and value not in options:
        raise InvalidInputError(t("Diese Einstellung wird vom Switch nicht unterstützt: {value}", value=value))


# --- Link aggregation ------------------------------------------------------------


class LagCreateIn(ApiModel):
    lag_id: int = Field(ge=1, le=4096)
    mode: LagMode
    members: list[str] = Field(min_length=1, max_length=MAX_LAG_MEMBERS)


class LagUpdateIn(ApiModel):
    lag_id: int = Field(ge=1, le=4096)
    add: list[str] = Field(default_factory=list, max_length=MAX_LAG_MEMBERS)
    remove: list[str] = Field(default_factory=list, max_length=MAX_LAG_MEMBERS)

    @model_validator(mode="after")
    def some_change(self):
        if not self.add and not self.remove:
            raise ValueError(t("Es wurde keine Änderung angegeben."))
        return self


class LagDeleteIn(ApiModel):
    lag_id: int = Field(ge=1, le=4096)


def _check_lag_id(ctx: OperationContext) -> None:
    if ctx.body.lag_id > ctx.driver.max_lag_id:
        raise InvalidInputError(t(
            "LAG-ID außerhalb des gültigen Bereichs 1-{max}: {value}", max=ctx.driver.max_lag_id, value=ctx.body.lag_id,
        ))


def _members(ctx: OperationContext, names: list[str]) -> tuple[str, ...]:
    driver, result, keys = ctx.driver, [], set()
    for name in names:
        interface = driver.validate_interface(name)
        if not driver.is_physical_interface(interface):
            raise InvalidInputError(t("Nur physische Ports können LAG-Mitglied sein: {port}", port=interface))
        key = driver.interface_key(interface)
        if key in keys:
            raise InvalidInputError(t("Port {port} ist doppelt angegeben.", port=interface))
        keys.add(key)
        result.append(interface)
    return tuple(result)


def _lag_index(ctx: OperationContext) -> tuple[dict | None, dict[str, int]]:
    """The LAG of the body and member key -> LAG id of every LAG."""
    lags = ctx.driver.read_lags(ctx.session)
    owner = {
        ctx.driver.interface_key(member["interface"]): lag["id"]
        for lag in lags for member in lag.get("members") or ()
    }
    return next((lag for lag in lags if lag["id"] == ctx.body.lag_id), None), owner


def _refuse_foreign(ctx: OperationContext, members, owner: dict[str, int]) -> None:
    for member in members:
        other = owner.get(ctx.driver.interface_key(member))
        if other is not None and other != ctx.body.lag_id:
            raise InvalidInputError(t("Port {port} ist bereits Mitglied von LAG {lag}.", port=member, lag=other))


def _uplink_risk(ctx: OperationContext, plan, names) -> object:
    found = uplinks.detect(ctx.driver, ctx.session, ctx.switch)
    hits = [name for name in names if ctx.driver.interface_key(name) in found]
    if hits and plan.risk is None:
        return replace(plan, risk=t(LAG_UPLINK_RISK, ports=", ".join(dict.fromkeys(hits))))
    return plan


def _require_lag(lag: dict | None, lag_id: int) -> dict:
    if lag is None:
        raise InvalidInputError(t("LAG {lag} existiert auf dem Switch nicht.", lag=lag_id))
    return lag


def _member_names(lag: dict) -> list[str]:
    return [member["interface"] for member in lag.get("members") or ()]


def _check_lag_create(ctx: OperationContext) -> None:
    _check_lag_id(ctx)
    _require_option(ctx, "lag", ctx.body.mode)
    ctx.data["members"] = _members(ctx, ctx.body.members)


def _plan_lag_create(ctx: OperationContext):
    lag, owner = _lag_index(ctx)
    if lag is not None:
        raise InvalidInputError(t("LAG {lag} existiert bereits.", lag=ctx.body.lag_id))
    members = ctx.data["members"]
    _refuse_foreign(ctx, members, owner)
    plan = ctx.driver.plan_lag_create(ctx.session, ctx.body.lag_id, ctx.body.mode, members)
    return _uplink_risk(ctx, plan, members)


def _check_lag_update(ctx: OperationContext) -> None:
    _check_lag_id(ctx)
    ctx.data["add"] = _members(ctx, ctx.body.add)
    ctx.data["remove"] = tuple(ctx.driver.validate_interface(name) for name in ctx.body.remove)


def _plan_lag_update(ctx: OperationContext):
    driver = ctx.driver
    lag, owner = _lag_index(ctx)
    lag = _require_lag(lag, ctx.body.lag_id)
    current = {driver.interface_key(name) for name in _member_names(lag)}
    add, remove = ctx.data["add"], ctx.data["remove"]
    _refuse_foreign(ctx, add, owner)
    for name in add:
        if driver.interface_key(name) in current:
            raise InvalidInputError(t("Port {port} ist bereits Mitglied von LAG {lag}.", port=name, lag=lag["id"]))
    for name in remove:
        if driver.interface_key(name) not in current:
            raise InvalidInputError(t("Port {port} ist kein Mitglied von LAG {lag}.", port=name, lag=lag["id"]))
    remaining = len(current) - len({driver.interface_key(name) for name in remove}) + len(add)
    if remaining < 1:
        raise InvalidInputError(t("Ein LAG braucht mindestens ein Mitglied; zum Entfernen bitte löschen."))
    if remaining > MAX_LAG_MEMBERS:
        raise InvalidInputError(t("Ein LAG hat höchstens {count} Mitglieder.", count=MAX_LAG_MEMBERS))
    plan = driver.plan_lag_update(ctx.session, lag["id"], add, remove)
    return _uplink_risk(ctx, plan, (lag["interface"], *add, *remove))


def _plan_lag_delete(ctx: OperationContext):
    lag, _owner = _lag_index(ctx)
    lag = _require_lag(lag, ctx.body.lag_id)
    plan = ctx.driver.plan_lag_delete(ctx.session, lag["id"])
    return _uplink_risk(ctx, plan, (lag["interface"], *_member_names(lag)))


register(OperationSpec(
    kind="lag-create",
    audit_action="create-lag",
    role=Role.ADMIN,
    features=("lag",),
    body=LagCreateIn,
    interface=lambda body: None,
    check=_check_lag_create,
    plan=_plan_lag_create,
))

register(OperationSpec(
    kind="lag-update",
    audit_action="update-lag",
    role=Role.ADMIN,
    features=("lag",),
    body=LagUpdateIn,
    interface=lambda body: None,
    check=_check_lag_update,
    plan=_plan_lag_update,
))

register(OperationSpec(
    kind="lag-delete",
    audit_action="delete-lag",
    role=Role.ADMIN,
    features=("lag",),
    body=LagDeleteIn,
    interface=lambda body: None,
    check=_check_lag_id,
    plan=_plan_lag_delete,
))


# --- Spanning tree ---------------------------------------------------------------


class StpModeIn(ApiModel):
    mode: StpMode


class StpPriorityIn(ApiModel):
    vlans: Optional[str] = Field(default=None, min_length=1, max_length=MAX_VLAN_LIST_LENGTH)
    instance: Optional[int] = Field(default=None, ge=0, le=64)
    priority: int = Field(ge=0, le=61440)

    @field_validator("priority")
    @classmethod
    def step(cls, value: int) -> int:
        if value % 4096:
            raise ValueError(t("Die Priorität muss ein Vielfaches von 4096 sein."))
        return value

    @model_validator(mode="after")
    def one_target(self):
        if self.vlans is not None and self.instance is not None:
            raise ValueError(t("Bitte entweder VLANs oder eine Instanz angeben."))
        return self


class MstInstanceIn(ApiModel):
    id: int = Field(ge=1, le=64)
    vlans: str = Field(min_length=1, max_length=MAX_VLAN_LIST_LENGTH)


class StpMstIn(ApiModel):
    name: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9._-]+$")
    revision: int = Field(ge=0, le=65535)
    instances: list[MstInstanceIn] = Field(default_factory=list, max_length=64)


class StpPortIn(ApiModel):
    interface: str = Field(min_length=1, max_length=100)
    instance_or_vlan: Optional[int] = Field(default=None, ge=0, le=4094)
    cost: Optional[int] = Field(default=None, ge=1, le=200000000)
    priority: Optional[int] = Field(default=None, ge=0, le=240)

    @field_validator("priority")
    @classmethod
    def step(cls, value: int | None) -> int | None:
        if value is not None and value % 16:
            raise ValueError(t("Die Port-Priorität muss ein Vielfaches von 16 sein."))
        return value

    @model_validator(mode="after")
    def some_change(self):
        if self.cost is None and self.priority is None:
            raise ValueError(t("Es wurde keine Änderung angegeben."))
        return self


def _with_stp_risk(plan):
    return plan if plan.risk else replace(plan, risk=t(STP_RISK))


def _check_stp_mode(ctx: OperationContext) -> None:
    _require_option(ctx, "stp", ctx.body.mode)


def _check_stp_priority(ctx: OperationContext) -> None:
    ctx.data["vlans"] = _vlans(ctx.body.vlans) if ctx.body.vlans is not None else None


def _check_stp_mst(ctx: OperationContext) -> None:
    mapping, seen_ids, seen_vlans = [], set(), {}
    for instance in ctx.body.instances:
        if instance.id in seen_ids:
            raise InvalidInputError(t("MST-Instanz {id} ist doppelt angegeben.", id=instance.id))
        seen_ids.add(instance.id)
        vlans = _vlans(instance.vlans)
        for vlan in vlans:
            if vlan in seen_vlans:
                raise InvalidInputError(t(
                    "VLAN {vlan} ist mehreren MST-Instanzen zugeordnet ({first}, {second}).",
                    vlan=vlan, first=seen_vlans[vlan], second=instance.id,
                ))
            seen_vlans[vlan] = instance.id
        mapping.append((instance.id, vlans))
    ctx.data["instances"] = tuple(mapping)


def _check_stp_port(ctx: OperationContext) -> None:
    ctx.data["interface"] = ctx.driver.validate_interface(ctx.body.interface)


register(OperationSpec(
    kind="stp-mode",
    audit_action="set-stp-mode",
    role=Role.ADMIN,
    features=("stp",),
    body=StpModeIn,
    interface=lambda body: None,
    check=_check_stp_mode,
    plan=lambda ctx: _with_stp_risk(ctx.driver.plan_stp_mode(ctx.session, ctx.body.mode)),
))

register(OperationSpec(
    kind="stp-priority",
    audit_action="set-stp-priority",
    role=Role.ADMIN,
    features=("stp",),
    body=StpPriorityIn,
    interface=lambda body: None,
    check=_check_stp_priority,
    plan=lambda ctx: ctx.driver.plan_stp_priority(
        ctx.session, ctx.body.priority, ctx.data["vlans"], ctx.body.instance,
    ),
))

register(OperationSpec(
    kind="stp-mst",
    audit_action="set-stp-mst",
    role=Role.ADMIN,
    features=("stp", "stp_mst"),
    body=StpMstIn,
    interface=lambda body: None,
    check=_check_stp_mst,
    plan=lambda ctx: _with_stp_risk(ctx.driver.plan_stp_mst(
        ctx.session, ctx.body.name, ctx.body.revision, ctx.data["instances"],
    )),
))

register(OperationSpec(
    kind="stp-port",
    audit_action="set-stp-port",
    role=Role.ADMIN,
    features=("stp",),
    body=StpPortIn,
    interface=lambda body: body.interface,
    check=_check_stp_port,
    plan=lambda ctx: ctx.driver.plan_stp_port(
        ctx.session, ctx.data["interface"], ctx.body.instance_or_vlan, ctx.body.cost, ctx.body.priority,
    ),
))
