"""Port operations: port-configure (port dialog) and port-state (enable/disable)."""

from typing import Literal, Optional

from pydantic import Field, model_validator

from ...auth import Role
from ...i18n import t
from .. import features, service
from ..catalog import POE_STANDARDS
from ..drivers.base import PortChange
from ..errors import InvalidInputError
from ..operations import ApiModel, OperationContext, OperationSpec, operator_refused, port_basis, register
from ..validation import MAX_VLAN_LIST_LENGTH, parse_vlan_list

# Body fields operators may set; everything else needs an administrator.
OPERATOR_FIELDS = frozenset({
    "description", "access_vlan", "voice_vlan", "shutdown", "poe_mode", "poe_standard", "speed", "duplex",
})


class PortConfigureIn(ApiModel):
    interface: str = Field(min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=200)
    mode: Optional[Literal["access", "trunk"]] = None
    access_vlan: Optional[int] = Field(default=None, ge=1, le=4094)
    native_vlan: Optional[int] = Field(default=None, ge=1, le=4094)
    trunk_allowed_vlan: Optional[str] = Field(default=None, max_length=MAX_VLAN_LIST_LENGTH)
    voice_vlan: Optional[int] = Field(default=None, ge=0, le=4094)
    edge_port: Optional[bool] = None
    speed: Optional[Literal["auto", "10", "100", "1000"]] = None
    duplex: Optional[Literal["auto", "half", "full"]] = None
    shutdown: Optional[bool] = None
    poe_mode: Optional[Literal["auto", "static", "never"]] = None
    poe_standard: Optional[Literal[("default", *POE_STANDARDS)]] = None

    @model_validator(mode="after")
    def validate_poe_profile(self):
        if self.poe_standard is not None and self.poe_mode not in {"auto", "static"}:
            raise ValueError(t("Ein PoE-Leistungsprofil erfordert den PoE-Modus auto oder static."))
        return self

    def set_fields(self) -> set[str]:
        return {name for name in type(self).model_fields if name != "interface" and getattr(self, name) is not None}

    def port_change(self) -> PortChange:
        return PortChange(
            description=self.description,
            mode=self.mode,
            access_vlan=self.access_vlan,
            native_vlan=self.native_vlan,
            trunk_allowed_vlans=(
                parse_vlan_list(self.trunk_allowed_vlan) if self.trunk_allowed_vlan is not None else None
            ),
            voice_vlan=self.voice_vlan,
            edge_port=self.edge_port,
            speed=self.speed,
            duplex=self.duplex,
            shutdown=self.shutdown,
            poe_mode=self.poe_mode,
            poe_standard=self.poe_standard,
        )


class PortStateIn(ApiModel):
    interface: str = Field(min_length=1, max_length=100)
    enabled: bool


def _check_configure(ctx: OperationContext) -> None:
    body: PortConfigureIn = ctx.body
    if not body.set_fields():
        raise InvalidInputError(t("Es wurde keine Änderung angegeben."))
    if not ctx.principal.can_edit and body.set_fields() - OPERATOR_FIELDS:
        raise operator_refused()
    change = body.port_change()
    service.check_port_change(features.for_switch(ctx.driver, ctx.switch), change)
    interface = ctx.driver.validate_interface(body.interface)
    ctx.driver.validate_port_change(interface, change)
    ctx.data.update(interface=interface, change=change)


def _plan_configure(ctx: OperationContext):
    driver, interface, change = ctx.driver, ctx.data["interface"], ctx.data["change"]
    detail = port_basis(ctx, interface, change)
    overrides = driver.runtime_overrides(detail) if detail else {}
    if overrides:
        service.check_port_change(features.for_switch(driver, ctx.switch, overrides), change)
    return driver.plan_port_change(ctx.session, interface, change, detail)


def _configure_detail(body: PortConfigureIn) -> str:
    return ", ".join(f"{key}={value}" for key, value in body.port_change().audit_items())


def _check_state(ctx: OperationContext) -> None:
    ctx.data["interface"] = ctx.driver.validate_interface(ctx.body.interface)


def _plan_state(ctx: OperationContext):
    port_basis(ctx, ctx.data["interface"])
    return ctx.driver.plan_port_state(ctx.session, ctx.data["interface"], ctx.body.enabled)


register(OperationSpec(
    kind="port-configure",
    audit_action="configure-interface",
    role=Role.OPERATOR,
    features=(),  # every set field is checked against its own feature (service.CHANGE_FEATURES)
    body=PortConfigureIn,
    interface=lambda body: body.interface,
    check=_check_configure,
    plan=_plan_configure,
    audit_detail=_configure_detail,
))

register(OperationSpec(
    kind="port-state",
    audit_action=lambda body: "port-enable" if body.enabled else "port-disable",
    role=Role.OPERATOR,
    features=("port_state",),
    body=PortStateIn,
    interface=lambda body: body.interface,
    check=_check_state,
    plan=_plan_state,
    audit_detail=lambda body: "",
))


# --- Port actions: bounce, PoE cycle, err-disabled recovery -----------------------


class PortActionIn(ApiModel):
    interface: str = Field(min_length=1, max_length=100)


def _check_action(ctx: OperationContext) -> None:
    ctx.data["interface"] = ctx.driver.validate_interface(ctx.body.interface)


def _plan_bounce(ctx: OperationContext):
    port_basis(ctx, ctx.data["interface"])
    return ctx.driver.plan_port_bounce(ctx.session, ctx.data["interface"])


def _plan_poe_cycle(ctx: OperationContext):
    driver = ctx.driver
    detail = port_basis(ctx, ctx.data["interface"])
    overrides = driver.runtime_overrides(detail) if detail else {}
    if overrides:
        features.require(features.for_switch(driver, ctx.switch, overrides), "poe_cycle")
    return driver.plan_poe_cycle(ctx.session, ctx.data["interface"])


def _plan_errdisable(ctx: OperationContext):
    port_basis(ctx, ctx.data["interface"])
    return ctx.driver.plan_errdisable_recover(ctx.session, ctx.data["interface"])


for _kind, _feature, _plan in (
    ("port-bounce", "port_bounce", _plan_bounce),
    ("poe-cycle", "poe_cycle", _plan_poe_cycle),
    ("errdisable-recover", "errdisable_recovery", _plan_errdisable),
):
    register(OperationSpec(
        kind=_kind,
        audit_action=_kind,
        role=Role.OPERATOR,
        features=(_feature,),
        body=PortActionIn,
        interface=lambda body: body.interface,
        check=_check_action,
        plan=_plan,
        audit_detail=lambda body: "",
        actions_only=True,
    ))
