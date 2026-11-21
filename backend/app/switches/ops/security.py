"""Port security tab operations: port-security-configure, security-global-configure, profile-apply."""

from dataclasses import replace
from typing import Literal, Optional

from pydantic import Field

from ...auth import Role
from ...i18n import t
from .. import features, profiles, service
from ..drivers.base import PortChange
from ..drivers.plans import (
    Dot1xSettings,
    PortSecuritySettings,
    SecurityChange,
    SecurityGlobalChange,
    StormControlSettings,
    StpGuardSettings,
    combine_plans,
)
from ..errors import ChangeConflict, InvalidInputError
from ..operations import ApiModel, OperationContext, OperationSpec, port_basis, register
from ..validation import MAX_VLAN_LIST_LENGTH, parse_vlan_list
from .ports import PortConfigureIn

TRUNK_PORT_SECURITY = "Port-Security ist nur an Access-Ports möglich."
DAI_RISK = "Dynamic ARP Inspection kann den Management-Verkehr blockieren, wenn Uplinks nicht vertrauenswürdig sind."
RADIUS_REQUIRED = "Für 802.1X muss zuerst ein RADIUS-Server konfiguriert werden."
NO_CHANGE = "Es wurde keine Änderung angegeben."
SKIPPED_FIELDS = "Nicht übernommen (inkompatibel): {fields}."
PROFILE_NOT_FOUND = "Das Port-Profil existiert nicht."
PROFILE_NOTHING_SUPPORTED = "Kein Feld des Profils wird von diesem Switch unterstützt."
VLAN_LIST_ALL = "Bitte konkrete VLANs angeben."
STALE = "Der Switch-Zustand hat sich seit der Vorschau geändert. Bitte Vorschau neu erstellen."
SECURITY_FEATURES = (
    "port_security", "dot1x", "stp_guard", "storm_control", "dhcp_snooping", "arp_inspection", "ip_source_guard",
)


# --- Bodies ------------------------------------------------------------------------------


class PortSecurityBlock(ApiModel):
    enabled: bool
    max_macs: Optional[int] = Field(default=None, ge=1, le=1024)
    sticky: Optional[bool] = None
    violation: Optional[Literal["protect", "restrict", "shutdown"]] = None


class Dot1xBlock(ApiModel):
    mode: Literal["off", "dot1x", "mab", "dot1x_mab"]
    host_mode: Optional[Literal["single", "multi_auth", "multi_host", "multi_domain"]] = None
    guest_vlan: Optional[int] = Field(default=None, ge=0, le=4094)
    auth_fail_vlan: Optional[int] = Field(default=None, ge=0, le=4094)


class StpGuardBlock(ApiModel):
    bpdu_guard: Optional[bool] = None
    root_guard: Optional[bool] = None
    loop_guard: Optional[bool] = None


class StormControlBlock(ApiModel):
    broadcast: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    multicast: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    unknown_unicast: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    action: Optional[Literal["drop", "shutdown"]] = None


class SecuritySettingsIn(ApiModel):
    """Body of port-security-configure without the port (also the ``security`` part of a port profile)."""

    port_security: Optional[PortSecurityBlock] = None
    dot1x: Optional[Dot1xBlock] = None
    stp_guard: Optional[StpGuardBlock] = None
    storm_control: Optional[StormControlBlock] = None
    dhcp_snooping_trust: Optional[bool] = None
    arp_inspection_trust: Optional[bool] = None
    ip_source_guard: Optional[bool] = None


class PortSecurityIn(SecuritySettingsIn):
    interface: str = Field(min_length=1, max_length=100)


class DhcpSnoopingBlock(ApiModel):
    enabled: bool
    vlans: Optional[str] = Field(default=None, max_length=MAX_VLAN_LIST_LENGTH)


class ArpInspectionBlock(ApiModel):
    vlans: str = Field(max_length=MAX_VLAN_LIST_LENGTH)


class Dot1xGlobalBlock(ApiModel):
    enabled: bool


class SecurityGlobalIn(ApiModel):
    dhcp_snooping: Optional[DhcpSnoopingBlock] = None
    arp_inspection: Optional[ArpInspectionBlock] = None
    dot1x: Optional[Dot1xGlobalBlock] = None


class ProfileApplyIn(ApiModel):
    interface: str = Field(min_length=1, max_length=100)
    profile_id: int = Field(ge=1)


# --- Feature checks ----------------------------------------------------------------------


def _requirements(values: dict) -> list[tuple[str, str, str | None]]:
    """(field path, feature, option or None) of every set value in a SecuritySettingsIn dump."""
    result = []
    block = values.get("port_security")
    if block is not None:
        result.append(("port_security.enabled", "port_security", None))
        if block.get("max_macs") is not None:
            result.append(("port_security.max_macs", "port_security", None))
        if block.get("violation") is not None:
            result.append(("port_security.violation", "port_security", block["violation"]))
        if block.get("sticky") is not None:
            result.append(("port_security.sticky", "port_security_sticky", None))
    block = values.get("dot1x")
    if block is not None:
        result.append(("dot1x.mode", "dot1x", None if block["mode"] == "off" else block["mode"]))
        if block.get("host_mode") is not None:
            result.append(("dot1x.host_mode", "dot1x_host_mode", block["host_mode"]))
        for name in ("guest_vlan", "auth_fail_vlan"):
            if block.get(name) is not None:
                result.append((f"dot1x.{name}", "dot1x_fallback_vlans", None))
    for name, value in (values.get("stp_guard") or {}).items():
        if value is not None:
            result.append((f"stp_guard.{name}", "stp_guard", name))
    for name, value in (values.get("storm_control") or {}).items():
        if value is None:
            continue
        if name == "action":
            result.append(("storm_control.action", "storm_control_action", value))
        else:
            result.append((f"storm_control.{name}", "storm_control", name))
    for name, feature in (
        ("dhcp_snooping_trust", "dhcp_snooping"),
        ("arp_inspection_trust", "arp_inspection"),
        ("ip_source_guard", "ip_source_guard"),
    ):
        if values.get(name) is not None:
            result.append((name, feature, None))
    return result


def _problem(capabilities, feature: str, option: str | None):
    support = capabilities[feature]
    if not support.supported:
        return support.error(feature)
    if option is not None and support.options is not None and option not in support.options:
        return features.unsupported(service.UNSUPPORTED_OPTION_REASON, value=option).error(feature)
    return None


def check_security_settings(capabilities, settings: SecuritySettingsIn) -> None:
    """Every set value needs its feature and an allowed option (raises the first problem)."""
    for _path, feature, option in _requirements(settings.model_dump()):
        error = _problem(capabilities, feature, option)
        if error is not None:
            raise error


def supported_security_settings(capabilities, settings: dict) -> tuple[dict, list[str]]:
    """Drop unsupported values of a SecuritySettingsIn dump; returns (remaining dump, skipped paths)."""
    values = {key: dict(value) if isinstance(value, dict) else value for key, value in settings.items()}
    skipped = []
    for path, feature, option in _requirements(settings):
        if _problem(capabilities, feature, option) is None:
            continue
        skipped.append(path)
        block, _, name = path.partition(".")
        if not name:
            values.pop(block, None)
        elif name in ("enabled", "mode"):
            values.pop(block, None)  # the block's key value is unusable: the whole block goes
        elif isinstance(values.get(block), dict):
            values[block].pop(name, None)
    for block in ("stp_guard", "storm_control"):
        if isinstance(values.get(block), dict) and not any(v is not None for v in values[block].values()):
            values.pop(block)
    return {key: value for key, value in values.items() if value is not None}, skipped


def security_change(settings: SecuritySettingsIn) -> SecurityChange:
    def build(cls, block):
        return cls(**block.model_dump()) if block is not None else None

    return SecurityChange(
        port_security=build(PortSecuritySettings, settings.port_security),
        dot1x=build(Dot1xSettings, settings.dot1x),
        stp_guard=build(StpGuardSettings, settings.stp_guard),
        storm_control=build(StormControlSettings, settings.storm_control),
        dhcp_snooping_trust=settings.dhcp_snooping_trust,
        arp_inspection_trust=settings.arp_inspection_trust,
        ip_source_guard=settings.ip_source_guard,
    )


def _has_values(settings: SecuritySettingsIn) -> bool:
    return any(value is not None for value in settings.model_dump(exclude={"interface"}).values())


def _refuse_trunk(settings: SecuritySettingsIn, mode: str | None) -> None:
    if settings.port_security is not None and settings.port_security.enabled and mode == "trunk":
        raise InvalidInputError(t(TRUNK_PORT_SECURITY))


# --- port-security-configure ---------------------------------------------------------------


def _check_port(ctx: OperationContext) -> None:
    body: PortSecurityIn = ctx.body
    if not _has_values(body):
        raise InvalidInputError(t(NO_CHANGE))
    check_security_settings(features.for_switch(ctx.driver, ctx.switch), body)
    ctx.data["interface"] = ctx.driver.validate_interface(body.interface)


def _plan_port(ctx: OperationContext):
    interface = ctx.data["interface"]
    detail = port_basis(ctx, interface)
    _refuse_trunk(ctx.body, detail.get("mode"))
    return ctx.driver.plan_port_security(ctx.session, interface, security_change(ctx.body), detail)


# --- security-global-configure -------------------------------------------------------------


def _vlans(value: str | None) -> tuple[int, ...] | None:
    if value is None:
        return None
    if not value.strip():
        return ()
    selection = parse_vlan_list(value)
    if selection == "all":
        raise InvalidInputError(t(VLAN_LIST_ALL))
    return () if selection == "none" else tuple(selection)


def _check_global(ctx: OperationContext) -> None:
    body: SecurityGlobalIn = ctx.body
    capabilities = features.for_switch(ctx.driver, ctx.switch)
    if body.dhcp_snooping is None and body.arp_inspection is None and body.dot1x is None:
        raise InvalidInputError(t(NO_CHANGE))
    if body.dhcp_snooping is not None:
        features.require(capabilities, "dhcp_snooping")
    if body.arp_inspection is not None:
        features.require(capabilities, "arp_inspection")
    if body.dot1x is not None:
        features.require(capabilities, "dot1x")
        if body.dot1x.enabled:
            features.require(capabilities, "device_aaa")
    ctx.data["change"] = SecurityGlobalChange(
        dhcp_snooping_enabled=body.dhcp_snooping.enabled if body.dhcp_snooping else None,
        dhcp_snooping_vlans=_vlans(body.dhcp_snooping.vlans) if body.dhcp_snooping else None,
        arp_inspection_vlans=_vlans(body.arp_inspection.vlans) if body.arp_inspection else None,
        dot1x_enabled=body.dot1x.enabled if body.dot1x else None,
    )


def _plan_global(ctx: OperationContext):
    body: SecurityGlobalIn = ctx.body
    if body.dot1x is not None and body.dot1x.enabled:
        aaa = (ctx.driver.read_device_config(ctx.session) or {}).get("aaa") or {}
        if not aaa.get("radius"):
            raise InvalidInputError(t(RADIUS_REQUIRED))
    plan = ctx.driver.plan_security_global(ctx.session, ctx.data["change"])
    if body.arp_inspection is not None:
        plan = replace(plan, risk=t(DAI_RISK))
    return plan


# --- profile-apply -----------------------------------------------------------------------


def _check_profile(ctx: OperationContext) -> None:
    ctx.data["interface"] = ctx.driver.validate_interface(ctx.body.interface)


def _supported_port_fields(capabilities, values: dict) -> tuple[dict, list[str]]:
    remaining, skipped = dict(values), []
    change = PortConfigureIn(interface="x", **values).port_change()
    for field, feature in service.CHANGE_FEATURES:
        value = getattr(change, field)
        if value is None:
            continue
        option = value if isinstance(value, str) else None
        if _problem(capabilities, feature, option) is not None:
            name = "trunk_allowed_vlan" if field == "trunk_allowed_vlans" else field
            remaining.pop(name, None)
            skipped.append(name)
    return remaining, skipped


def _plan_profile(ctx: OperationContext):
    driver, session, interface = ctx.driver, ctx.session, ctx.data["interface"]
    profile = profiles.get(ctx.body.profile_id)
    if profile is None:
        if ctx.applying:
            raise ChangeConflict("preview_stale", t(STALE))
        raise InvalidInputError(t(PROFILE_NOT_FOUND))
    ctx.basis["profile"] = {"id": profile["id"], "updated_at": profile["updated_at"], "settings": profile["settings"]}
    settings = profile["settings"]
    port_values = settings.get("port") or {}
    full_change = PortConfigureIn(interface=interface, **port_values).port_change() if port_values else PortChange()
    detail = port_basis(ctx, interface, full_change)
    capabilities = features.for_switch(driver, ctx.switch, driver.runtime_overrides(detail) if detail else {})
    port_values, skipped = _supported_port_fields(capabilities, port_values)
    security_values, skipped_security = supported_security_settings(capabilities, settings.get("security") or {})
    skipped += skipped_security
    plans = []
    if port_values:
        port_in = PortConfigureIn(interface=interface, **port_values)
        change = port_in.port_change()
        service.check_port_change(capabilities, change)
        driver.validate_port_change(interface, change)
        plans.append(driver.plan_port_change(session, interface, change, detail))
        mode = port_in.mode or detail.get("mode")
    else:
        mode = detail.get("mode")
    security = SecuritySettingsIn(**security_values)
    if _has_values(security):
        _refuse_trunk(security, mode)
        plans.append(driver.plan_port_security(session, interface, security_change(security), detail))
    if not plans:
        raise InvalidInputError(t(PROFILE_NOTHING_SUPPORTED))
    if skipped:
        ctx.warnings.append(t(SKIPPED_FIELDS, fields=", ".join(skipped)))
    return combine_plans(*plans)


def _profile_detail(body: ProfileApplyIn) -> str:
    profile = profiles.get(body.profile_id)
    return f"profile={profile['name']!r}" if profile else f"profile_id={body.profile_id}"


register(OperationSpec(
    kind="port-security-configure",
    audit_action="configure-port-security",
    role=Role.ADMIN,
    features=(),  # each block is checked against its own feature
    body=PortSecurityIn,
    interface=lambda body: body.interface,
    check=_check_port,
    plan=_plan_port,
))

register(OperationSpec(
    kind="security-global-configure",
    audit_action="configure-security-global",
    role=Role.ADMIN,
    features=(),
    body=SecurityGlobalIn,
    interface=lambda body: None,
    check=_check_global,
    plan=_plan_global,
))

register(OperationSpec(
    kind="profile-apply",
    audit_action="apply-port-profile",
    role=Role.ADMIN,
    features=(),
    body=ProfileApplyIn,
    interface=lambda body: body.interface,
    check=_check_profile,
    plan=_plan_profile,
    audit_detail=_profile_detail,
))
