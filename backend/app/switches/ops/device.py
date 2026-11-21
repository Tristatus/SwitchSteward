"""Device settings operations: identity, services, SNMPv3, AAA, local users, SSH/web
access, layer 3 (SVIs, gateway, static routes), ACLs and port QoS.

Every value is validated before a session is opened (``check``); secrets (keys, passwords)
are write-only: they only go into the driver's plan steps, never into lines, audit or replies.
"""

import re
from dataclasses import replace
from typing import Literal, Optional

from pydantic import Field

from ...auth import Role
from ...i18n import t
from .. import features
from ..drivers.plans import (
    AaaChange,
    AclEntry,
    IdentityChange,
    RadiusServer,
    ServicesChange,
    SnmpUserChange,
    SyslogTarget,
    TacacsServer,
)
from ..errors import InvalidInputError
from ..operations import ApiModel, OperationContext, OperationSpec, register
from ..validation import (
    validate_acl_name,
    validate_banner,
    validate_host,
    validate_hostname,
    validate_ipv4,
    validate_ipv4_prefix,
    validate_secret,
    validate_snmp_text,
    validate_username,
)

ACCESS_RISK = "Änderungen an der Anmeldung können den Zugang von SwitchSteward sperren."
MANAGEMENT_L3_RISK = (
    "Die Änderung betrifft die Management-Adresse oder das Routing des Switches; "
    "SwitchSteward kann den Switch danach eventuell nicht mehr erreichen."
)
MANAGEMENT_ACL_RISK = "Die ACL wird an das Management-Interface gebunden und kann SwitchSteward aussperren."
LOCAL_FALLBACK_REQUIRED = "Die lokale Anmeldung muss als Rückfallebene erhalten bleiben."
OWN_ACCOUNT = "Das Konto, mit dem SwitchSteward sich anmeldet, kann hier nicht geändert werden."
NO_CHANGE = "Es wurde keine Änderung angegeben."
UNSUPPORTED_OPTION_REASON = "Der Wert {value} wird von diesem Gerät nicht unterstützt."
_VLAN_INTERFACE_RE = re.compile(r"^(?:interface\s+)?vlan\s*(\d{1,4})$", re.IGNORECASE)


def _capabilities(ctx: OperationContext) -> dict:
    return features.for_switch(ctx.driver, ctx.switch)


def _require_option(ctx: OperationContext, feature: str, option: str) -> None:
    support = features.require(_capabilities(ctx), feature)
    if support.options is not None and option not in support.options:
        raise features.unsupported(UNSUPPORTED_OPTION_REASON, value=option).error(feature)


def _set_fields(body) -> set[str]:
    return {name for name in type(body).model_fields if getattr(body, name) is not None}


def _require_change(body) -> None:
    if not _set_fields(body):
        raise InvalidInputError(t(NO_CHANGE))


def _with_risk(plan, risk: str | None):
    return replace(plan, risk=risk) if risk and not plan.risk else plan


def _device_config(ctx: OperationContext) -> dict:
    if "device_config" not in ctx.data:
        ctx.data["device_config"] = ctx.driver.read_device_config(ctx.session) or {}
    return ctx.data["device_config"]


def _management_path(ctx: OperationContext) -> dict:
    """Management path for risk checks; only read for previews (apply reuses the preview's risk)."""
    if ctx.applying or not _capabilities(ctx)["management_path"].supported:
        return {}
    try:
        return ctx.driver.read_management_path(ctx.session) or {}
    except Exception:
        ctx.warnings.append(t("Das Management-VLAN konnte nicht ermittelt werden."))
        return {}


def _vlan_interface(name: str) -> int | None:
    match = _VLAN_INTERFACE_RE.fullmatch(name.strip())
    if not match:
        return None
    vlan = int(match.group(1))
    if not 1 <= vlan <= 4094:
        raise InvalidInputError(t("Ungültige VLAN-ID: {value}", value=repr(vlan)))
    return vlan


def _ip_list(values: list[str], validator) -> tuple[str, ...]:
    result = tuple(dict.fromkeys(validator(value) for value in values))
    return result


# --- device-identity -------------------------------------------------------------------


class IdentityIn(ApiModel):
    hostname: Optional[str] = Field(default=None, max_length=63)
    banner: Optional[str] = Field(default=None, max_length=1000)
    snmp_location: Optional[str] = Field(default=None, max_length=255)
    snmp_contact: Optional[str] = Field(default=None, max_length=255)


def _check_identity(ctx: OperationContext) -> None:
    body: IdentityIn = ctx.body
    _require_change(body)
    ctx.data["change"] = IdentityChange(
        hostname=validate_hostname(body.hostname) if body.hostname is not None else None,
        banner=(validate_banner(body.banner) if body.banner else "") if body.banner is not None else None,
        snmp_location=validate_snmp_text(body.snmp_location) if body.snmp_location is not None else None,
        snmp_contact=validate_snmp_text(body.snmp_contact) if body.snmp_contact is not None else None,
    )


def _identity_detail(body: IdentityIn) -> str:
    items = []
    if body.hostname is not None:
        items.append(f"hostname={body.hostname!r}")
    if body.banner is not None:
        items.append(f"banner={len(body.banner)}chars")
    for name in ("snmp_location", "snmp_contact"):
        if getattr(body, name) is not None:
            items.append(f"{name}={getattr(body, name)!r}")
    return " ".join(items)


register(OperationSpec(
    kind="device-identity",
    audit_action="set-device-identity",
    role=Role.ADMIN,
    features=("device_identity",),
    body=IdentityIn,
    interface=lambda body: None,
    check=_check_identity,
    plan=lambda ctx: ctx.driver.plan_device_identity(ctx.session, ctx.data["change"]),
    audit_detail=_identity_detail,
))


# --- device-services -------------------------------------------------------------------


class TimezoneIn(ApiModel):
    name: str = Field(pattern=r"^[A-Za-z]{1,6}$")
    offset_minutes: int = Field(ge=-720, le=840)


class SyslogIn(ApiModel):
    host: str = Field(min_length=1, max_length=253)
    severity: int = Field(ge=0, le=7)


class ServicesIn(ApiModel):
    ntp_servers: Optional[list[str]] = Field(default=None, max_length=4)
    timezone: Optional[TimezoneIn] = None
    dns_servers: Optional[list[str]] = Field(default=None, max_length=3)
    domain_name: Optional[str] = Field(default=None, max_length=253)
    syslog: Optional[list[SyslogIn]] = Field(default=None, max_length=4)


def _check_services(ctx: OperationContext) -> None:
    body: ServicesIn = ctx.body
    _require_change(body)
    syslog = None
    if body.syslog is not None:
        targets = {}
        for item in body.syslog:
            targets[validate_host(item.host)] = item.severity
        syslog = tuple(SyslogTarget(host, severity) for host, severity in targets.items())
    ctx.data["change"] = ServicesChange(
        ntp_servers=_ip_list(body.ntp_servers, validate_host) if body.ntp_servers is not None else None,
        timezone_name=body.timezone.name if body.timezone else None,
        timezone_offset_minutes=body.timezone.offset_minutes if body.timezone else None,
        dns_servers=_ip_list(body.dns_servers, validate_ipv4) if body.dns_servers is not None else None,
        domain_name=(validate_host(body.domain_name) if body.domain_name else "") if body.domain_name is not None else None,
        syslog=syslog,
    )


register(OperationSpec(
    kind="device-services",
    audit_action="set-device-services",
    role=Role.ADMIN,
    features=("device_services",),
    body=ServicesIn,
    interface=lambda body: None,
    check=_check_services,
    plan=lambda ctx: ctx.driver.plan_device_services(ctx.session, ctx.data["change"]),
))


# --- SNMPv3 users ----------------------------------------------------------------------


class SnmpUserSetIn(ApiModel):
    name: str = Field(min_length=1, max_length=32)
    auth: Literal["sha", "sha256"]
    auth_key: str = Field(min_length=1, max_length=64)
    priv: Optional[Literal["aes128"]] = None
    priv_key: Optional[str] = Field(default=None, max_length=64)
    access: Literal["ro", "rw"]


class NameIn(ApiModel):
    name: str = Field(min_length=1, max_length=32)


def _check_snmp_set(ctx: OperationContext) -> None:
    body: SnmpUserSetIn = ctx.body
    validate_username(body.name)
    validate_secret(body.auth_key)
    if body.priv is not None and not body.priv_key:
        raise InvalidInputError(t("Für die Verschlüsselung ist ein Schlüssel erforderlich."))
    if body.priv is None and body.priv_key:
        raise InvalidInputError(t("Ein Verschlüsselungsschlüssel braucht ein Verschlüsselungsverfahren."))
    if body.priv_key:
        validate_secret(body.priv_key)
    ctx.data["change"] = SnmpUserChange(
        name=body.name, auth=body.auth, auth_key=body.auth_key, priv=body.priv,
        priv_key=body.priv_key or None, access=body.access,
    )


def _check_name(ctx: OperationContext) -> None:
    validate_username(ctx.body.name)


register(OperationSpec(
    kind="device-snmp-user-set",
    audit_action="set-snmp-user",
    role=Role.ADMIN,
    features=("device_snmp",),
    body=SnmpUserSetIn,
    interface=lambda body: None,
    check=_check_snmp_set,
    plan=lambda ctx: ctx.driver.plan_snmp_user_set(ctx.session, ctx.data["change"]),
))

register(OperationSpec(
    kind="device-snmp-user-delete",
    audit_action="delete-snmp-user",
    role=Role.ADMIN,
    features=("device_snmp",),
    body=NameIn,
    interface=lambda body: None,
    check=_check_name,
    plan=lambda ctx: ctx.driver.plan_snmp_user_delete(ctx.session, ctx.body.name),
))


# --- device-aaa ------------------------------------------------------------------------


class RadiusIn(ApiModel):
    host: str = Field(min_length=1, max_length=253)
    key: Optional[str] = Field(default=None, max_length=64)
    auth_port: int = Field(default=1812, ge=1, le=65535)
    acct_port: int = Field(default=1813, ge=1, le=65535)


class TacacsIn(ApiModel):
    host: str = Field(min_length=1, max_length=253)
    key: Optional[str] = Field(default=None, max_length=64)
    port: int = Field(default=49, ge=1, le=65535)


class AaaIn(ApiModel):
    radius: Optional[list[RadiusIn]] = Field(default=None, max_length=4)
    tacacs: Optional[list[TacacsIn]] = Field(default=None, max_length=4)
    login_order: Optional[list[Literal["local", "radius", "tacacs"]]] = Field(default=None, min_length=1, max_length=3)


def _check_aaa(ctx: OperationContext) -> None:
    body: AaaIn = ctx.body
    _require_change(body)
    if body.radius is not None:
        _require_option(ctx, "device_aaa", "radius")
    if body.tacacs is not None:
        _require_option(ctx, "device_aaa", "tacacs")
    order = None
    if body.login_order is not None:
        _require_option(ctx, "device_aaa", "login_order")
        order = tuple(dict.fromkeys(body.login_order))
        if "local" not in order:
            raise InvalidInputError(t(LOCAL_FALLBACK_REQUIRED))
        for method in order:
            if method != "local":
                _require_option(ctx, "device_aaa", method)
    radius = tacacs = None
    if body.radius is not None:
        radius = tuple(
            RadiusServer(validate_host(item.host), validate_secret(item.key) if item.key else None,
                         item.auth_port, item.acct_port)
            for item in body.radius
        )
    if body.tacacs is not None:
        tacacs = tuple(
            TacacsServer(validate_host(item.host), validate_secret(item.key) if item.key else None, item.port)
            for item in body.tacacs
        )
    for servers in (radius, tacacs):
        hosts = [server.host for server in servers or ()]
        if len(hosts) != len(set(hosts)):
            raise InvalidInputError(t("Jeder Server darf nur einmal angegeben werden."))
    ctx.data["change"] = AaaChange(radius=radius, tacacs=tacacs, login_order=order)


def _plan_aaa(ctx: OperationContext):
    change: AaaChange = ctx.data["change"]
    if any(server.key is None for server in (change.radius or ()) + (change.tacacs or ())):
        aaa = _device_config(ctx).get("aaa") or {}
        for block, servers in (("radius", change.radius), ("tacacs", change.tacacs)):
            known = {entry.get("host") for entry in aaa.get(block) or () if entry.get("key_configured")}
            for server in servers or ():
                if server.key is None and server.host not in known:
                    raise InvalidInputError(t(
                        "Für den neuen Server {host} ist ein Schlüssel erforderlich.", host=server.host,
                    ))
    return _with_risk(ctx.driver.plan_device_aaa(ctx.session, change), t(ACCESS_RISK))


register(OperationSpec(
    kind="device-aaa",
    audit_action="set-device-aaa",
    role=Role.ADMIN,
    features=("device_aaa",),
    body=AaaIn,
    interface=lambda body: None,
    check=_check_aaa,
    plan=_plan_aaa,
))


# --- local users -----------------------------------------------------------------------


class UserSetIn(ApiModel):
    name: str = Field(min_length=1, max_length=32)
    password: Optional[str] = Field(default=None, max_length=64)
    privilege: Literal["admin", "read_only"]


def _check_own_account(ctx: OperationContext) -> None:
    name = validate_username(ctx.body.name)
    own = (ctx.credentials or {}).get("username") or ""
    if name.casefold() == own.casefold():
        raise InvalidInputError(t(OWN_ACCOUNT))


def _check_user_set(ctx: OperationContext) -> None:
    _check_own_account(ctx)
    if ctx.body.password:
        validate_secret(ctx.body.password)


def _existing_users(ctx: OperationContext) -> set[str]:
    return {user.get("name") for user in _device_config(ctx).get("users") or ()}


def _plan_user_set(ctx: OperationContext):
    body: UserSetIn = ctx.body
    password = body.password or None
    if password is None and body.name not in _existing_users(ctx):
        raise InvalidInputError(t("Für einen neuen Benutzer ist ein Passwort erforderlich."))
    plan = ctx.driver.plan_device_user_set(ctx.session, body.name, password, body.privilege)
    return _with_risk(plan, t(ACCESS_RISK))


def _plan_user_delete(ctx: OperationContext):
    if ctx.body.name not in _existing_users(ctx):
        raise InvalidInputError(t("Benutzer {name} existiert auf dem Switch nicht.", name=ctx.body.name))
    return _with_risk(ctx.driver.plan_device_user_delete(ctx.session, ctx.body.name), t(ACCESS_RISK))


register(OperationSpec(
    kind="device-user-set",
    audit_action="set-device-user",
    role=Role.ADMIN,
    features=("device_users",),
    body=UserSetIn,
    interface=lambda body: None,
    check=_check_user_set,
    plan=_plan_user_set,
))

register(OperationSpec(
    kind="device-user-delete",
    audit_action="delete-device-user",
    role=Role.ADMIN,
    features=("device_users",),
    body=NameIn,
    interface=lambda body: None,
    check=_check_own_account,
    plan=_plan_user_delete,
))


# --- device-ssh ------------------------------------------------------------------------


class SshIn(ApiModel):
    timeout_seconds: Optional[int] = Field(default=None, ge=60, le=3600)
    telnet_enabled: Optional[bool] = None
    web_enabled: Optional[bool] = None


def _check_ssh(ctx: OperationContext) -> None:
    body: SshIn = ctx.body
    _require_change(body)
    for field, option in (("timeout_seconds", "timeout"), ("telnet_enabled", "telnet"), ("web_enabled", "web")):
        if getattr(body, field) is not None:
            _require_option(ctx, "device_ssh", option)


def _plan_ssh(ctx: OperationContext):
    body: SshIn = ctx.body
    plan = ctx.driver.plan_device_ssh(ctx.session, body.timeout_seconds, body.telnet_enabled, body.web_enabled)
    return _with_risk(plan, t(ACCESS_RISK))


register(OperationSpec(
    kind="device-ssh",
    audit_action="set-device-ssh",
    role=Role.ADMIN,
    features=("device_ssh",),
    body=SshIn,
    interface=lambda body: None,
    check=_check_ssh,
    plan=_plan_ssh,
))


# --- layer 3 ---------------------------------------------------------------------------


class SviSetIn(ApiModel):
    vlan: int = Field(ge=1, le=4094)
    address: str = Field(min_length=7, max_length=15)
    prefix_length: int = Field(ge=1, le=32)
    dhcp_relay: list[str] = Field(default_factory=list, max_length=4)


class SviDeleteIn(ApiModel):
    vlan: int = Field(ge=1, le=4094)


class GatewayIn(ApiModel):
    gateway: str = Field(min_length=7, max_length=15)


class RouteIn(ApiModel):
    prefix: str = Field(min_length=7, max_length=15)
    prefix_length: int = Field(ge=0, le=32)
    next_hop: str = Field(min_length=7, max_length=15)


class RouteAddIn(RouteIn):
    distance: Optional[int] = Field(default=None, ge=1, le=255)


def _check_svi_set(ctx: OperationContext) -> None:
    body: SviSetIn = ctx.body
    _require_option(ctx, "device_l3", "svi")
    if body.dhcp_relay:
        _require_option(ctx, "device_l3", "dhcp_relay")
    ctx.data["address"] = validate_ipv4(body.address)
    ctx.data["relay"] = _ip_list(body.dhcp_relay, validate_ipv4)


def _svi_carries_management(ctx: OperationContext, vlan: int) -> bool:
    path = _management_path(ctx)
    if path.get("management_vlan") == vlan:
        return True
    interface = path.get("management_interface")
    if interface and _vlan_interface(str(interface)) == vlan:
        return True
    ip = path.get("management_ip")
    if ip:
        for svi in (_device_config(ctx).get("l3") or {}).get("svis") or ():
            if svi.get("vlan") == vlan and svi.get("address") == ip:
                return True
    return False


def _plan_svi_set(ctx: OperationContext):
    body: SviSetIn = ctx.body
    plan = ctx.driver.plan_svi_set(ctx.session, body.vlan, ctx.data["address"], body.prefix_length, ctx.data["relay"])
    risky = not ctx.applying and _svi_carries_management(ctx, body.vlan)
    return _with_risk(plan, t(MANAGEMENT_L3_RISK) if risky else None)


def _plan_svi_delete(ctx: OperationContext):
    plan = ctx.driver.plan_svi_delete(ctx.session, ctx.body.vlan)
    risky = not ctx.applying and _svi_carries_management(ctx, ctx.body.vlan)
    return _with_risk(plan, t(MANAGEMENT_L3_RISK) if risky else None)


def _check_gateway(ctx: OperationContext) -> None:
    _require_option(ctx, "device_l3", "gateway")
    ctx.data["gateway"] = validate_ipv4(ctx.body.gateway)


def _check_route(ctx: OperationContext) -> None:
    _require_option(ctx, "device_l3", "static_routes")
    network = validate_ipv4_prefix(ctx.body.prefix, ctx.body.prefix_length)
    ctx.data.update(network=network, next_hop=validate_ipv4(ctx.body.next_hop))


def _route_risk(ctx: OperationContext) -> str | None:
    return t(MANAGEMENT_L3_RISK) if ctx.data["network"].prefixlen == 0 else None


def _plan_route_add(ctx: OperationContext):
    network = ctx.data["network"]
    plan = ctx.driver.plan_route_add(
        ctx.session, str(network.network_address), network.prefixlen, ctx.data["next_hop"], ctx.body.distance,
    )
    return _with_risk(plan, _route_risk(ctx))


def _plan_route_delete(ctx: OperationContext):
    network = ctx.data["network"]
    plan = ctx.driver.plan_route_delete(ctx.session, str(network.network_address), network.prefixlen,
                                        ctx.data["next_hop"])
    return _with_risk(plan, _route_risk(ctx))


register(OperationSpec(
    kind="l3-svi-set",
    audit_action="set-svi",
    role=Role.ADMIN,
    features=("device_l3",),
    body=SviSetIn,
    interface=lambda body: None,
    check=_check_svi_set,
    plan=_plan_svi_set,
))

register(OperationSpec(
    kind="l3-svi-delete",
    audit_action="delete-svi",
    role=Role.ADMIN,
    features=("device_l3",),
    body=SviDeleteIn,
    interface=lambda body: None,
    check=lambda ctx: _require_option(ctx, "device_l3", "svi"),
    plan=_plan_svi_delete,
))

register(OperationSpec(
    kind="l3-gateway",
    audit_action="set-default-gateway",
    role=Role.ADMIN,
    features=("device_l3",),
    body=GatewayIn,
    interface=lambda body: None,
    check=_check_gateway,
    plan=lambda ctx: _with_risk(ctx.driver.plan_gateway(ctx.session, ctx.data["gateway"]), t(MANAGEMENT_L3_RISK)),
))

register(OperationSpec(
    kind="l3-route-add",
    audit_action="add-static-route",
    role=Role.ADMIN,
    features=("device_l3",),
    body=RouteAddIn,
    interface=lambda body: None,
    check=_check_route,
    plan=_plan_route_add,
))

register(OperationSpec(
    kind="l3-route-delete",
    audit_action="delete-static-route",
    role=Role.ADMIN,
    features=("device_l3",),
    body=RouteIn,
    interface=lambda body: None,
    check=_check_route,
    plan=_plan_route_delete,
))


# --- ACLs ------------------------------------------------------------------------------


class AclCreateIn(ApiModel):
    name: str = Field(min_length=1, max_length=31)
    type: Literal["standard", "extended"]


class AclNameIn(ApiModel):
    name: str = Field(min_length=1, max_length=31)


class AclEntryIn(ApiModel):
    name: str = Field(min_length=1, max_length=31)
    seq: int = Field(ge=1, le=2147483647)
    action: Literal["permit", "deny"]
    protocol: Literal["ip", "tcp", "udp", "icmp"]
    src: str = Field(min_length=7, max_length=15)
    src_len: int = Field(ge=0, le=32)
    dst: Optional[str] = Field(default=None, min_length=7, max_length=15)
    dst_len: Optional[int] = Field(default=None, ge=0, le=32)
    dst_port_op: Optional[Literal["eq", "range"]] = None
    dst_port: Optional[int] = Field(default=None, ge=1, le=65535)
    dst_port_end: Optional[int] = Field(default=None, ge=1, le=65535)


class AclEntryDeleteIn(ApiModel):
    name: str = Field(min_length=1, max_length=31)
    seq: int = Field(ge=1, le=2147483647)


class AclBindIn(ApiModel):
    name: str = Field(min_length=1, max_length=31)
    interface: str = Field(min_length=1, max_length=100)
    direction: Literal["in", "out"]


def _check_acl_name(ctx: OperationContext) -> None:
    validate_acl_name(ctx.body.name)


def _acls(ctx: OperationContext) -> dict[str, dict]:
    return {acl.get("name"): acl for acl in _device_config(ctx).get("acls") or ()}


def _existing_acl(ctx: OperationContext) -> dict:
    acl = _acls(ctx).get(ctx.body.name)
    if acl is None:
        raise InvalidInputError(t("ACL {name} existiert auf dem Switch nicht.", name=ctx.body.name))
    return acl


def _plan_acl_create(ctx: OperationContext):
    if ctx.body.name in _acls(ctx):
        raise InvalidInputError(t("ACL {name} existiert bereits.", name=ctx.body.name))
    return ctx.driver.plan_acl_create(ctx.session, ctx.body.name, ctx.body.type)


def _plan_acl_delete(ctx: OperationContext):
    acl = _existing_acl(ctx)
    bound = [binding.get("interface") for binding in acl.get("bindings") or ()]
    if bound:
        raise InvalidInputError(t("Die ACL ist noch an {interfaces} gebunden.", interfaces=", ".join(map(str, bound))))
    return ctx.driver.plan_acl_delete(ctx.session, ctx.body.name)


def _check_acl_entry(ctx: OperationContext) -> None:
    body: AclEntryIn = ctx.body
    validate_acl_name(body.name)
    source = validate_ipv4_prefix(body.src, body.src_len)
    destination = None
    if (body.dst is None) != (body.dst_len is None):
        raise InvalidInputError(t("Zieladresse und Präfixlänge müssen gemeinsam angegeben werden."))
    if body.dst is not None:
        destination = validate_ipv4_prefix(body.dst, body.dst_len)
    if body.dst_port_op is None:
        if body.dst_port is not None or body.dst_port_end is not None:
            raise InvalidInputError(t("Ein Zielport braucht einen Vergleich (eq oder range)."))
    else:
        if body.protocol not in {"tcp", "udp"}:
            raise InvalidInputError(t("Zielports gibt es nur für TCP und UDP."))
        if body.dst_port is None:
            raise InvalidInputError(t("Es fehlt der Zielport."))
        if body.dst_port_op == "eq" and body.dst_port_end is not None:
            raise InvalidInputError(t("Ein Portbereich braucht den Vergleich range."))
        if body.dst_port_op == "range" and (body.dst_port_end is None or body.dst_port_end < body.dst_port):
            raise InvalidInputError(t("Das Ende des Portbereichs muss größer oder gleich dem Anfang sein."))
    ctx.data["entry"] = AclEntry(
        seq=body.seq, action=body.action, protocol=body.protocol,
        src=str(source.network_address), src_len=source.prefixlen,
        dst=str(destination.network_address) if destination else None,
        dst_len=destination.prefixlen if destination else None,
        dst_port_op=body.dst_port_op, dst_port=body.dst_port, dst_port_end=body.dst_port_end,
    )


def _plan_acl_entry_add(ctx: OperationContext):
    acl = _existing_acl(ctx)
    entry: AclEntry = ctx.data["entry"]
    if acl.get("type") == "standard" and (entry.protocol != "ip" or entry.dst is not None or entry.dst_port_op):
        raise InvalidInputError(t("Eine Standard-ACL prüft nur die Quelladresse."))
    if any(item.get("seq") == entry.seq for item in acl.get("entries") or ()):
        raise InvalidInputError(t("Der Eintrag {seq} existiert bereits.", seq=entry.seq))
    return ctx.driver.plan_acl_entry_add(ctx.session, ctx.body.name, entry)


def _plan_acl_entry_delete(ctx: OperationContext):
    acl = _existing_acl(ctx)
    if not any(item.get("seq") == ctx.body.seq for item in acl.get("entries") or ()):
        raise InvalidInputError(t("Der Eintrag {seq} existiert nicht.", seq=ctx.body.seq))
    return ctx.driver.plan_acl_entry_delete(ctx.session, ctx.body.name, ctx.body.seq)


def _check_acl_bind(ctx: OperationContext) -> None:
    body: AclBindIn = ctx.body
    validate_acl_name(body.name)
    vlan = _vlan_interface(body.interface)
    if vlan is not None:
        _require_option(ctx, "acl", f"vlan_{body.direction}")
        ctx.data.update(interface=body.interface.strip(), vlan=vlan)
    else:
        _require_option(ctx, "acl", f"port_{body.direction}")
        ctx.data.update(interface=ctx.driver.validate_interface(body.interface), vlan=None)


def _bind_risk(ctx: OperationContext) -> str | None:
    vlan = ctx.data["vlan"]
    if vlan is None or ctx.applying:
        return None
    return t(MANAGEMENT_ACL_RISK) if _svi_carries_management(ctx, vlan) else None


def _plan_acl_bind(ctx: OperationContext):
    _existing_acl(ctx)
    plan = ctx.driver.plan_acl_bind(ctx.session, ctx.body.name, ctx.data["interface"], ctx.body.direction)
    return _with_risk(plan, _bind_risk(ctx))


def _plan_acl_unbind(ctx: OperationContext):
    plan = ctx.driver.plan_acl_unbind(ctx.session, ctx.body.name, ctx.data["interface"], ctx.body.direction)
    return _with_risk(plan, _bind_risk(ctx))


def _port_interface(body) -> str | None:
    """Ports get the automatic uplink risk; VLAN interfaces are checked against the management SVI."""
    return None if _vlan_interface(body.interface) is not None else body.interface


register(OperationSpec(
    kind="acl-create",
    audit_action="create-acl",
    role=Role.ADMIN,
    features=("acl",),
    body=AclCreateIn,
    interface=lambda body: None,
    check=_check_acl_name,
    plan=_plan_acl_create,
))

register(OperationSpec(
    kind="acl-delete",
    audit_action="delete-acl",
    role=Role.ADMIN,
    features=("acl",),
    body=AclNameIn,
    interface=lambda body: None,
    check=_check_acl_name,
    plan=_plan_acl_delete,
))

register(OperationSpec(
    kind="acl-entry-add",
    audit_action="add-acl-entry",
    role=Role.ADMIN,
    features=("acl",),
    body=AclEntryIn,
    interface=lambda body: None,
    check=_check_acl_entry,
    plan=_plan_acl_entry_add,
))

register(OperationSpec(
    kind="acl-entry-delete",
    audit_action="delete-acl-entry",
    role=Role.ADMIN,
    features=("acl",),
    body=AclEntryDeleteIn,
    interface=lambda body: None,
    check=_check_acl_name,
    plan=_plan_acl_entry_delete,
))

register(OperationSpec(
    kind="acl-bind",
    audit_action="bind-acl",
    role=Role.ADMIN,
    features=("acl",),
    body=AclBindIn,
    interface=_port_interface,
    check=_check_acl_bind,
    plan=_plan_acl_bind,
))

register(OperationSpec(
    kind="acl-unbind",
    audit_action="unbind-acl",
    role=Role.ADMIN,
    features=("acl",),
    body=AclBindIn,
    interface=_port_interface,
    check=_check_acl_bind,
    plan=_plan_acl_unbind,
))


# --- qos-port --------------------------------------------------------------------------


class QosPortIn(ApiModel):
    interface: str = Field(min_length=1, max_length=100)
    trust: Optional[Literal["none", "cos", "dscp"]] = None
    voice_preset: Optional[bool] = None


def _check_qos(ctx: OperationContext) -> None:
    body: QosPortIn = ctx.body
    if body.trust is None and body.voice_preset is None:
        raise InvalidInputError(t(NO_CHANGE))
    if body.trust is not None:
        _require_option(ctx, "qos", body.trust)
    if body.voice_preset is not None:
        features.require(_capabilities(ctx), "qos_voice")
    ctx.data["interface"] = ctx.driver.validate_interface(body.interface)


register(OperationSpec(
    kind="qos-port",
    audit_action="set-qos-port",
    role=Role.ADMIN,
    features=("qos",),
    body=QosPortIn,
    interface=lambda body: body.interface,
    check=_check_qos,
    plan=lambda ctx: ctx.driver.plan_qos_port(
        ctx.session, ctx.data["interface"], ctx.body.trust, ctx.body.voice_preset,
    ),
))
