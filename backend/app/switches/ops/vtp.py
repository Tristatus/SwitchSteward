"""VTP operations (Cisco): vtp-configure and vtp-primary.

VTP state lives in vlan.dat, not in the running configuration (except in transparent
mode), so a configuration rollback cannot revert these changes.
"""

from dataclasses import replace
from typing import Literal, Optional

from pydantic import Field, model_validator

from ...auth import Role
from ...i18n import t
from ..drivers.base import VtpChange
from ..errors import InvalidInputError
from ..operations import ApiModel, OperationContext, OperationSpec, register
from ..validation import validate_vtp_domain, validate_vtp_password

VTP_DOMAIN_RISK = (
    "VTP-Änderungen wirken auf die ganze Domäne: Ein Server oder Client mit höherer Konfigurationsrevision "
    "überschreibt die VLAN-Datenbank aller Switches der Domäne; fehlende VLANs legen Ports still."
)
VTP_REVISION_RESET_RISK = "Ein neuer Domänenname setzt die Konfigurationsrevision auf 0."
VTP_LEAVE_RISK = "Im Modus Transparent oder Aus übernimmt der Switch keine VLAN-Änderungen der Domäne mehr."
VTP_PASSWORD_RISK = "Ein abweichendes VTP-Passwort trennt den Switch von der VTP-Synchronisation der Domäne."  # noqa: S105 - message, not a password
VTP_PRUNING_RISK = "VTP-Pruning ändert domänenweit, welche VLANs über Trunks weitergeleitet werden."
VTP_PRIMARY_RISK = (
    "Der Switch wird Primary Server: Seine VLAN-Datenbank (Revision {revision}) wird an alle Switches der "
    "Domäne {domain} verteilt und ersetzt dort die bestehenden VLANs."
)
_SYNC_MODES = ("server", "client")
_BASIS_FIELDS = ("domain", "version", "mode", "pruning", "password_configured", "primary_server", "revision")


class VtpConfigureIn(ApiModel):
    domain: Optional[str] = Field(None, min_length=1, max_length=32)
    version: Optional[Literal[1, 2, 3]] = None
    mode: Optional[Literal["server", "client", "transparent", "off"]] = None
    pruning: Optional[bool] = None
    password: Optional[str] = Field(None, max_length=64)
    password_hidden: bool = False
    clear_password: bool = False

    @model_validator(mode="after")
    def consistent(self):
        if self.password is not None and self.clear_password:
            raise ValueError(t("Passwort setzen und entfernen schließen sich aus."))
        if self.password_hidden and self.password is None:
            raise ValueError(t("'hidden' braucht ein neues Passwort."))
        values = (self.domain, self.version, self.mode, self.pruning, self.password)
        if all(value is None for value in values) and not self.clear_password:
            raise ValueError(t("Mindestens eine VTP-Einstellung muss geändert werden."))
        return self


class VtpPrimaryIn(ApiModel):
    password: Optional[str] = Field(None, max_length=64)


def _vtp_basis(status: dict) -> dict:
    return {key: status.get(key) for key in _BASIS_FIELDS}


def _failed(result: dict, message: str) -> dict:
    return {"ok": False, "message": message, "raw": result["raw"]}


# --- vtp-configure -------------------------------------------------------------------------


def _check_configure(ctx: OperationContext) -> None:
    body = ctx.body
    if body.domain is not None:
        validate_vtp_domain(body.domain)
    if body.password is not None:
        validate_vtp_password(body.password)
    ctx.data["change"] = VtpChange(
        domain=body.domain, version=body.version, mode=body.mode, pruning=body.pruning, password=body.password,
        password_hidden=body.password_hidden, clear_password=body.clear_password,
    )


def _configure_risk(status: dict, change: VtpChange, changed: frozenset[str]) -> str:
    target_mode = change.mode or status.get("mode")
    risks = []
    if changed & {"domain", "version", "mode"} and target_mode in _SYNC_MODES:
        risks.append(VTP_DOMAIN_RISK)
    if "domain" in changed:
        risks.append(VTP_REVISION_RESET_RISK)
    if "mode" in changed and target_mode in ("transparent", "off") and status.get("mode") in _SYNC_MODES:
        risks.append(VTP_LEAVE_RISK)
    if changed & {"password", "clear_password"}:
        risks.append(VTP_PASSWORD_RISK)
    if "pruning" in changed:
        risks.append(VTP_PRUNING_RISK)
    return " ".join(t(risk) for risk in risks)


def _plan_configure(ctx: OperationContext):
    change = ctx.data["change"]
    status = ctx.driver.read_vtp(ctx.session)
    basis = _vtp_basis(status)
    del basis["revision"]  # VLAN edits elsewhere in the domain change it
    ctx.basis["vtp"] = basis
    changed = change.changed(status)
    ctx.data["changed"] = changed
    plan = ctx.driver.plan_vtp_configure(ctx.session, change)
    if plan.steps:
        plan = replace(plan, risk=_configure_risk(status, change, changed) or None)
    return plan


def _verify_configure(ctx: OperationContext, result):
    if not result["ok"]:
        return result
    change = ctx.data["change"]
    fresh = ctx.driver.read_vtp(ctx.session)
    missing = set()
    for name in ctx.data["changed"]:
        if name == "password":
            mismatch = fresh.get("password_configured") is False
        elif name == "clear_password":
            mismatch = fresh.get("password_configured") is True
        else:
            mismatch = fresh.get(name) != getattr(change, name)
        if mismatch:
            missing.add(name)
    if not missing:
        return result
    return _failed(result, t(
        "Der Switch hat keinen Fehler gemeldet, die VTP-Änderung ist aber nicht sichtbar: {fields}",
        fields=", ".join(sorted(missing)),
    ))


register(OperationSpec(
    kind="vtp-configure",
    audit_action="set-vtp",
    role=Role.ADMIN,
    features=("vtp",),
    body=VtpConfigureIn,
    interface=lambda body: None,
    check=_check_configure,
    plan=_plan_configure,
    verify=_verify_configure,
    rollback_supported=False,
))


# --- vtp-primary ---------------------------------------------------------------------------


def _check_primary(ctx: OperationContext) -> None:
    if ctx.body.password is not None:
        validate_vtp_password(ctx.body.password)


def _plan_primary(ctx: OperationContext):
    status = ctx.driver.read_vtp(ctx.session)
    ctx.basis["vtp"] = _vtp_basis(status)
    if status.get("version") != 3:
        raise InvalidInputError(t("'Primary übernehmen' gibt es nur mit VTP-Version 3."))
    if status.get("mode") != "server":
        raise InvalidInputError(t("Nur ein VTPv3-Server kann Primary Server werden."))
    if status.get("primary_server") is True:
        raise InvalidInputError(t("Der Switch ist bereits Primary Server."))
    plan = ctx.driver.plan_vtp_primary(ctx.session, ctx.body.password)
    return replace(plan, risk=t(VTP_PRIMARY_RISK, revision=status.get("revision"), domain=status.get("domain") or "–"))


def _verify_primary(ctx: OperationContext, result):
    if not result["ok"] or ctx.driver.read_vtp(ctx.session).get("primary_server") is True:
        return result
    return _failed(result, t("Der Switch hat keinen Fehler gemeldet, ist aber nicht Primary Server geworden."))


register(OperationSpec(
    kind="vtp-primary",
    audit_action="vtp-primary",
    role=Role.ADMIN,
    features=("vtp",),
    body=VtpPrimaryIn,
    interface=lambda body: None,
    check=_check_primary,
    plan=_plan_primary,
    verify=_verify_primary,
    actions_only=True,
    rollback_supported=False,
))
