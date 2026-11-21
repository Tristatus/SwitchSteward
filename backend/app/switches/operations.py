"""Registered change operations: every write to a switch is previewed as a plan, then applied unchanged.

An ``OperationSpec`` names the request body, the role and features it needs, its audit
action and how the driver plan is built. Area modules in ``switches.ops`` register their
specs with ``register``; ``service.preview_change``/``service.apply_change`` run them.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from fastapi import HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..auth import Principal, Role
from ..i18n import t
from .drivers.base import PortChange, SwitchDriver, WriteResult
from .drivers.plans import ChangePlan

ROLLBACK_MIN_MINUTES = 1
ROLLBACK_MAX_MINUTES = 60
ROLLBACK_DEFAULT_MINUTES = 5
# Body fields that are never written to the audit log (also nested).
SECRET_FIELDS = frozenset({"password", "secret", "key", "auth_key", "priv_key"})
OPERATOR_ACCESS_ONLY = "Operatoren dürfen nur Access-Ports ändern."


def operator_refused() -> HTTPException:
    return HTTPException(status.HTTP_403_FORBIDDEN, detail=t(OPERATOR_ACCESS_ONLY))


def port_basis(ctx: "OperationContext", interface: str, change: PortChange | None = None) -> dict:
    """Read the port state, record its mode as preview basis and refuse operators on non-access ports.

    Every ``Role.OPERATOR`` operation on a port calls this inside ``plan`` (uplinks are
    refused separately through the uplink risk). Returns the driver's port detail.
    """
    detail = ctx.driver.read_port_state(ctx.session, interface, change or PortChange()) or {}
    mode = detail.get("mode")
    ctx.basis["mode"] = mode
    if not ctx.principal.can_edit and mode != "access":
        raise operator_refused()
    return detail


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


@dataclass
class OperationContext:
    """State of one preview or apply; ``session`` is None while ``spec.check`` runs.

    ``basis``: device state the plan was built from (JSON values); a different basis at
    apply time makes the preview stale even when the lines are equal. ``data``: free
    storage shared by the spec's callbacks within one run.
    """

    driver: SwitchDriver
    session: Any
    switch: dict
    credentials: dict
    body: BaseModel
    principal: Principal
    warnings: list[str] = field(default_factory=list)
    applying: bool = False
    basis: dict = field(default_factory=dict)
    data: dict = field(default_factory=dict)


@dataclass(frozen=True)
class OperationSpec:
    """One kind of change.

    ``audit_action``: action name, or a function of the body (e.g. port-enable/port-disable).
    ``role``: ``Role.ADMIN`` or ``Role.OPERATOR``. ``features``: required before any session.
    ``interface``: the port the change touches (uplink risk, audit column) or None.
    ``check``: validation before the session is opened. ``plan``: builds the plan in the session.
    ``before``/``after``: apply only, same session, around ``execute_plan``; exceptions become warnings.
    ``verify``: confirms an accepted result (fresh read). ``audit_detail``: audit text of the body.
    ``deferred``: apply creates a scheduler job instead of executing. ``job``: the job a deferred
    apply creates, ``(kind, run_at UTC, params)``; default ``(spec.kind, now, params)``. A spec
    that is not ``deferred`` is deferred too when ``job(ctx)`` returns a job (e.g. a firmware
    activation at a later time). ``actions_only``: pure
    action without configuration change (no save state, no MikroTik backups).
    ``marks``: save state after a successful apply (``dirty`` is skipped for persistent plans).
    ``rollback_supported``: whether a configuration rollback can revert the change at all.
    """

    kind: str
    audit_action: str | Callable[[BaseModel], str]
    role: Role
    features: tuple[str, ...]
    body: type[BaseModel]
    interface: Callable[[BaseModel], str | None]
    plan: Callable[[OperationContext], ChangePlan]
    before: Callable[[OperationContext], None] | None = None
    after: Callable[[OperationContext, WriteResult], None] | None = None
    verify: Callable[[OperationContext, WriteResult], WriteResult] | None = None
    audit_detail: Callable[[BaseModel], str] | None = None
    deferred: bool = False
    actions_only: bool = False
    check: Callable[[OperationContext], None] | None = None
    marks: Literal["dirty", "saved", "unknown"] | None = "dirty"
    job: Callable[[OperationContext], tuple[str, str, dict] | None] | None = None
    # False: the change lives outside the running config (e.g. VTP in vlan.dat); a config rollback cannot revert it.
    rollback_supported: bool = True

    def action_for(self, body: BaseModel) -> str:
        return self.audit_action(body) if callable(self.audit_action) else self.audit_action

    def detail_for(self, body: BaseModel) -> str:
        return self.audit_detail(body) if self.audit_detail is not None else default_audit_detail(body)


OPERATIONS: dict[str, OperationSpec] = {}


def register(spec: OperationSpec) -> OperationSpec:
    if spec.kind in OPERATIONS:
        raise ValueError(f"Operation {spec.kind} is already registered")
    OPERATIONS[spec.kind] = spec
    return spec


def _without_secrets(value):
    if isinstance(value, dict):
        return {key: _without_secrets(item) for key, item in value.items() if key not in SECRET_FIELDS}
    if isinstance(value, list):
        return [_without_secrets(item) for item in value]
    return value


def default_audit_detail(body: BaseModel) -> str:
    """``key=value`` of every set field except ``interface`` (own audit column) and secrets."""
    values = _without_secrets(body.model_dump(exclude_none=True))
    values.pop("interface", None)
    return " ".join(f"{key}={value!r}" if isinstance(value, str) else f"{key}={value}" for key, value in values.items())


class ChangeIn(ApiModel):
    kind: str = Field(min_length=1, max_length=64)
    params: dict = Field(default_factory=dict)
    rollback_minutes: int | None = Field(default=None, ge=ROLLBACK_MIN_MINUTES, le=ROLLBACK_MAX_MINUTES)

    @field_validator("kind")
    @classmethod
    def known_kind(cls, value: str) -> str:
        if value not in OPERATIONS:
            raise ValueError("unknown change kind")
        return value


class ApplyIn(ApiModel):
    preview_token: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    confirm_risk: bool = False
