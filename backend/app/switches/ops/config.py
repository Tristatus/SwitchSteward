"""Configuration operations: save-config (running → startup) with backups before and after saving."""

from ...auth import Role
from ..drivers.base import WriteResult
from ..operations import ApiModel, OperationContext, OperationSpec, register
from .backup import take_backup


class SaveConfigIn(ApiModel):
    pass


def _plan_save(ctx: OperationContext):
    return ctx.driver.plan_save_config(ctx.session)


def _backup_before_save(ctx: OperationContext) -> None:
    take_backup(ctx, "before-save", "startup")


def _backup_after_save(ctx: OperationContext, result: WriteResult) -> None:
    if result["ok"]:
        take_backup(ctx, "after-save", "startup")


register(OperationSpec(
    kind="save-config",
    audit_action="save-config",
    role=Role.ADMIN,
    features=("save_config",),
    body=SaveConfigIn,
    interface=lambda body: None,
    plan=_plan_save,
    before=_backup_before_save,
    after=_backup_after_save,
    audit_detail=lambda body: "",
    marks="saved",
))
