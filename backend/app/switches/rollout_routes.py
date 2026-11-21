"""VLAN rollout to a switch group: preview and apply routes (administrators only)."""

from typing import Optional

from fastapi import APIRouter
from pydantic import Field

from ..audit import audit_action, record
from ..auth import AdminPrincipal
from . import rollout
from .operations import ApiModel

router = APIRouter(prefix="/api", tags=["switches"])


class RolloutPreviewIn(ApiModel):
    vlan_id: int = Field(ge=1, le=4094)
    name: Optional[str] = Field(default=None, max_length=32)


class RolloutApplyIn(ApiModel):
    rollout_token: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    selections: dict[int, list[str]] = Field(default_factory=dict)


@router.post("/switch-groups/{group_id}/vlan-rollout/preview")
@audit_action("vlan-rollout-preview")
def api_vlan_rollout_preview(group_id: int, body: RolloutPreviewIn, principal: AdminPrincipal):
    result = rollout.preview(group_id, principal, body.vlan_id, body.name)
    record("vlan-rollout-preview", target=f"group:{group_id}", detail=f"vlan={body.vlan_id}")
    return result


@router.post("/switch-groups/{group_id}/vlan-rollout/apply")
@audit_action("vlan-rollout")
def api_vlan_rollout_apply(group_id: int, body: RolloutApplyIn, principal: AdminPrincipal):
    return rollout.apply(group_id, principal, body.rollout_token, body.selections)
