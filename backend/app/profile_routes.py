"""Port profiles: admin CRUD and the selection list for the port dialog."""

import sqlite3

from fastapi import APIRouter, HTTPException, status

from .audit import audit_action, record
from .auth import AdminPrincipal, CurrentPrincipal
from .i18n import t
from .switches import profiles

router = APIRouter(prefix="/api", tags=["port-profiles"])

DUPLICATE = "Ein Port-Profil mit diesem Namen existiert bereits."
NOT_FOUND = "Das Port-Profil existiert nicht."


def _public(profile: dict) -> dict:
    return {key: profile[key] for key in ("id", "name", "description", "settings")}


def _admin(profile: dict) -> dict:
    return {**_public(profile), "updated_by": profile["updated_by"], "updated_at": profile["updated_at"]}


@router.get("/port-profiles")
def api_port_profiles(_: CurrentPrincipal):
    return {"profiles": [_public(profile) for profile in profiles.list_profiles()]}


@router.get("/admin/port-profiles")
def api_admin_port_profiles(_: AdminPrincipal):
    return {"profiles": [_admin(profile) for profile in profiles.list_profiles()]}


@router.post("/admin/port-profiles")
@audit_action("port-profile-create")
def api_create_port_profile(body: profiles.PortProfileIn, principal: AdminPrincipal):
    try:
        profile = profiles.create(body, principal.username)
    except sqlite3.IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=t(DUPLICATE)) from None
    record("port-profile-create", target=profile["name"], detail=f"id={profile['id']}")
    return _admin(profile)


@router.put("/admin/port-profiles/{profile_id}")
@audit_action("port-profile-update")
def api_update_port_profile(profile_id: int, body: profiles.PortProfileIn, principal: AdminPrincipal):
    try:
        profile = profiles.update(profile_id, body, principal.username)
    except sqlite3.IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=t(DUPLICATE)) from None
    if profile is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=t(NOT_FOUND))
    record("port-profile-update", target=profile["name"], detail=f"id={profile_id}")
    return _admin(profile)


@router.delete("/admin/port-profiles/{profile_id}")
@audit_action("port-profile-delete")
def api_delete_port_profile(profile_id: int, _: AdminPrincipal):
    profile = profiles.delete(profile_id)
    if profile is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=t(NOT_FOUND))
    record("port-profile-delete", target=profile["name"], detail=f"id={profile_id}")
    return {"ok": True}
