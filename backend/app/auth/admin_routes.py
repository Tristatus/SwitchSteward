"""Administration API: sign-in settings, user accounts, group-to-role mappings and operations settings.

Every route requires the admin role; CSRF is enforced by ``SecurityMiddleware``. Changes run in
one transaction with the lockout guard, so a rejected change leaves no trace in the database.
"""

import logging
import sqlite3
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .. import backups, config, crypto, sftp_server, system_settings
from .. import database as db
from ..audit import audit_action, record
from ..i18n import t
from . import AdminPrincipal, entra, ldap, passwords, sessions, settings, throttle, users
from .guards import ensure_admin_path
from .roles import matched_mappings, resolve_role
from .routes import client_ip

logger = logging.getLogger("switchsteward.auth")
router = APIRouter(prefix="/api/admin", tags=["admin"])

_EFFECTIVE = "next_login"


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _display_name(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if _has_control_characters(value):
        raise ValueError(t("Steuerzeichen und Zeilenumbrüche sind nicht erlaubt."))
    return value or None


def _validation_message(exc: ValidationError) -> str:
    errors = exc.errors(include_input=False, include_context=False, include_url=False)
    message = errors[0]["msg"] if errors else t("Ungültige Eingabe.")
    return message.removeprefix("Value error, ")


def _bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


# --- Sign-in settings --------------------------------------------------------------


def _settings_view() -> dict:
    with db.get_conn() as conn:
        general = settings.load_general(conn)
        ad = settings.load_ad(conn)
        entra_settings = settings.load_entra(conn)
        admin_count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE provider = 'local' AND enabled = 1 AND assigned_role = 'admin'"
        ).fetchone()[0]
    entra_view = entra_settings.model_dump(exclude={"client_secret_enc"})
    return {
        "general": general.model_dump(),
        "local": {"enabled": True, "admin_count": admin_count},
        "ad": ad.model_dump(),
        "entra": {
            **entra_view,
            "client_secret_configured": bool(entra_settings.client_secret_enc),
            "redirect_uri": settings.entra_redirect_uri(general),
        },
    }


@router.get("/auth-settings")
def get_auth_settings(_: AdminPrincipal):
    return _settings_view()


@router.put("/auth-settings/general")
@audit_action("auth-settings-update")
def update_general_settings(body: settings.GeneralAuthSettings, principal: AdminPrincipal):
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            settings.check_entra_ready(settings.load_entra(conn), body)
        except ValueError as exc:
            raise _bad_request(str(exc)) from None
        previous = settings.load_general(conn)
        settings.save(body, conn=conn)
    _log_settings_change("general", previous, body)
    record("auth-settings-update", target="general", detail=f"public_base_url={body.public_base_url or '-'}")
    return _settings_view()


def _log_settings_change(section: str, previous: BaseModel, updated: BaseModel) -> None:
    """System-log the names of changed settings; values are never logged (they may be secrets)."""
    before, after = previous.model_dump(), updated.model_dump()
    changed = sorted(key.removesuffix("_enc") for key in after if before.get(key) != after[key])
    logger.info("Authentication settings '%s' saved; changed keys: %s", section, ", ".join(changed) or "none")


def _guard_provider_change(conn: sqlite3.Connection, provider: str, was_enabled: bool, enabled: bool,
                           principal) -> int:
    """Lockout checks after saving; switching a provider off ends all of its sessions."""
    if was_enabled and not enabled and principal.provider == provider:
        raise _conflict(t("Der Anmeldeweg, über den Sie angemeldet sind, kann nicht deaktiviert werden."))
    ensure_admin_path(conn)
    if was_enabled and not enabled:
        return sessions.revoke_provider_sessions(provider, conn=conn)
    return 0


@router.put("/auth-settings/ad")
@audit_action("auth-settings-update")
def update_ad_settings(body: settings.AdSettings, principal: AdminPrincipal):
    if body.enabled:
        try:
            settings.check_ad_files(body)
        except ValueError as exc:
            raise _bad_request(str(exc)) from None
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        previous = settings.load_ad(conn)
        settings.save(body, conn=conn)
        revoked = _guard_provider_change(conn, "ad", previous.enabled, body.enabled, principal)
    _log_settings_change("ad", previous, body)
    record("auth-settings-update", target="ad", detail=f"enabled={body.enabled} revoked_sessions={revoked}")
    return _settings_view()


class EntraSettingsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    tenant_id: str = Field(default="", max_length=64)
    client_id: str = Field(default="", max_length=64)
    cloud: Literal["global", "usgov", "china"] = "global"
    default_role: Literal["none", "viewer"] = "none"
    client_secret: str | None = Field(default=None, max_length=1024)
    clear_client_secret: bool = False


@router.put("/auth-settings/entra")
@audit_action("auth-settings-update")
def update_entra_settings(body: EntraSettingsInput, principal: AdminPrincipal):
    secret = body.client_secret.strip() if body.client_secret else None
    if secret and body.clear_client_secret:
        raise _bad_request(t("Ein neues Client-Secret und das Entfernen des Secrets schließen sich aus."))
    if secret and _has_control_characters(secret):
        raise _bad_request(t("Steuerzeichen und Zeilenumbrüche sind nicht erlaubt."))
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        previous = settings.load_entra(conn)
        if secret:
            secret_enc = crypto.encrypt(secret).decode("ascii")
        else:
            secret_enc = None if body.clear_client_secret else previous.client_secret_enc
        try:
            updated = settings.EntraSettings(
                enabled=body.enabled, tenant_id=body.tenant_id, client_id=body.client_id, cloud=body.cloud,
                default_role=body.default_role, client_secret_enc=secret_enc,
            )
            settings.check_entra_ready(updated, settings.load_general(conn))
        except ValidationError as exc:
            raise _bad_request(_validation_message(exc)) from None
        except ValueError as exc:
            raise _bad_request(str(exc)) from None
        settings.save(updated, conn=conn)
        revoked = _guard_provider_change(conn, "entra", previous.enabled, updated.enabled, principal)
    _log_settings_change("entra", previous, updated)
    secret_change = "set" if secret else ("cleared" if body.clear_client_secret else "kept")
    record(
        "auth-settings-update", target="entra",
        detail=f"enabled={updated.enabled} client_secret={secret_change} revoked_sessions={revoked}",
    )
    return _settings_view()


class AdTestInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)


def _ad_test_result(ok: bool, message: str, role=None, matched=()) -> dict:
    return {
        "ok": ok,
        "role": role.value if role else None,
        "matched_groups": [
            {"group_id": mapping.group_id, "label": mapping.label, "role": mapping.role} for mapping in matched
        ],
        "message": message,
    }


@router.post("/auth-settings/ad/test")
@audit_action("auth-ad-test")
def check_ad_settings(body: AdTestInput, request: Request, _: AdminPrincipal):
    stored = settings.load_ad()
    try:
        # Tests may run before AD is switched on, but only with otherwise complete settings.
        ad = settings.AdSettings.model_validate({**stored.model_dump(), "enabled": True})
    except ValidationError as exc:
        result = _ad_test_result(False, _validation_message(exc))
        record("auth-ad-test", target="ad", detail=f"username={body.username} ok=False", status="error")
        return result
    ip = client_ip(request)
    attempt = throttle.reserve_login_attempt(ip, "ad", body.username)
    mappings = settings.list_mappings("ad")
    try:
        identity = ldap.authenticate(ad, mappings, body.username, body.password)
    except ldap.LdapAuthError:
        result = _ad_test_result(False, t("Benutzername oder Passwort falsch."))
    except (ldap.LdapConfigError, ldap.DirectoryUnavailableError) as exc:
        throttle.discard_login_attempt(ip, "ad", body.username, attempt)
        result = _ad_test_result(False, str(exc))
    else:
        throttle.clear_login_failures(ip, "ad", body.username)
        existing = users.find_user("ad", identity.subject)
        role = resolve_role(existing, "ad", identity.matched_group_ids, mappings, ad.default_role)
        matched = matched_mappings(identity.matched_group_ids, mappings)
        message = (
            t("Anmeldung erfolgreich.") if role else t("Anmeldung erfolgreich, aber keine Rolle zugeordnet.")
        )
        result = _ad_test_result(True, message, role, matched)
    record(
        "auth-ad-test", target="ad", detail=f"username={body.username} ok={result['ok']} role={result['role'] or '-'}",
        status="ok" if result["ok"] else "error",
    )
    return result


@router.post("/auth-settings/entra/test")
@audit_action("auth-entra-test")
def check_entra_settings(_: AdminPrincipal):
    entra_settings = settings.load_entra()
    if not settings.is_guid(entra_settings.tenant_id):
        result = {"ok": False, "issuer": None, "message": t("Tenant-ID und Client-ID müssen GUIDs sein.")}
    else:
        try:
            meta = entra.check_configuration(entra_settings)
        except entra.EntraAuthError as exc:
            logger.warning("Entra configuration check failed: %s", exc)
            result = {"ok": False, "issuer": None, "message": t("Die Entra-ID-Konfiguration konnte nicht geladen werden.")}
        else:
            result = {"ok": True, "issuer": meta["issuer"], "message": t("Entra-ID-Konfiguration erfolgreich geladen.")}
    record("auth-entra-test", target="entra", detail=f"ok={result['ok']}", status="ok" if result["ok"] else "error")
    return result


# --- Users ---------------------------------------------------------------------------


def _user_view(user_id: int, conn: sqlite3.Connection | None = None) -> dict:
    views = users.list_users(user_id=user_id, conn=conn)
    if not views:
        raise _not_found(t("Benutzer nicht gefunden."))
    return views[0]


@router.get("/users")
def list_users(_: AdminPrincipal):
    return users.list_users()


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    display_name: str | None = Field(default=None, max_length=256)
    password: str = Field(min_length=1, max_length=1024)
    role: Literal["admin", "operator", "viewer"]

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        value = value.strip()
        if not users.USERNAME_PATTERN.fullmatch(value):
            raise ValueError(t("Der Benutzername darf nur Buchstaben, Ziffern und . _ @ - enthalten (1–64 Zeichen)."))
        return value

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str | None) -> str | None:
        return _display_name(value)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return passwords.validate_password(value)


@router.post("/users")
@audit_action("user-create")
def create_user(body: UserCreate, _: AdminPrincipal):
    password_hash = passwords.hash_password(body.password)
    try:
        with db.get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            user_id = users.create_local_user(conn, body.username, password_hash, body.role, body.display_name)
    except sqlite3.IntegrityError:
        raise _conflict(t("Ein lokaler Benutzer mit diesem Namen existiert bereits.")) from None
    record("user-create", target=body.username, detail=f"provider=local role={body.role}")
    return _user_view(user_id)


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, max_length=256)
    assigned_role: Literal["admin", "operator", "viewer"] | None = None
    enabled: bool | None = None
    password: str | None = Field(default=None, max_length=1024)

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str | None) -> str | None:
        return _display_name(value)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str | None) -> str | None:
        return passwords.validate_password(value) if value is not None else None


@router.put("/users/{user_id}")
@audit_action("user-update")
def update_user(user_id: int, body: UserUpdate, principal: AdminPrincipal):
    fields = body.model_fields_set
    is_self = user_id == principal.user_id
    password_hash = passwords.hash_password(body.password) if body.password is not None else None
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        user = users.get_user(user_id, conn=conn)
        if user is None:
            raise _not_found(t("Benutzer nicht gefunden."))
        local = user.provider == users.LOCAL
        if "assigned_role" in fields and body.assigned_role is None and local:
            raise _bad_request(t("Lokale Benutzer benötigen eine Rolle."))
        if body.password is not None and not local:
            raise _bad_request(t("Passwörter können nur für lokale Benutzer gesetzt werden."))
        if "enabled" in fields and body.enabled is None:
            raise _bad_request(t("Der Status muss aktiv oder gesperrt sein."))
        role_changed = "assigned_role" in fields and body.assigned_role != user.assigned_role
        disabled = "enabled" in fields and body.enabled is False and user.enabled
        if is_self and disabled:
            raise _conflict(t("Das eigene Konto kann nicht gesperrt werden."))
        if is_self and role_changed and body.assigned_role != "admin":
            raise _conflict(t("Die eigene Administratorrolle kann nicht entzogen werden."))
        updates = {}
        if "display_name" in fields:
            updates["display_name"] = body.display_name
        if role_changed:
            updates["assigned_role"] = body.assigned_role
        if "enabled" in fields:
            updates["enabled"] = 1 if body.enabled else 0
        if password_hash is not None:
            updates["password_hash"] = password_hash
        if updates:
            assignments = ", ".join(f"{column} = ?" for column in updates)
            # Column names come from the fixed keys above, never from the request.
            conn.execute(
                f"UPDATE users SET {assignments}, updated_at = ? WHERE id = ?",  # noqa: S608
                (*updates.values(), sessions.timestamp(), user_id),
            )
        ensure_admin_path(conn)
        revoked = 0
        if role_changed or disabled or password_hash is not None:
            # Your own password change keeps the current session; every other session ends.
            keep = principal.session_id if is_self else None
            revoked = sessions.revoke_user_sessions(user_id, keep_session_id=keep, conn=conn)
        view = _user_view(user_id, conn)
    changed = ",".join(sorted("password" if key == "password_hash" else key for key in updates)) or "-"
    record(
        "user-update", target=user.username,
        detail=f"provider={user.provider} fields={changed} role={view['assigned_role'] or '-'} "
               f"enabled={view['enabled']} revoked_sessions={revoked}",
    )
    return view


@router.delete("/users/{user_id}")
@audit_action("user-delete")
def delete_user(user_id: int, principal: AdminPrincipal):
    if user_id == principal.user_id:
        raise _conflict(t("Das eigene Konto kann nicht gelöscht werden."))
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        user = users.get_user(user_id, conn=conn)
        if user is None:
            raise _not_found(t("Benutzer nicht gefunden."))
        # Sessions are removed by ON DELETE CASCADE.
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        ensure_admin_path(conn)
    record("user-delete", target=user.username, detail=f"provider={user.provider}")
    return {"ok": True}


@router.post("/users/{user_id}/revoke-sessions")
@audit_action("sessions-revoke")
def revoke_sessions(user_id: int, principal: AdminPrincipal):
    with db.get_conn() as conn:
        user = users.get_user(user_id, conn=conn)
        if user is None:
            raise _not_found(t("Benutzer nicht gefunden."))
        revoked = sessions.revoke_user_sessions(user_id, keep_session_id=principal.session_id, conn=conn)
    record("sessions-revoke", target=user.username, detail=f"provider={user.provider} revoked_sessions={revoked}")
    return {"ok": True, "revoked": revoked}


# --- Group mappings --------------------------------------------------------------------


def _mapping_view(mapping: settings.GroupMapping) -> dict:
    return {
        "id": mapping.id, "provider": mapping.provider, "group_id": mapping.group_id, "label": mapping.label,
        "role": mapping.role,
    }


@router.get("/group-mappings")
def list_group_mappings(_: AdminPrincipal):
    return [_mapping_view(mapping) for mapping in settings.list_mappings()]


class MappingCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["ad", "entra"]
    group_id: str = Field(min_length=1, max_length=1024)
    label: str | None = Field(default=None, max_length=256)
    role: Literal["admin", "operator", "viewer"]

    @field_validator("label")
    @classmethod
    def validate_label(cls, value: str | None) -> str | None:
        return _display_name(value)

    @field_validator("group_id")
    @classmethod
    def strip_group_id(cls, value: str) -> str:
        value = value.strip()
        if not value or _has_control_characters(value):
            raise ValueError(t("Ungültige Gruppenkennung."))
        return value


class MappingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(default=None, max_length=256)
    role: Literal["admin", "operator", "viewer"] | None = None

    @field_validator("label")
    @classmethod
    def validate_label(cls, value: str | None) -> str | None:
        return _display_name(value)


@router.post("/group-mappings")
@audit_action("mapping-create")
def create_group_mapping(body: MappingCreate, _: AdminPrincipal):
    group_id = body.group_id
    if body.provider == "ad" and "=" not in group_id:
        raise _bad_request(t("AD-Gruppen werden als Distinguished Name (CN=…,DC=…) angegeben."))
    if body.provider == "entra":
        group_id = group_id.lower()
        if not settings.is_guid(group_id):
            raise _bad_request(t("Entra-ID-Gruppen werden mit ihrer Objekt-ID (GUID) angegeben."))
    try:
        with db.get_conn() as conn:
            cursor = conn.execute(
                "INSERT INTO group_role_mappings (provider, group_id, label, role) VALUES (?, ?, ?, ?)",
                (body.provider, group_id, body.label, body.role),
            )
            mapping = settings.get_mapping(cursor.lastrowid, conn=conn)
    except sqlite3.IntegrityError:
        raise _conflict(t("Diese Gruppe ist bereits zugeordnet.")) from None
    record("mapping-create", target=body.provider, detail=f"group={group_id} role={body.role}")
    return {**_mapping_view(mapping), "effective": _EFFECTIVE}


@router.put("/group-mappings/{mapping_id}")
@audit_action("mapping-update")
def update_group_mapping(mapping_id: int, body: MappingUpdate, _: AdminPrincipal):
    fields = body.model_fields_set
    if "role" in fields and body.role is None:
        raise _bad_request(t("Eine Zuordnung benötigt eine Rolle."))
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        mapping = settings.get_mapping(mapping_id, conn=conn)
        if mapping is None:
            raise _not_found(t("Zuordnung nicht gefunden."))
        label = body.label if "label" in fields else mapping.label
        role = body.role if "role" in fields else mapping.role
        conn.execute("UPDATE group_role_mappings SET label = ?, role = ? WHERE id = ?", (label, role, mapping_id))
        ensure_admin_path(conn)
        updated = settings.get_mapping(mapping_id, conn=conn)
    record("mapping-update", target=mapping.provider, detail=f"group={mapping.group_id} role={role}")
    return {**_mapping_view(updated), "effective": _EFFECTIVE}


@router.delete("/group-mappings/{mapping_id}")
@audit_action("mapping-delete")
def delete_group_mapping(mapping_id: int, _: AdminPrincipal):
    with db.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        mapping = settings.get_mapping(mapping_id, conn=conn)
        if mapping is None:
            raise _not_found(t("Zuordnung nicht gefunden."))
        conn.execute("DELETE FROM group_role_mappings WHERE id = ?", (mapping_id,))
        ensure_admin_path(conn)
    record("mapping-delete", target=mapping.provider, detail=f"group={mapping.group_id} role={mapping.role}")
    return {"ok": True, "effective": _EFFECTIVE}


# --- Operations settings ("Betrieb") ----------------------------------------------------------


def _operations_view() -> dict:
    with db.get_conn() as conn:
        backup_settings = system_settings.load_backups(conn)
        transfer = system_settings.load_transfer(conn)
        firmware = system_settings.load_firmware(conn)
    sftp = sftp_server.status()
    return {
        "backups": {
            "directory": backup_settings.directory,
            "resolved_directory": str(config.resolve_runtime_path(backup_settings.directory)),
            "retention": backup_settings.retention,
            "encryption": backup_settings.encryption,
            "password_configured": bool(backup_settings.password_enc),
        },
        "transfer": {
            **transfer.model_dump(),
            "sftp_running": sftp["running"],
            "sftp_host_key_fingerprint": sftp["fingerprint"],
        },
        "firmware": {
            "directory": firmware.directory,
            "resolved_directory": str(config.resolve_runtime_path(firmware.directory)),
        },
    }


def _checked_storage_dir(directory: str) -> None:
    try:
        system_settings.storage_dir(directory)
    except ValueError as exc:
        raise _bad_request(str(exc)) from None


@router.get("/operations-settings")
def get_operations_settings(_: AdminPrincipal):
    return _operations_view()


class BackupSettingsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    directory: str = Field(min_length=1, max_length=1024)
    retention: int = Field(ge=1, le=1000)
    encryption: Literal["none", "password"]
    # Only needed when switching to password mode or changing the password.
    password: str | None = Field(default=None, min_length=12, max_length=1024)


@router.put("/operations-settings/backups")
@audit_action("operations-settings-update")
def update_backup_settings(body: BackupSettingsInput, _: AdminPrincipal):
    previous = system_settings.load_backups()
    old_password = system_settings.backup_password(previous)
    password = None
    if body.encryption == "password":
        password = body.password or old_password
        if not password:
            raise _bad_request(t("Für die Backup-Verschlüsselung ist ein Passwort erforderlich."))
    try:
        updated = system_settings.BackupSettings(
            directory=body.directory, retention=body.retention, encryption=body.encryption,
            password_enc=system_settings.encrypt_password(password) if password else None,
        )
    except ValidationError as exc:
        raise _bad_request(_validation_message(exc)) from None
    _checked_storage_dir(updated.directory)
    password_changed = password is not None and password != old_password
    converted = 0
    if body.encryption != previous.encryption or password_changed:
        # Existing files are converted first; on failure files and settings stay unchanged.
        try:
            converted = backups.reencrypt_all(
                previous, body.encryption, password,
                commit_with=lambda conn: system_settings.save(updated, conn=conn),
            )
        except ValueError as exc:
            raise _bad_request(str(exc)) from None
    else:
        system_settings.save(updated)
    logger.info("Backup settings saved (encryption=%s, converted=%d)", updated.encryption, converted)
    record("operations-settings-update", target="backups", detail=(
        f"directory={updated.directory} retention={updated.retention} encryption={updated.encryption} "
        f"password={'changed' if password_changed else 'kept'} converted={converted}"
    ))
    return _operations_view()


@router.put("/operations-settings/transfer")
@audit_action("operations-settings-update")
def update_transfer_settings(body: system_settings.TransferSettings, _: AdminPrincipal):
    previous = system_settings.load_transfer()
    running = sftp_server.status()["running"]
    listener_changed = (body.sftp_bind, body.sftp_port) != (previous.sftp_bind, previous.sftp_port)
    if body.sftp_enabled != running or (body.sftp_enabled and listener_changed):
        # The server is (re)started first; a bind failure keeps the previous settings.
        try:
            sftp_server.restart(body)
        except OSError as exc:
            try:
                sftp_server.restart(previous)
            except OSError as restore_error:
                logger.error("Previous SFTP server could not be restored: %s", restore_error)
            raise _bad_request(t(
                "Der SFTP-Server konnte nicht gestartet werden: {error}", error=exc.strerror or str(exc),
            )) from None
    system_settings.save(body)
    logger.info("Transfer settings saved")
    record("operations-settings-update", target="transfer", detail=(
        f"base_url={body.base_url or '-'} token_minutes={body.token_minutes} sftp_enabled={body.sftp_enabled} "
        f"sftp_bind={body.sftp_bind} sftp_port={body.sftp_port} sftp_host={body.sftp_host or '-'}"
    ))
    return _operations_view()


@router.put("/operations-settings/firmware")
@audit_action("operations-settings-update")
def update_firmware_settings(body: system_settings.FirmwareSettings, _: AdminPrincipal):
    _checked_storage_dir(body.directory)
    system_settings.save(body)
    logger.info("Firmware settings saved")
    record("operations-settings-update", target="firmware", detail=f"directory={body.directory}")
    return _operations_view()
