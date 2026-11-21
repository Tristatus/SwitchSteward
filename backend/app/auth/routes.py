"""Sign-in methods, local/AD login, Entra ID redirect flow, logout and session information."""

import html
import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .. import config, request_context
from .. import database as db
from ..audit import audit_action, record
from ..i18n import t
from . import CurrentPrincipal, entra, ldap, sessions, settings, throttle, users
from .local import LocalAuthError, authenticate_local
from .roles import resolve_role
from .sessions import Role

logger = logging.getLogger("switchsteward.auth")
router = APIRouter(tags=["auth"])

ENTRA_LOGIN_PATH = "/api/auth/entra/login"
_NO_STORE = {"Cache-Control": "no-store"}


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["local", "ad"] = "local"
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError(t("Benutzername darf nicht leer sein."))
        return value


def client_ip(request: Request) -> str:
    # Do not trust spoofable forwarding headers without trusted-proxy middleware.
    return request.client.host if request.client else "unknown"


def _login_failed(username: str | None, provider: str, reason: str) -> None:
    record("login-failed", username=username, auth_provider=provider, detail=f"reason={reason}", status="error")


def _invalid_credentials() -> HTTPException:
    # Cookie authentication: no WWW-Authenticate challenge.
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=t("Benutzername oder Passwort falsch."))


def _start_session(user: users.User, role: Role) -> tuple[str, str]:
    """Create the session row and audit the login; returns ``(cookie_token, csrf_token)``."""
    with db.get_conn() as conn:
        sessions.purge_expired(conn=conn)
        users.record_login(conn, user.id, role.value)
        token, csrf_token = sessions.create_session(user.id, role, conn=conn)
    request_context.set_principal(user.username, user.provider)
    logger.info("Login of %s (%s, role %s)", user.username, user.provider, role.value)
    record("login", username=user.username, auth_provider=user.provider, detail=f"role={role.value}")
    return token, csrf_token


def _external_user(provider: str, identity, mappings, default_role: str) -> tuple[users.User, Role | None]:
    """Create/refresh the account record and resolve its role, even when no role results."""
    with db.get_conn() as conn:
        user = users.upsert_external_user(
            conn, provider, identity.subject, identity.username, identity.display_name, identity.email,
        )
        group_ids = getattr(identity, "matched_group_ids", None) or getattr(identity, "group_ids", frozenset())
        role = resolve_role(user, provider, group_ids, mappings, default_role)
        users.record_login(conn, user.id, role.value if role else None)
    return user, role


def _login_local(body: LoginRequest, ip: str) -> tuple[users.User, Role]:
    _reserve(ip, "local", body.username)
    try:
        user = authenticate_local(body.username, body.password)
    except LocalAuthError as exc:
        logger.info("Failed local login for %s from %s (%s)", body.username, ip, exc.reason)
        _login_failed(body.username, "local", exc.reason)
        raise _invalid_credentials() from None
    role = resolve_role(user, "local", (), (), "none")
    if role is None:
        _login_failed(user.username, "local", "no_role")
        raise _invalid_credentials()
    throttle.clear_login_failures(ip, "local", body.username)
    return user, role


def _login_ad(body: LoginRequest, ip: str) -> tuple[users.User, Role]:
    ad = settings.load_ad()
    if not ad.enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=t("Active Directory ist deaktiviert."))
    attempt = _reserve(ip, "ad", body.username)
    mappings = settings.list_mappings("ad")
    try:
        identity = ldap.authenticate(ad, mappings, body.username, body.password)
    except (ldap.LdapConfigError, ldap.DirectoryUnavailableError) as exc:
        throttle.discard_login_attempt(ip, "ad", body.username, attempt)
        logger.error("Active Directory unavailable: %s", exc)
        _login_failed(body.username, "ad", "unavailable")
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, t("Anmeldedienst ist nicht verfügbar.")) from None
    except ldap.LdapAuthError:
        logger.info("Failed AD login for %s from %s", body.username, ip)
        _login_failed(body.username, "ad", "invalid_credentials")
        raise _invalid_credentials() from None
    user, role = _external_user("ad", identity, mappings, ad.default_role)
    if role is None:
        reason = "disabled" if not user.enabled else "no_role"
        logger.info("AD login of %s refused (%s)", user.username, reason)
        _login_failed(user.username, "ad", reason)
        raise _invalid_credentials()
    throttle.clear_login_failures(ip, "ad", body.username)
    return user, role


def _reserve(ip: str, provider: str, username: str) -> float:
    try:
        return throttle.reserve_login_attempt(ip, provider, username)
    except HTTPException:
        _login_failed(username, provider, "throttled")
        raise


@router.get("/api/auth/methods")
def auth_methods():
    general = settings.load_general()
    return {
        "local": {"enabled": True},
        "ad": {"enabled": settings.load_ad().enabled},
        "entra": {
            "enabled": settings.load_entra().enabled and bool(general.public_base_url),
            "login_url": ENTRA_LOGIN_PATH,
        },
    }


@router.post("/api/login")
@audit_action("login")
def login(body: LoginRequest, request: Request, response: Response):
    ip = client_ip(request)
    user, role = _login_local(body, ip) if body.provider == "local" else _login_ad(body, ip)
    token, csrf_token = _start_session(user, role)
    sessions.set_session_cookie(response, token)
    return {
        "ok": True,
        "username": user.username,
        "display_name": user.display_name,
        "provider": user.provider,
        "role": role.value,
        "can_edit": role is Role.ADMIN,
        "can_operate": role in (Role.ADMIN, Role.OPERATOR),
        "csrf_token": csrf_token,
    }


@router.post("/api/logout")
@audit_action("logout")
def logout(response: Response, principal: CurrentPrincipal):
    sessions.delete_session(principal.session_id)
    sessions.clear_session_cookie(response)
    logger.info("Logout of %s", principal.username)
    record("logout")
    return {"ok": True}


@router.get("/api/me")
def me(principal: CurrentPrincipal):
    return {
        "username": principal.username,
        "display_name": principal.display_name,
        "provider": principal.provider,
        "role": principal.role.value,
        "can_edit": principal.can_edit,
        "can_operate": principal.can_operate,
        "csrf_token": principal.csrf_token,
    }


def _redirect_page(target: str) -> HTMLResponse:
    """200 page that navigates same-site, so the SameSite=Strict session cookie is sent on the next request."""
    url = html.escape(target, quote=True)
    body = (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        f"<meta http-equiv=\"refresh\" content=\"0;url={url}\"><title>SwitchSteward</title></head>"
        f"<body><p><a href=\"{url}\">{html.escape(t('Weiter zu SwitchSteward'))}</a></p></body></html>"
    )
    return HTMLResponse(body, headers=_NO_STORE)


def _error_page(code: str) -> HTMLResponse:
    response = _redirect_page(f"/?login_error={code}")
    _clear_transaction_cookie(response)
    return response


def _clear_transaction_cookie(response: Response) -> None:
    response.delete_cookie(
        entra.TX_COOKIE, path=entra.CALLBACK_PATH, secure=config.settings.cookie_secure, httponly=True, samesite="lax",
    )


@router.get(ENTRA_LOGIN_PATH)
def entra_login():
    entra_settings = settings.load_entra()
    redirect_uri = settings.entra_redirect_uri(settings.load_general())
    if not entra_settings.enabled or not redirect_uri:
        return _redirect_page("/?login_error=entra_disabled")
    try:
        authorize_url, tx_cookie = entra.begin_login(entra_settings, redirect_uri)
    except entra.EntraAuthError as exc:
        logger.error("Entra sign-in could not start: %s", exc)
        return _redirect_page("/?login_error=entra_unavailable")
    response = RedirectResponse(authorize_url, status_code=status.HTTP_302_FOUND, headers=_NO_STORE)
    # Lax (not Strict): the callback is a top-level GET navigation coming from Microsoft.
    response.set_cookie(
        entra.TX_COOKIE, tx_cookie, max_age=entra.TX_MAX_AGE, httponly=True, samesite="lax",
        secure=config.settings.cookie_secure, path=entra.CALLBACK_PATH,
    )
    return response


@router.get(entra.CALLBACK_PATH)
def entra_callback(request: Request):
    entra_settings = settings.load_entra()
    redirect_uri = settings.entra_redirect_uri(settings.load_general())
    if not entra_settings.enabled or not redirect_uri:
        return _error_page("entra_disabled")
    try:
        identity = entra.complete_login(
            entra_settings, redirect_uri, dict(request.query_params), request.cookies.get(entra.TX_COOKIE),
        )
    except entra.EntraAuthError as exc:
        logger.warning("Entra sign-in failed: %s", exc)
        _login_failed(None, "entra", "unavailable" if exc.code == "unavailable" else "invalid_credentials")
        return _error_page(f"entra_{exc.code}")
    user, role = _external_user("entra", identity, settings.list_mappings("entra"), entra_settings.default_role)
    if role is None:
        reason = "disabled" if not user.enabled else "no_role"
        logger.info("Entra login of %s refused (%s)", user.username, reason)
        _login_failed(user.username, "entra", reason)
        return _error_page("account_disabled" if reason == "disabled" else "entra_no_role")
    token, _csrf_token = _start_session(user, role)
    response = _redirect_page("/")
    _clear_transaction_cookie(response)
    sessions.set_session_cookie(response, token)
    return response
