import asyncio
import logging
import os
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import audit, config, request_context, scheduler, sftp_server, system_settings, updates
from . import database as db
from .audit import AuditFallbackMiddleware
from .auth import settings as auth_settings
from .auth.admin_routes import router as admin_router
from .auth.routes import router as auth_router
from .favicon import router as favicon_router
from .firmware_routes import router as firmware_router
from .i18n import LanguageMiddleware, current_language, language_from_headers, t
from .inventory_routes import router as inventory_router
from .jobs_routes import router as jobs_router
from .log_routes import router as log_router
from .logging_setup import configure_logging
from .profile_routes import router as profile_router
from .request_context import RequestContextMiddleware
from .runtime_files import prepare_runtime_files
from .security import UPLOAD_ROUTES, SecurityMiddleware
from .switches import transport as switch_transport
from .switches.backup_routes import router as switches_backup_router
from .switches.device_routes import router as switches_device_router
from .switches.errors import ChangeConflict, InvalidInputError, SwitchConnectionError, UnsupportedFeatureError
from .switches.l2_routes import router as switches_l2_router
from .switches.maintenance_routes import router as switches_maintenance_router
from .switches.rollout_routes import router as switches_rollout_router
from .switches.routes import router as switches_router
from .switches.security_routes import router as switches_security_router
from .system_routes import router as system_router
from .transfer_routes import router as transfer_router
from .version import get_version
from .wlan import models as wlan_models
from .wlan.routes import router as wlan_router

logger = logging.getLogger("switchsteward.api")
FRONTEND_DIR = config.settings.frontend_dir
_STATIC_SUFFIXES = (".html", ".css", ".js")
_VERSION_PLACEHOLDER = "__APP_VERSION__"


def _active_sign_in_methods() -> str:
    methods = ["local"]
    if auth_settings.load_ad().enabled:
        methods.append("ad")
    if auth_settings.load_entra().enabled:
        methods.append("entra")
    return ",".join(methods)


def _log_startup(settings: config.Settings) -> None:
    logger.info(
        "SwitchSteward %s starting: config=%s database=%s tls=%s auth=%s",
        get_version(), settings.config_file, settings.database_path,
        "enabled" if settings.tls_enabled else "disabled", _active_sign_in_methods(),
    )
    ad = auth_settings.load_ad()
    for enabled, message in (
        (settings.ssh_allow_legacy, "Legacy SSH algorithms are allowed (ssh.allow_legacy_algorithms)"),
        (not settings.ssh_strict_host_keys, "SSH host key checking is disabled (ssh.strict_host_keys)"),
        (ad.enabled and ad.allow_insecure_ldap, "Unencrypted LDAP is allowed (Active Directory settings)"),
        (ad.enabled and ad.allow_unverified_ldaps,
         "Unverified LDAPS certificates are allowed (Active Directory settings)"),
        (settings.wireless_allow_unverified_restconf_tls,
         "Unverified RESTCONF TLS is allowed (wireless.allow_unverified_restconf_tls)"),
        (settings.switch_api_allow_unverified_tls,
         "Unverified switch API TLS is allowed (switch_api.allow_unverified_tls)"),
    ):
        if enabled:
            logger.warning(message)


def _audit_update_result() -> None:
    try:
        result = updates.update_manager.unaudited_result()
        if result is None:
            return
        audit.record(
            "install-update-result", username="system",
            detail=f"version={result.get('version')} update_id={result.get('update_id')} {result.get('message', '')}",
            status="ok" if result.get("status") == "success" else "error",
        )
        updates.update_manager.mark_result_audited(result.get("update_id"))
    except updates.UpdateError as exc:
        logger.warning("Update result could not be audited: %s", exc)


def _start_sftp() -> None:
    """Start the built-in SFTP transfer server when enabled; a bind failure is logged, not fatal."""
    transfer_settings = system_settings.load_transfer()
    if not transfer_settings.sftp_enabled:
        return
    try:
        sftp_server.start(transfer_settings)
    except OSError as exc:
        logger.error("SFTP transfer server could not be started: %s", exc)


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = config.settings
    configure_logging(settings)
    prepare_runtime_files(settings)
    config.validate_file_settings()
    switch_transport.validate_ssh_configuration()
    switch_transport.apply_legacy_ssh_policy()
    db.init_db()
    _log_startup(settings)
    _audit_update_result()
    scheduler.recover_jobs()
    _start_sftp()
    stop = asyncio.Event()
    scheduler_task = asyncio.create_task(scheduler.run_scheduler(stop))
    try:
        yield
    finally:
        stop.set()
        await scheduler_task
        sftp_server.stop()
        logger.info("SwitchSteward stopping")


app = FastAPI(
    title="SwitchSteward",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(inventory_router)
app.include_router(switches_router)
app.include_router(switches_backup_router)
app.include_router(switches_l2_router)
app.include_router(switches_security_router)
app.include_router(switches_maintenance_router)
app.include_router(switches_device_router)
app.include_router(switches_rollout_router)
app.include_router(firmware_router)
app.include_router(profile_router)
app.include_router(wlan_router)
app.include_router(system_router)
app.include_router(log_router)
app.include_router(jobs_router)
app.include_router(favicon_router)
app.include_router(transfer_router)

# Added innermost first: Language > RequestContext > AuditFallback > Security > routes, so
# rejections of the security middleware are translated too.
app.add_middleware(
    SecurityMiddleware, max_body_bytes=config.settings.api_max_body_bytes, upload_routes=UPLOAD_ROUTES,
)
app.add_middleware(AuditFallbackMiddleware)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(LanguageMiddleware)


@app.exception_handler(RequestValidationError)
async def request_validation_error(_: Request, exc: RequestValidationError):
    # The default response includes rejected values and can echo passwords.
    errors = [{key: value for key, value in error.items() if key not in {"input", "ctx"}} for error in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.exception_handler(InvalidInputError)
async def invalid_switch_input(_: Request, exc: InvalidInputError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(UnsupportedFeatureError)
async def unsupported_switch_feature(_: Request, exc: UnsupportedFeatureError):
    return JSONResponse(status_code=409, content={"detail": {
        "message": t(exc.reason, **exc.params), "code": "incompatible", "feature": exc.feature,
    }})


@app.exception_handler(ChangeConflict)
async def switch_change_conflict(_: Request, exc: ChangeConflict):
    return JSONResponse(status_code=409, content={"detail": {"message": exc.message, "code": exc.code}})


@app.exception_handler(SwitchConnectionError)
async def switch_connection_error(_: Request, exc: SwitchConnectionError):
    logger.error("Switch connection error: %s", exc)
    return JSONResponse(status_code=502, content={"detail": str(exc)})


@app.exception_handler(wlan_models.WlanConfigurationError)
@app.exception_handler(wlan_models.UnsupportedPlatformError)
async def wlan_configuration_error(_: Request, exc: wlan_models.WlanError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(wlan_models.WlanError)
async def wlan_connection_error(_: Request, exc: wlan_models.WlanError):
    logger.error("WLAN controller error: %s", exc)
    return JSONResponse(status_code=502, content={"detail": str(exc)})


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    request_id = request_context.current_request_id() or "-"
    logger.error("Unhandled exception (request %s)", request_id, exc_info=exc)
    # This handler runs in Starlette's outermost error middleware, outside LanguageMiddleware.
    token = current_language.set(language_from_headers(request.headers))
    try:
        detail = t("Interner Fehler (Request-ID {request_id}).", request_id=request_id)
    finally:
        current_language.reset(token)
    return JSONResponse(status_code=500, content={"detail": detail}, headers={"X-Request-ID": request_id})


class _FrontendFiles(StaticFiles):
    """Serve only top-level .html/.css/.js files; everything else stays private."""

    async def get_response(self, path: str, scope):
        if path != os.path.basename(path) or "/" in path or "\\" in path or not path.endswith(_STATIC_SUFFIXES):
            raise StarletteHTTPException(status_code=404)
        return await super().get_response(path, scope)


app.mount("/static", _FrontendFiles(directory=str(FRONTEND_DIR)), name="static")


@lru_cache(maxsize=1)
def _index_html(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace(_VERSION_PLACEHOLDER, quote(get_version()))


@app.get("/")
def index():
    return HTMLResponse(_index_html(FRONTEND_DIR / "index.html"))
