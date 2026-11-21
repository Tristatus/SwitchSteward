"""Lokaler Einrichtungsassistent für neue Installationen."""

import asyncio
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import ssl
import tempfile
from contextlib import asynccontextmanager, closing
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator, model_validator
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

from . import audit, config
from .auth import passwords
from .auth import users as auth_users
from .favicon import router as favicon_router
from .i18n import LanguageMiddleware, t
from .logging_setup import configure_logging
from .release_manifest import REQUIRED_FRONTEND_FILES
from .request_context import RequestContextMiddleware
from .runtime_files import prepare_runtime_files
from .schema import initialize_schema

logger = logging.getLogger("switchsteward.setup")

_BODY_LIMIT = 65_536
_FRONTEND_DIR = config.BACKEND_DIR.parent / "frontend"
_HEADERS = {
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'"
    ),
}
_Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1024)]
_PathText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4096)]
_HostText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=253)]
_Secret = Annotated[str, StringConstraints(min_length=1, max_length=1024)]


def _host(value: str) -> str:
    host = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if len(host) > 253 or not all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
        for part in host.rstrip(".").split(".")
    ):
        raise ValueError(t("Host muss eine IP-Adresse oder ein DNS-Name ohne URL/Port sein."))
    return host.lower()


class SetupInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    admin_username: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
    admin_password: Annotated[str, StringConstraints(min_length=12, max_length=1024)]
    server_host: _HostText
    server_port: Annotated[int, Field(strict=True, ge=1, le=65_535)]
    tls_mode: Literal["http", "self_signed", "certificate", "reverse_proxy"]
    public_url: _Text | None = None
    tls_cert_file: _PathText | None = None
    tls_key_file: _PathText | None = None
    database_path: _PathText
    ssh_known_hosts_file: _PathText | None = None
    netconf_known_hosts_file: _PathText | None = None
    ssh_username: _Text | None = None
    ssh_password: _Secret | None = None
    ssh_enable_secret: _Secret | None = None

    @field_validator("*", mode="before")
    @classmethod
    def reject_control_characters(cls, value):
        values = value if isinstance(value, list) else [value]
        if any(
            isinstance(item, str) and any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in values
        ):
            raise ValueError(t("Steuerzeichen und Zeilenumbrüche sind nicht erlaubt."))
        return value

    @field_validator("server_host")
    @classmethod
    def validate_host(cls, value):
        return _host(value)

    @field_validator("admin_username")
    @classmethod
    def validate_admin_username(cls, value):
        if not auth_users.USERNAME_PATTERN.fullmatch(value):
            raise ValueError(t("Der Benutzername darf nur Buchstaben, Ziffern und . _ @ - enthalten (1–64 Zeichen)."))
        return value

    @field_validator("admin_password")
    @classmethod
    def validate_admin_password(cls, value):
        return passwords.validate_password(value)

    @model_validator(mode="after")
    def validate_credentials_and_tls(self):
        if bool(self.ssh_username) != bool(self.ssh_password):
            raise ValueError(t("SSH-Benutzername und Passwort müssen gemeinsam angegeben werden."))
        if self.ssh_enable_secret and not self.ssh_username:
            raise ValueError(t("Ein Enable-Passwort benötigt SSH-Zugangsdaten."))
        if self.tls_mode == "certificate" and not (self.tls_cert_file and self.tls_key_file):
            raise ValueError(t("Für HTTPS müssen Zertifikat und privater Schlüssel angegeben werden."))
        if self.tls_mode == "reverse_proxy":
            if not self.public_url:
                raise ValueError(t("Für einen Reverse Proxy ist die öffentliche HTTPS-Adresse erforderlich."))
            try:
                url = urlsplit(self.public_url)
                valid = (
                    url.scheme == "https"
                    and url.hostname
                    and url.username is None
                    and url.password is None
                    and url.path in {"", "/"}
                    and not url.query
                    and not url.fragment
                    and (url.port is None or 1 <= url.port <= 65_535)
                )
                if valid:
                    _host(url.hostname)
            except ValueError:
                valid = False
            if not valid:
                raise ValueError(t("Die öffentliche Adresse muss eine HTTPS-URL ohne Pfad oder Zugangsdaten sein."))
        return self


def _setup_required(path: Path) -> bool:
    return config._read_json(path).get("installation", {}).get("completed", True) is False


def _error(detail: str, status_code: int) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status_code, headers=_HEADERS)


class _SetupGuard:
    def __init__(self, app, config_file: Path):
        self.app = app
        self.config_file = config_file

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)

        async def secure_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {name.lower() for name, _ in headers}
                headers.extend(
                    (name.lower().encode("ascii"), value.encode("ascii"))
                    for name, value in _HEADERS.items()
                    if name.lower().encode("ascii") not in existing
                )
                message = {**message, "headers": headers}
            await send(message)

        try:
            local_peer = request.client and ipaddress.ip_address(request.client.host).is_loopback
            local_host = re.fullmatch(
                r"(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?",
                request.headers.get("host", "").lower(),
            )
            # Ungültige Portangaben dürfen nicht in die Origin-Prüfung gelangen.
            _ = request.url.port
        except ValueError:
            local_peer = local_host = False
        if not local_peer or not local_host:
            await _error(t("Die Ersteinrichtung ist nur auf diesem Rechner erreichbar."), 403)(scope, receive, secure_send)
            return
        origin = request.headers.get("origin")
        expected_origin = str(request.base_url).rstrip("/")
        if (origin is not None and origin != expected_origin) or (request.method == "POST" and origin is None):
            await _error(t("Unzulässiger Anfrage-Ursprung."), 403)(scope, receive, secure_send)
            return
        try:
            required = _setup_required(self.config_file)
        except (RuntimeError, OSError):
            await _error(t("Der Einrichtungsstatus kann nicht gelesen werden."), 503)(scope, receive, secure_send)
            return
        if not required:
            code = 409 if request.method == "POST" else 404
            await _error(t("Die Ersteinrichtung wurde bereits abgeschlossen."), code)(scope, receive, secure_send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > _BODY_LIMIT:
                await _error(t("Die Anfrage ist zu groß."), 413)(scope, receive, secure_send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        received = False

        async def limited_receive():
            nonlocal received
            if not received:
                received = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, limited_receive, secure_send)


def _configuration(payload: SetupInput, config_file: Path) -> tuple[dict, config.Settings]:
    data = config._read_json(config_file)
    data["application"]["database_path"] = payload.database_path
    data["server"].update(host=payload.server_host, port=payload.server_port)
    use_tls = payload.tls_mode in {"self_signed", "certificate"}
    data["server"]["tls"].update(
        enabled=use_tls,
        generate_self_signed=payload.tls_mode == "self_signed",
        cert_file=(payload.tls_cert_file or "cert.pem") if use_tls else None,
        key_file=(payload.tls_key_file or "key.pem") if use_tls else None,
    )
    data["session"]["cookie_secure"] = payload.tls_mode != "http"
    data["ssh"].update(strict_host_keys=True, known_hosts_file=payload.ssh_known_hosts_file)
    data.setdefault("wireless", {}).update(
        netconf_strict_host_keys=True, netconf_known_hosts_file=payload.netconf_known_hosts_file
    )
    data.setdefault("installation", {})["completed"] = True
    loaded = config._load_settings(data)
    if loaded.database_path.exists() or loaded.database_path.is_symlink():
        raise ValueError(t("Der Datenbankpfad existiert bereits. Für die Ersteinrichtung eine neue Datei wählen."))
    if not loaded.secret_key:
        data["secrets"]["encryption_key"] = Fernet.generate_key().decode("ascii")
    if not loaded.session_secret_key:
        data["secrets"]["session_key"] = secrets.token_urlsafe(32)
    loaded = config._load_settings(data)
    if payload.tls_mode == "certificate":
        if not loaded.tls_cert_file.is_file() or not loaded.tls_key_file.is_file():
            raise ValueError(t("TLS-Zertifikat und Schlüssel müssen vorhandene Dateien sein."))
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
            loaded.tls_cert_file, loaded.tls_key_file, password=""
        )
    return data, loaded


def _save_setup(payload: SetupInput, config_file: Path) -> config.Settings:
    data, loaded = _configuration(payload, config_file)
    if not loaded.secret_key:
        raise ValueError(t("Der Verschlüsselungsschlüssel fehlt in der Konfiguration."))
    cipher = Fernet(loaded.secret_key.encode("ascii"))
    session_key = loaded.session_secret_key or loaded.secret_key
    if len(session_key.encode("utf-8")) < 32:
        raise ValueError(t("Der vorhandene Session-Schlüssel muss mindestens 32 Byte lang sein."))
    for required in REQUIRED_FRONTEND_FILES:
        asset = required.removeprefix("frontend/")
        if not (loaded.frontend_dir / asset).is_file():
            raise ValueError(t("Im konfigurierten Frontend-Verzeichnis fehlt {asset}.", asset=asset))
    if loaded.database_path in {
        loaded.ssh_known_hosts_file,
        loaded.wireless_netconf_known_hosts_file,
        loaded.tls_cert_file,
        loaded.tls_key_file,
    }:
        raise ValueError(t("Die Datenbank benötigt einen eigenen Pfad, getrennt von Host-Schlüsseln und TLS-Dateien."))
    prepare_runtime_files(loaded)
    config.validate_file_settings(loaded)
    config.validate_server_settings(loaded)
    if loaded.tls_enabled:
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
            loaded.tls_cert_file, loaded.tls_key_file, password=""
        )
    admin_password_hash = passwords.hash_password(payload.admin_password)
    loaded.database_path.parent.mkdir(parents=True, exist_ok=True)
    database_created = False
    temporary_path = None
    try:
        descriptor = os.open(loaded.database_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        database_created = True
        with closing(sqlite3.connect(loaded.database_path, timeout=loaded.sqlite_timeout_seconds)) as connection:
            with connection:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys = ON")
                initialize_schema(connection)
                auth_users.create_local_user(connection, payload.admin_username, admin_password_hash, "admin")
                if payload.ssh_username:
                    connection.execute(
                        "INSERT INTO credentials (id, username, password_enc, enable_secret_enc) VALUES (1, ?, ?, ?)",
                        (
                            payload.ssh_username,
                            cipher.encrypt(payload.ssh_password.encode("utf-8")),
                            cipher.encrypt(payload.ssh_enable_secret.encode("utf-8")) if payload.ssh_enable_secret else None,
                        ),
                    )
        descriptor, temporary_name = tempfile.mkstemp(prefix=".setup-", suffix=".json", dir=config_file.parent)
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.chmod(temporary_path, 0o600)
            stream.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, config_file)
    except Exception:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        if database_created:
            loaded.database_path.unlink(missing_ok=True)
        raise
    return loaded


def _next_url(settings: config.Settings, payload: SetupInput) -> str:
    if payload.tls_mode == "reverse_proxy":
        return payload.public_url.rstrip("/") + "/"
    host = settings.server_host
    try:
        address = ipaddress.ip_address(host)
        if address.is_unspecified:
            host = "localhost"
        elif address.version == 6:
            host = f"[{host}]"
    except ValueError:
        pass
    scheme = "http" if payload.tls_mode == "http" else "https"
    return f"{scheme}://{host}:{settings.server_port}/"


def _audit_setup_complete(loaded: config.Settings, payload: SetupInput) -> None:
    # The new database is not the configured one yet; the record goes there directly.
    # The actor is the local administrator created by the setup.
    try:
        with closing(sqlite3.connect(loaded.database_path, timeout=loaded.sqlite_timeout_seconds)) as connection:
            with connection:
                audit.record(
                    "setup-complete", username=payload.admin_username, auth_provider="local",
                    detail=f"tls_mode={payload.tls_mode} server={loaded.server_host}:{loaded.server_port}",
                    connection=connection,
                )
    except sqlite3.Error as exc:
        logger.error("Setup completion could not be audited: %s", exc)


@asynccontextmanager
async def _lifespan(_: FastAPI):
    configure_logging(config.settings)
    logger.info("Setup assistant starting: config=%s", config.settings.config_file)
    yield


def create_setup_app() -> FastAPI:
    app = FastAPI(
        title="SwitchSteward – Ersteinrichtung", docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan,
    )
    app.include_router(favicon_router)
    config_file = config.settings.config_file
    token = secrets.token_urlsafe(32)
    lock = asyncio.Lock()
    app.state.on_complete = None
    # Added innermost first: RequestContext > Language > SetupGuard > routes, so guard
    # errors are translated too. No audit fallback here: before completion there is no
    # configured database to write into.
    app.add_middleware(_SetupGuard, config_file=config_file)
    app.add_middleware(LanguageMiddleware)
    app.add_middleware(RequestContextMiddleware)

    @app.get("/")
    async def setup_page():
        return FileResponse(_FRONTEND_DIR / "setup.html")

    @app.get("/static/setup.css")
    async def setup_styles():
        return FileResponse(_FRONTEND_DIR / "setup.css", media_type="text/css")

    @app.get("/static/setup.js")
    async def setup_script():
        return FileResponse(_FRONTEND_DIR / "setup.js", media_type="text/javascript")

    @app.get("/static/i18n.js")
    async def setup_i18n():
        return FileResponse(_FRONTEND_DIR / "i18n.js", media_type="text/javascript")

    @app.get("/static/i18n.en.js")
    async def setup_i18n_en():
        return FileResponse(_FRONTEND_DIR / "i18n.en.js", media_type="text/javascript")

    @app.get("/api/setup")
    async def setup_status():
        settings = config._load_settings(config._read_json(config_file))
        return {
            "required": True,
            "token": token,
            "defaults": {
                "server_host": settings.server_host,
                "server_port": settings.server_port,
                "database_path": str(settings.database_path),
            },
        }

    @app.post("/api/setup")
    @audit.audit_action("setup-complete")
    async def save_setup(request: Request):
        supplied_token = request.headers.get("x-setup-token", "")
        if not secrets.compare_digest(supplied_token.encode("utf-8"), token.encode("ascii")):
            return _error(t("Ungültiges Einrichtungstoken. Die Seite neu laden."), 403)
        try:
            payload = SetupInput.model_validate(await request.json())
        except (json.JSONDecodeError, UnicodeError, RecursionError):
            return _error(t("Die Anfrage enthält kein gültiges JSON."), 422)
        except ValidationError as exc:
            errors = exc.errors(include_input=False, include_context=False, include_url=False)
            return JSONResponse({"detail": errors}, status_code=422)
        except ValueError:
            # Python also rejects JSON integers exceeding its conversion limit.
            return _error(t("Die Anfrage enthält kein gültiges JSON."), 422)
        async with lock:
            if not _setup_required(config_file):
                return _error(t("Die Ersteinrichtung wurde bereits abgeschlossen."), 409)
            try:
                loaded = await run_in_threadpool(_save_setup, payload, config_file)
            except (ValueError, RuntimeError, OSError, sqlite3.Error) as exc:
                logger.warning("Setup could not be saved: %s", exc)
                return _error(t("Die Einrichtung konnte nicht gespeichert werden: {error}", error=exc), 422)
        await run_in_threadpool(_audit_setup_complete, loaded, payload)
        logger.info("Setup completed: database=%s", loaded.database_path)
        callback = app.state.on_complete
        return JSONResponse(
            {
                "saved": True,
                "restart_required": True,
                "automatic_restart": callable(callback),
                "next_url": _next_url(loaded, payload),
            },
            background=BackgroundTask(callback) if callable(callback) else None,
        )

    return app
