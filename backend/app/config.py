"""Zentrale, JSON-basierte Laufzeitkonfiguration von SwitchSteward."""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bootstrap_config import ensure_config
from .i18n import t

BACKEND_DIR = Path(__file__).resolve().parent.parent


def _resolve_path(value: str, *, base_dir: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


# Der Pfad zur zentralen JSON-Datei ist die einzige Bootstrap-Einstellung.
CONFIG_FILE = _resolve_path(
    os.environ.get("SWITCHSTEWARD_CONFIG_FILE", "config.json"),
    base_dir=BACKEND_DIR,
)


def resolve_runtime_path(value: str) -> Path:
    """Absolute path; relative values are resolved against the configuration file's directory."""
    return _resolve_path(value, base_dir=CONFIG_FILE.parent)


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        ensure_config(path)
    if not path.is_file():
        raise RuntimeError(t(
            "Konfigurationsdatei nicht gefunden: {path}. Der konfigurierte Pfad muss eine JSON-Datei sein.", path=path
        ))
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(t("Konfigurationsdatei kann nicht gelesen werden: {path}: {error}", path=path, error=exc)) from exc
    if not isinstance(data, dict):
        raise RuntimeError(t("Die Konfigurationsdatei muss ein JSON-Objekt enthalten."))
    return data


MISSING: Any = object()


def _lookup(data: dict[str, Any], *path: str, default: Any = MISSING) -> Any:
    """Return the value at ``path``; missing keys yield ``default`` or raise if no default is given."""
    current: Any = data
    for part in path:
        if not isinstance(current, dict):
            if default is MISSING:
                raise RuntimeError(t("Konfigurationseintrag fehlt: {path}", path=".".join(path)))
            raise RuntimeError(t("Konfigurationsabschnitt für {path} muss ein JSON-Objekt sein.", path=".".join(path)))
        if part not in current:
            if default is MISSING:
                raise RuntimeError(t("Konfigurationseintrag fehlt: {path}", path=".".join(path)))
            return default
        current = current[part]
    return current


def _string(data: dict[str, Any], *path: str, optional: bool = False, default: Any = MISSING) -> str | None:
    value = _lookup(data, *path, default=default)
    if optional and value is None:
        return None
    if not isinstance(value, str):
        if optional:
            raise RuntimeError(t("{path} muss eine Zeichenkette oder null sein.", path=".".join(path)))
        raise RuntimeError(t("{path} muss eine Zeichenkette sein.", path=".".join(path)))
    value = value.strip()
    if not value and not optional:
        raise RuntimeError(t("{path} darf nicht leer sein.", path=".".join(path)))
    return value or None


def _boolean(data: dict[str, Any], *path: str, default: Any = MISSING) -> bool:
    value = _lookup(data, *path, default=default)
    if not isinstance(value, bool):
        raise RuntimeError(t("{path} muss true oder false sein.", path=".".join(path)))
    return value


def _integer(data: dict[str, Any], *path: str, minimum: int, maximum: int, default: Any = MISSING) -> int:
    value = _lookup(data, *path, default=default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(t("{path} muss eine ganze Zahl sein.", path=".".join(path)))
    if not minimum <= value <= maximum:
        raise RuntimeError(t(
            "{path} muss zwischen {minimum} und {maximum} liegen.", path=".".join(path), minimum=minimum, maximum=maximum
        ))
    return value


def _path(data: dict[str, Any], *path: str, optional: bool = False, default: Any = MISSING) -> Path | None:
    value = _string(data, *path, optional=optional, default=default)
    return _resolve_path(value, base_dir=CONFIG_FILE.parent) if value else None


def _choice(data: dict[str, Any], *path: str, allowed: set[str], default: Any = MISSING) -> str:
    value = _string(data, *path, default=default)
    if value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise RuntimeError(t("{path} muss einen der folgenden Werte haben: {choices}.", path=".".join(path), choices=choices))
    return value


@dataclass(frozen=True)
class Settings:
    config_file: Path
    setup_completed: bool
    secret_key: str | None
    session_secret_key: str | None
    database_path: Path
    frontend_dir: Path
    sqlite_timeout_seconds: int
    api_max_body_bytes: int
    audit_log_limit: int
    cookie_name: str
    cookie_secure: bool
    session_max_age: int
    login_max_failures: int
    login_window_seconds: int
    login_max_tracked_keys: int
    ssh_strict_host_keys: bool
    ssh_known_hosts_file: Path | None
    ssh_allow_legacy: bool
    ssh_timeout_seconds: int
    wireless_allow_unverified_restconf_tls: bool
    wireless_restconf_ca_cert_file: Path | None
    wireless_netconf_strict_host_keys: bool
    wireless_netconf_known_hosts_file: Path | None
    wireless_netconf_allow_legacy_algorithms: bool
    wireless_connect_timeout_seconds: int
    wireless_read_timeout_seconds: int
    wireless_cache_ttl_seconds: int
    wireless_max_response_bytes: int
    switch_api_ca_cert_file: Path | None
    switch_api_allow_unverified_tls: bool
    switch_api_timeout_seconds: int
    server_host: str
    server_port: int
    server_log_level: str
    tls_enabled: bool
    tls_generate_self_signed: bool
    tls_cert_file: Path | None
    tls_key_file: Path | None
    log_directory: Path
    log_level: str
    log_max_bytes: int
    log_backup_count: int


def _load_settings(data: dict[str, Any]) -> Settings:
    return Settings(
        config_file=CONFIG_FILE,
        setup_completed=_boolean(data, "installation", "completed", default=True),
        secret_key=_string(data, "secrets", "encryption_key", optional=True),
        session_secret_key=_string(data, "secrets", "session_key", optional=True),
        database_path=_path(data, "application", "database_path"),
        frontend_dir=_path(data, "application", "frontend_dir"),
        sqlite_timeout_seconds=_integer(
            data, "application", "sqlite_timeout_seconds", minimum=1, maximum=300
        ),
        api_max_body_bytes=_integer(data, "application", "api_max_body_bytes", minimum=1_024, maximum=10_485_760),
        audit_log_limit=_integer(data, "application", "audit_log_limit", minimum=1, maximum=1_000),
        cookie_name=_string(data, "session", "cookie_name"),
        cookie_secure=_boolean(data, "session", "cookie_secure"),
        session_max_age=_integer(data, "session", "max_age_seconds", minimum=300, maximum=86_400),
        login_max_failures=_integer(data, "session", "login_max_failures", minimum=1, maximum=100),
        login_window_seconds=_integer(data, "session", "login_window_seconds", minimum=60, maximum=86_400),
        login_max_tracked_keys=_integer(
            data, "session", "login_max_tracked_keys", minimum=100, maximum=1_000_000
        ),
        ssh_strict_host_keys=_boolean(data, "ssh", "strict_host_keys"),
        ssh_known_hosts_file=_path(data, "ssh", "known_hosts_file", optional=True),
        ssh_allow_legacy=_boolean(data, "ssh", "allow_legacy_algorithms"),
        ssh_timeout_seconds=_integer(data, "ssh", "timeout_seconds", minimum=1, maximum=300),
        wireless_allow_unverified_restconf_tls=_boolean(
            data,
            "wireless",
            "allow_unverified_restconf_tls",
            default=False,
        ),
        wireless_restconf_ca_cert_file=_path(
            data, "wireless", "restconf_ca_cert_file", optional=True, default=None
        ),
        wireless_netconf_strict_host_keys=_boolean(
            data, "wireless", "netconf_strict_host_keys", default=True
        ),
        wireless_netconf_known_hosts_file=_path(
            data, "wireless", "netconf_known_hosts_file", optional=True, default=None
        ),
        wireless_netconf_allow_legacy_algorithms=_boolean(
            data,
            "wireless",
            "netconf_allow_legacy_algorithms",
            default=False,
        ),
        wireless_connect_timeout_seconds=_integer(
            data, "wireless", "connect_timeout_seconds", default=5, minimum=1, maximum=120
        ),
        wireless_read_timeout_seconds=_integer(
            data, "wireless", "read_timeout_seconds", default=30, minimum=1, maximum=300
        ),
        wireless_cache_ttl_seconds=_integer(
            data, "wireless", "cache_ttl_seconds", default=30, minimum=1, maximum=300
        ),
        wireless_max_response_bytes=_integer(
            data,
            "wireless",
            "max_response_bytes",
            default=10_485_760,
            minimum=65_536,
            maximum=104_857_600,
        ),
        switch_api_ca_cert_file=_path(data, "switch_api", "ca_cert_file", optional=True, default=None),
        switch_api_allow_unverified_tls=_boolean(data, "switch_api", "allow_unverified_tls", default=False),
        switch_api_timeout_seconds=_integer(
            data, "switch_api", "timeout_seconds", minimum=1, maximum=120, default=10
        ),
        server_host=_string(data, "server", "host"),
        server_port=_integer(data, "server", "port", minimum=1, maximum=65_535),
        server_log_level=_choice(
            data,
            "server",
            "log_level",
            allowed={"critical", "error", "warning", "info", "debug", "trace"},
        ),
        tls_enabled=_boolean(data, "server", "tls", "enabled"),
        tls_generate_self_signed=_boolean(
            data, "server", "tls", "generate_self_signed", default=False
        ),
        tls_cert_file=_path(data, "server", "tls", "cert_file", optional=True),
        tls_key_file=_path(data, "server", "tls", "key_file", optional=True),
        log_directory=_path(data, "logging", "directory", default="logs"),
        log_level=_choice(data, "logging", "level", allowed={"info", "warning", "error"}, default="info"),
        log_max_bytes=_integer(
            data, "logging", "max_bytes", minimum=1_048_576, maximum=1_073_741_824, default=10_485_760
        ),
        log_backup_count=_integer(data, "logging", "backup_count", minimum=1, maximum=100, default=10),
    )


settings = _load_settings(_read_json(CONFIG_FILE))


def reload_settings() -> Settings:
    """Lädt die im Installationsdialog gespeicherten Werte vor dem App-Import."""
    global settings
    settings = _load_settings(_read_json(CONFIG_FILE))
    return settings


def validate_file_settings(current: Settings | None = None) -> None:
    """Prüft konfigurierte Pfade, ohne optionale Dateien zu erzwingen."""
    current = current if current is not None else settings
    if not current.frontend_dir.is_dir():
        raise RuntimeError(t("application.frontend_dir ist kein lesbares Verzeichnis: {path}", path=current.frontend_dir))
    wireless_ca_file = (
        None
        if current.wireless_allow_unverified_restconf_tls
        else current.wireless_restconf_ca_cert_file
    )
    wireless_known_hosts_file = (
        current.wireless_netconf_known_hosts_file
        if current.wireless_netconf_strict_host_keys
        else None
    )
    switch_api_ca_file = None if current.switch_api_allow_unverified_tls else current.switch_api_ca_cert_file
    for name, path in (
        ("ssh.known_hosts_file", current.ssh_known_hosts_file),
        ("wireless.restconf_ca_cert_file", wireless_ca_file),
        ("wireless.netconf_known_hosts_file", wireless_known_hosts_file),
        ("switch_api.ca_cert_file", switch_api_ca_file),
    ):
        if path and not path.is_file():
            raise RuntimeError(t("{name} verweist auf keine lesbare Datei: {path}", name=name, path=path))


def validate_server_settings(current: Settings | None = None) -> None:
    current = current if current is not None else settings
    if not current.tls_enabled:
        return
    if not current.tls_cert_file or not current.tls_key_file:
        raise RuntimeError(t("Bei server.tls.enabled=true müssen cert_file und key_file gesetzt sein."))
    for name, path in (
        ("server.tls.cert_file", current.tls_cert_file),
        ("server.tls.key_file", current.tls_key_file),
    ):
        if not path.is_file():
            raise RuntimeError(t("{name} verweist auf keine lesbare Datei: {path}", name=name, path=path))
