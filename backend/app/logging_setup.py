"""System and audit log files, console output, request ids and secret redaction."""

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import request_context

AUDIT_LOGGER_NAME = "switchsteward.audit"
SYSTEM_LOG_FILE = "system.log"
AUDIT_LOG_FILE = "audit.log"
_FORMAT = "%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
_MARKER = "_switchsteward_logging"
_LEVELS = {
    "critical": logging.CRITICAL,
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
    "trace": 5,  # uvicorn's TRACE level
}
_QUIET_LIBRARIES = ("paramiko", "netmiko", "httpx", "httpcore", "ldap3")
# Secrets, tokens, auth codes and cookies must never reach a log file.
_SECRET_VALUE = re.compile(
    r"(?i)(\b[\w-]*(?:password|passwd|secret|token|authorization|cookie)|\bcode)"
    r"(\s*[=:]\s*)(\"?)((?:bearer\s+|basic\s+)?[^\s,;&\"']+)"
)


def redact(text: str) -> str:
    return _SECRET_VALUE.sub(lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}***", text)


class RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = request_context.current_request_id() or "-"
        return True


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = redact(message)
        if redacted != message:
            record.msg, record.args = redacted, None
        return True


def _handler(handler: logging.Handler, level: int, formatter: logging.Formatter) -> logging.Handler:
    handler.setLevel(level)
    handler.setFormatter(formatter)
    handler.addFilter(RequestContextFilter())
    handler.addFilter(RedactionFilter())
    return handler


def _rotating(path: Path, settings) -> RotatingFileHandler:
    return RotatingFileHandler(
        path, maxBytes=settings.log_max_bytes, backupCount=settings.log_backup_count, encoding="utf-8",
    )


def configure_logging(settings) -> None:
    """Install file and console handlers once per distinct logging configuration."""
    key = (
        str(settings.log_directory), settings.log_level, settings.log_max_bytes,
        settings.log_backup_count, settings.server_log_level,
    )
    root = logging.getLogger()
    previous = getattr(root, _MARKER, None)
    if previous is not None and previous["key"] == key:
        return

    directory = Path(settings.log_directory)
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        system_file = _rotating(directory / SYSTEM_LOG_FILE, settings)
        audit_file = _rotating(directory / AUDIT_LOG_FILE, settings)
    except OSError as exc:
        raise RuntimeError(f"Log-Verzeichnis {directory} ist nicht beschreibbar.") from exc

    audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
    if previous is not None:
        for handler in previous["root_handlers"]:
            root.removeHandler(handler)
            handler.close()
        audit_logger.removeHandler(previous["audit_handler"])
        previous["audit_handler"].close()

    formatter = logging.Formatter(_FORMAT, datefmt=_DATE_FORMAT)
    file_level = _LEVELS[settings.log_level]
    console_level = _LEVELS[settings.server_log_level]
    root_handlers = [
        _handler(system_file, file_level, formatter),
        _handler(logging.StreamHandler(), console_level, formatter),
    ]
    for handler in root_handlers:
        root.addHandler(handler)
    root.setLevel(min(file_level, console_level))

    # The audit file is independent of logging.level: every audit record is kept.
    audit_handler = _handler(audit_file, logging.INFO, logging.Formatter("%(message)s"))
    audit_logger.addHandler(audit_handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False

    for name in _QUIET_LIBRARIES:
        logging.getLogger(name).setLevel(logging.WARNING)
    # Request lines come from switchsteward.http (without query strings).
    logging.getLogger("uvicorn.access").disabled = True
    for name in ("uvicorn", "uvicorn.error"):
        # Let uvicorn records reach the root handlers instead of uvicorn's own config.
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True
    setattr(root, _MARKER, {"key": key, "root_handlers": root_handlers, "audit_handler": audit_handler})
