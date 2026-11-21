"""Audit trail: database rows for the GUI plus JSON lines in audit.log.

Every mutating route is marked with ``audit_action``; routes record their outcome with
``record``. ``AuditFallbackMiddleware`` records failed mutating requests that did not
record anything themselves (validation errors, conflicts, denied access).
"""

import json
import logging
import sqlite3
from collections.abc import Callable
from datetime import datetime, timezone

from starlette.concurrency import run_in_threadpool

from . import database as db
from . import request_context
from .logging_setup import AUDIT_LOGGER_NAME

logger = logging.getLogger("switchsteward.auditing")
_audit_file = logging.getLogger(AUDIT_LOGGER_NAME)


def record(
    action: str,
    *,
    target: str | None = None,
    interface: str | None = None,
    detail: str = "",
    status: str = "ok",
    username: str | None = None,
    auth_provider: str | None = None,
    connection: sqlite3.Connection | None = None,
) -> None:
    """Write one audit record; ``connection`` targets a database outside the configured one."""
    context = request_context.current() or {}
    username = username or context.get("username")
    auth_provider = auth_provider or context.get("auth_provider")
    client_ip = context.get("client_ip")
    request_id = context.get("request_id")
    try:
        if connection is None:
            db.add_audit(
                username, target, interface, action, detail, status,
                auth_provider=auth_provider, client_ip=client_ip, request_id=request_id,
            )
        else:
            db.insert_audit(
                connection, username, target, interface, action, detail, status,
                auth_provider=auth_provider, client_ip=client_ip, request_id=request_id,
            )
    except Exception:
        logger.error("Audit record %s could not be stored", action)
        raise
    # Logging handlers report write errors themselves; a full disk never aborts the request.
    _audit_file.info(json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "username": username,
        "auth_provider": auth_provider,
        "client_ip": client_ip,
        "target": target,
        "interface": interface,
        "action": action,
        "detail": detail,
        "status": status,
        "request_id": request_id,
    }, ensure_ascii=False))
    if context:
        context["audited"] = True


def audited_write(
    action: str,
    *,
    target: str | None,
    interface: str | None = None,
    detail: str | None = None,
    operation: Callable[[], dict],
) -> dict:
    """Run a device write and audit its outcome.

    ``operation`` returns a WriteResult (``ok``, ``message``); the audit detail is
    ``detail`` or, without one, the result message. Exceptions are audited as
    errors and re-raised.
    """
    try:
        result = operation()
    except Exception:
        record(action, target=target, interface=interface,
               detail=f"{detail} -> FEHLER" if detail else "FEHLER", status="error")
        raise
    record(action, target=target, interface=interface, detail=detail or result["message"],
           status="ok" if result["ok"] else "error")
    return result


def audit_action(name: str):
    """Mark a route endpoint with its audit action name (checked by the route-walk test)."""

    def decorate(endpoint):
        endpoint.__audit_action__ = name
        return endpoint

    return decorate


class AuditFallbackMiddleware:
    """Audit failed mutating API requests whose route did not write an audit record."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        method = scope.get("method", "")
        if (
            scope["type"] != "http"
            or not request_context.is_mutating(method)
            or not scope.get("path", "").startswith("/api/")
        ):
            await self.app(scope, receive, send)
            return
        status_code = 500

        async def capture_status(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, capture_status)
        except Exception:
            status_code = 500
            await self._fallback(scope, status_code)
            raise
        await self._fallback(scope, status_code)

    async def _fallback(self, scope, status_code: int) -> None:
        context = request_context.current()
        if status_code < 400 or context is None or context["audited"]:
            return
        if status_code == 401:
            logger.warning("Rejected unauthenticated %s %s", scope.get("method"), scope.get("path"))
            return
        name = getattr(scope.get("endpoint"), "__audit_action__", "request")
        if status_code == 403:
            action, detail = "access-denied", f"route_action={name} http_status=403"
        else:
            action, detail = name, f"http_status={status_code}"
        try:
            await run_in_threadpool(record, action, status="error", detail=detail)
        except Exception:
            # The original response (or exception) wins; record() already logged the failure.
            return
