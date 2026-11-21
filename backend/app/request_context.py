"""Per-request context shared by middleware, routes, audit and logging."""

import logging
import time
from contextvars import ContextVar
from uuid import uuid4

logger = logging.getLogger("switchsteward.http")

# The dict is shared by reference: threadpool routes and the middleware see the same state.
request_context: ContextVar[dict | None] = ContextVar("switchsteward_request_context", default=None)

_UNLOGGED_PATHS = frozenset({"/favicon.svg", "/favicon.ico", "/apple-touch-icon.png"})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def current() -> dict | None:
    return request_context.get()


def current_request_id() -> str | None:
    context = request_context.get()
    return context["request_id"] if context else None


def set_principal(username: str, auth_provider: str | None) -> None:
    context = request_context.get()
    if context is not None:
        context["username"] = username
        context["auth_provider"] = auth_provider


def is_mutating(method: str) -> bool:
    return method.upper() in _MUTATING_METHODS


def _logged(path: str) -> bool:
    return not path.startswith("/static/") and path not in _UNLOGGED_PATHS


class RequestContextMiddleware:
    """Outermost middleware: request id, X-Request-ID header and one log line per request."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        context = {
            "request_id": uuid4().hex[:12],
            "client_ip": client[0] if client else "unknown",
            "username": None,
            "auth_provider": None,
            "audited": False,
        }
        request_context.set(context)
        status_code = 500
        started = time.perf_counter()

        async def send_with_request_id(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                message = {
                    **message,
                    "headers": [*message.get("headers", []), (b"x-request-id", context["request_id"].encode("ascii"))],
                }
            await send(message)

        # The context is deliberately not reset: the generic 500 handler runs in the
        # outer ServerErrorMiddleware of the same task and needs the request id.
        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            path = scope.get("path", "")
            if _logged(path):
                # The path is logged without query string: it may carry codes or search terms.
                logger.info(
                    "%s %s %s %dms user=%s ip=%s",
                    scope.get("method", "-"), path, status_code,
                    round((time.perf_counter() - started) * 1000),
                    context["username"] or "-", context["client_ip"],
                )
