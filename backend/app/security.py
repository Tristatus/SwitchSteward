"""ASGI request limits and security headers, including rejected requests."""

import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import auth, firmware, updates
from .i18n import t

# Login has no session yet; every other mutating API request needs the session's CSRF token.
CSRF_EXEMPT_PATHS = frozenset({"/api/login"})
_BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    # style-src keeps 'unsafe-inline' for existing style= attributes; scripts are external only.
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    ),
}
# Every header this middleware may set; responses never carry a second, app-supplied copy.
_MANAGED_HEADER_NAMES = frozenset(
    name.lower().encode("ascii") for name in (*_BASE_HEADERS, "Cache-Control", "Strict-Transport-Security")
)


@dataclass(frozen=True)
class UploadRoute:
    """Admin-only POST route whose raw body is streamed to a temporary file instead of memory.

    ``too_large``: translated rejection text. ``temp_dir``: parent of the request's temporary
    directory (None = system default); may raise ``HTTPException`` when it is not usable.
    The route reads the file path from ``scope["switchsteward.upload_path"]``.
    """

    max_bytes: int
    too_large: Callable[[], str]
    temp_dir: Callable[[], Path | None] = lambda: None


def _firmware_incoming() -> Path:
    # Same file system as the firmware directory, so the route can move the file with os.replace.
    try:
        return firmware.incoming_dir()
    except firmware.FirmwareError as exc:
        raise HTTPException(exc.status_code, str(exc)) from None


UPLOAD_ROUTES: Mapping[str, UploadRoute] = {
    "/api/system/updates": UploadRoute(updates.MAX_UPLOAD_BYTES, lambda: t("Update-Archiv ist zu groß.")),
    "/api/firmware/images": UploadRoute(
        firmware.MAX_UPLOAD_BYTES, lambda: t("Firmware-Image ist zu groß."), _firmware_incoming,
    ),
}


class SecurityMiddleware:
    def __init__(self, app, max_body_bytes: int, upload_routes: Mapping[str, UploadRoute] = UPLOAD_ROUTES):
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.upload_routes = upload_routes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        is_api = scope["path"].startswith("/api/")
        upload = self.upload_routes.get(scope["path"]) if request.method == "POST" else None
        is_upload = upload is not None
        body_limit = upload.max_bytes if is_upload else self.max_body_bytes
        headers = dict(_BASE_HEADERS)
        # Transfer downloads carry a one-time ticket in the URL; never cache them either.
        if is_api or scope["path"].startswith("/transfer/"):
            headers["Cache-Control"] = "no-store"
        if scope["scheme"] == "https":
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        async def secure_send(message):
            if message["type"] == "http.response.start":
                existing = [
                    (name, value) for name, value in message.get("headers", [])
                    if name.lower() not in _MANAGED_HEADER_NAMES
                ]
                message = {
                    **message,
                    "headers": existing + [(name.lower().encode("ascii"), value.encode("ascii"))
                                           for name, value in headers.items()],
                }
            await send(message)

        async def reject(status_code, detail, extra_headers=None):
            response = JSONResponse(status_code=status_code, content={"detail": detail}, headers=extra_headers)
            await response(scope, receive, secure_send)

        if is_api:
            lengths = request.headers.getlist("content-length")
            if lengths:
                if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
                    await reject(400, t("Ungültiger Content-Length-Header."))
                    return
                # Avoid integer conversion of arbitrarily long attacker-controlled values.
                length = lengths[0].lstrip("0") or "0"
                if len(length) > len(str(body_limit)) or int(length) > body_limit:
                    await reject(413, t("Anfrage ist zu groß."))
                    return

            if request.method in {"POST", "PUT", "PATCH", "DELETE"} and scope["path"] not in CSRF_EXEMPT_PATHS:
                try:
                    # Sessions live in SQLite: keep the lookup off the event loop.
                    principal = await run_in_threadpool(auth.require_csrf, request)
                    if is_upload:
                        auth.require_admin(principal)
                except HTTPException as exc:
                    await reject(exc.status_code, exc.detail, exc.headers)
                    return

            if is_upload:
                # Authenticate before accepting upload bytes; keep large uploads on disk.
                # The generated path lives only for this request and never uses the filename header.
                try:
                    parent = await run_in_threadpool(upload.temp_dir)
                except HTTPException as exc:
                    await reject(exc.status_code, exc.detail)
                    return
                with tempfile.TemporaryDirectory(prefix="switchsteward-upload-", dir=parent) as temporary:
                    upload_path = Path(temporary) / "upload"
                    total = 0
                    with upload_path.open("wb") as upload_file:
                        while True:
                            message = await receive()
                            if message["type"] == "http.disconnect":
                                return
                            chunk = message.get("body", b"")
                            total += len(chunk)
                            if total > body_limit:
                                await reject(413, upload.too_large())
                                return
                            upload_file.write(chunk)
                            if not message.get("more_body", False):
                                break
                    scope["switchsteward.upload_path"] = upload_path

                    async def upload_receive():
                        return {"type": "http.request", "body": b"", "more_body": False}

                    await self.app(scope, upload_receive, secure_send)
                return

            # Content-Length is optional for chunked requests and cannot enforce a limit.
            # Buffer only up to the limit, before JSON decoding or handler side effects.
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                if len(body) + len(chunk) > self.max_body_bytes:
                    await reject(413, t("Anfrage ist zu groß."))
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
        else:
            await self.app(scope, receive, secure_send)
