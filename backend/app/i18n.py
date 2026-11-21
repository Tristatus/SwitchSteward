"""Request language and message translation.

German texts are the message IDs; ``app.i18n_en.MESSAGES`` maps them to English.
"""

from collections.abc import Mapping
from contextvars import ContextVar

from .i18n_en import MESSAGES

SUPPORTED_LANGUAGES = ("de", "en")
DEFAULT_LANGUAGE = "de"

current_language: ContextVar[str] = ContextVar("current_language", default=DEFAULT_LANGUAGE)


def t(msgid: str, **params) -> str:
    template = MESSAGES.get(msgid, msgid) if current_language.get() == "en" else msgid
    return template.format(**params) if params else template


def _supported(value: str | None) -> str | None:
    tag = (value or "").strip().lower()
    primary = tag.split("-", 1)[0].split("_", 1)[0]
    return primary if primary in SUPPORTED_LANGUAGES else None


def language_from_headers(headers: Mapping[str, str]) -> str:
    """Return the UI language: X-UI-Language, then the first Accept-Language tag, else German."""
    explicit = _supported(headers.get("x-ui-language"))
    if explicit:
        return explicit
    accept = headers.get("accept-language") or ""
    first_tag = accept.split(",", 1)[0].split(";", 1)[0]
    return _supported(first_tag) or DEFAULT_LANGUAGE


class LanguageMiddleware:
    """Pure ASGI middleware that sets ``current_language`` for each HTTP request."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers") or []
        }
        token = current_language.set(language_from_headers(headers))
        try:
            await self.app(scope, receive, send)
        finally:
            current_language.reset(token)
