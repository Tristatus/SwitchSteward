"""In-memory login throttling per (client IP, provider, normalized username)."""

import logging
import time
from collections import OrderedDict, deque
from threading import Lock

from fastapi import HTTPException, status

from .. import config
from ..i18n import t
from . import settings

logger = logging.getLogger("switchsteward.auth")

_MAX_LOGIN_FAILURES = config.settings.login_max_failures
_LOGIN_FAILURE_WINDOW = config.settings.login_window_seconds
_MAX_TRACKED_LOGIN_KEYS = config.settings.login_max_tracked_keys
_login_failures: OrderedDict[tuple[str, str, str], deque[float]] = OrderedDict()
_login_lock = Lock()


def _login_key(client_ip: str, provider: str, username: str) -> tuple[str, str, str]:
    normalized = username.strip().casefold()
    if provider == "ad" and "@" not in normalized:
        # "alice" and "alice@<AD domain>" are the same AD account and share one budget.
        normalized = f"{normalized}@{settings.load_ad().domain.casefold()}"
    return client_ip, provider, normalized


def _prune_login_failures(now: float) -> None:
    cutoff = now - _LOGIN_FAILURE_WINDOW
    for key, attempts in list(_login_failures.items()):
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        if not attempts:
            _login_failures.pop(key, None)


def reserve_login_attempt(client_ip: str, provider: str, username: str) -> float:
    """Count in-flight attempts atomically, so parallel requests cannot bypass the limit."""
    now = time.monotonic()
    key = _login_key(client_ip, provider, username)
    with _login_lock:
        _prune_login_failures(now)
        if len(_login_failures.get(key, ())) >= _MAX_LOGIN_FAILURES:
            logger.warning("Throttled %s login attempt for %s from %s", provider, key[2], client_ip)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=t("Zu viele fehlgeschlagene Anmeldungen. Bitte später erneut versuchen."),
            )
        if key not in _login_failures and len(_login_failures) >= _MAX_TRACKED_LOGIN_KEYS:
            _login_failures.popitem(last=False)
        _login_failures.setdefault(key, deque(maxlen=_MAX_LOGIN_FAILURES)).append(now)
        _login_failures.move_to_end(key)
    return now


def discard_login_attempt(client_ip: str, provider: str, username: str, attempt: float) -> None:
    """An infrastructure failure must not consume a user's password retry budget."""
    key = _login_key(client_ip, provider, username)
    with _login_lock:
        attempts = _login_failures.get(key)
        if attempts and attempt in attempts:
            attempts.remove(attempt)
            if not attempts:
                _login_failures.pop(key, None)


def clear_login_failures(client_ip: str, provider: str, username: str) -> None:
    with _login_lock:
        _login_failures.pop(_login_key(client_ip, provider, username), None)
