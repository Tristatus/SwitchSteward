"""Share overlapping switch reads without caching completed device snapshots."""

import copy
import hashlib
import inspect
import threading
from concurrent.futures import Future
from dataclasses import dataclass
from functools import wraps

from .. import i18n


def _freeze(value):
    if isinstance(value, dict):
        return tuple((key, _freeze(item)) for key, item in sorted(value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass
class _PendingRead:
    future: Future
    shared: bool = False


class _ReadCoordinator:
    def __init__(self):
        self._lock = threading.Lock()
        self._generation = 0
        self._pending = {}

    def invalidate(self):
        # Old readers may finish, but readers starting after a write begins or
        # ends must not join them. The integer needs no per-device retention.
        with self._lock:
            self._generation += 1

    def run(self, operation, arguments, read):
        # Include endpoint, metadata (incl. device_type), credentials, read options
        # and the request language: waiting callers must not receive warnings in
        # another caller's language. Store only a fingerprint, never a password.
        fingerprint = hashlib.sha256(
            repr((_freeze(arguments), i18n.current_language.get())).encode("utf-8")
        ).digest()
        with self._lock:
            key = (operation, fingerprint, self._generation)
            pending = self._pending.get(key)
            owner = pending is None
            if owner:
                pending = _PendingRead(Future())
                self._pending[key] = pending
            else:
                pending.shared = True

        if not owner:
            # Consumers enrich snapshots in place. Every caller owns its copy.
            return copy.deepcopy(pending.future.result())

        try:
            result = read()
            with self._lock:
                self._pending.pop(key, None)
                shared = pending.shared
            if shared:
                # No caller may mutate the shared original. Avoid this extra
                # copy entirely for the usual case of a single request.
                pending.future.set_result(result)
                return copy.deepcopy(result)
            return result
        except BaseException as exc:
            if not pending.future.done():
                pending.future.set_exception(exc)
            raise
        finally:
            with self._lock:
                if self._pending.get(key) is pending:
                    del self._pending[key]


_COORDINATOR = _ReadCoordinator()


def coalesced_read(function):
    signature = inspect.signature(function)

    @wraps(function)
    def wrapped(*args, **kwargs):
        arguments = signature.bind(*args, **kwargs)
        arguments.apply_defaults()
        return _COORDINATOR.run(
            function.__qualname__, arguments.arguments, lambda: function(*args, **kwargs),
        )

    return wrapped


def invalidates_reads(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        _COORDINATOR.invalidate()
        try:
            return function(*args, **kwargs)
        finally:
            # A failed command or interrupted connection can still have changed
            # part of the device configuration; invalidate every outcome.
            _COORDINATOR.invalidate()

    return wrapped
