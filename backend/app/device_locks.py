"""Per-device write locks: one change at a time per device, across threads and server processes.

A thread lock serializes requests within the process; an OS file lock (released on crash)
serializes backend processes sharing the database directory.
"""

import os
import threading
import weakref
from collections.abc import Callable
from contextlib import contextmanager

from . import config

_GUARD = threading.Lock()
_LOCKS: "weakref.WeakValueDictionary[tuple[str, int], threading.Lock]" = weakref.WeakValueDictionary()


def _lock_file(handle, lock: bool) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK if lock else msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), (fcntl.LOCK_EX | fcntl.LOCK_NB) if lock else fcntl.LOCK_UN)


@contextmanager
def write_lock(
    namespace: str,
    device_id: int,
    busy_message: str,
    other_process_message: str,
    error: Callable[[str], Exception] = RuntimeError,
):
    """Hold the write lock of one device; ``error(message)`` is raised when it is taken.

    ``busy_message``: another request of this process holds the lock;
    ``other_process_message``: another server process holds it. Lock files live in
    ``.{namespace}-locks`` next to the database.
    """
    with _GUARD:
        lock = _LOCKS.get((namespace, device_id))
        if lock is None:
            lock = threading.Lock()
            _LOCKS[(namespace, device_id)] = lock
    if not lock.acquire(blocking=False):
        raise error(busy_message)
    handle = None
    acquired = False
    try:
        folder = config.settings.database_path.resolve().parent / f".{namespace}-locks"
        folder.mkdir(parents=True, exist_ok=True)
        handle = (folder / f"{int(device_id)}.lock").open("a+b")
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        try:
            _lock_file(handle, True)
        except OSError:
            raise error(other_process_message) from None
        acquired = True
        yield
    finally:
        if handle is not None:
            try:
                if acquired:
                    _lock_file(handle, False)
            finally:
                handle.close()
        lock.release()
