"""Built-in read-only SFTP server through which AOS-CX, AOS-S and Netgear download transfer tickets.

Login: user ``t{token_id}``, password = ticket secret (``transfer``); the session then sees
exactly one file, ``/{filename}`` of its ticket, readable only. Opening it counts one use of
the ticket and is audited (``transfer-download``). Everything else is refused
(``SFTP_PERMISSION_DENIED``); there is no shell, exec or port forwarding.

Limits: 8 concurrent connections, 30 s to authenticate, 3 password attempts, 300 s idle.
The RSA 3072 host key lives next to the database (``sftp_host_rsa.key``, mode 0600) and is
created on first start; its SHA-256 fingerprint is shown in the administration.
"""

import base64
import hashlib
import io
import logging
import os
import posixpath
import socket
import threading
import time
from pathlib import Path

import paramiko

from . import config, transfer

logger = logging.getLogger("switchsteward.sftp")

MAX_CONNECTIONS = 8
AUTH_TIMEOUT_SECONDS = 30
IDLE_TIMEOUT_SECONDS = 300
MAX_PASSWORD_ATTEMPTS = 3
HOST_KEY_BITS = 3072
HOST_KEY_FILE = "sftp_host_rsa.key"
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

_lock = threading.Lock()
_state: dict = {"listener": None}


def host_key_path() -> Path:
    return config.settings.database_path.parent / HOST_KEY_FILE


def _load_host_key() -> paramiko.RSAKey:
    path = host_key_path()
    if path.exists():
        return paramiko.RSAKey(filename=str(path))
    key = paramiko.RSAKey.generate(HOST_KEY_BITS)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        key.write_private_key(handle)
    logger.info("SFTP host key created: %s", path)
    return key


def fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class _Server(paramiko.ServerInterface):
    """Authentication with a transfer ticket; only session channels with the sftp subsystem."""

    def __init__(self):
        self.ticket: tuple[str, str, str] | None = None
        self.failures = 0
        self.last_activity = time.monotonic()
        self.client_ip: str | None = None
        self._payload_size: int | None = None

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        if self.ticket is not None or self.failures >= MAX_PASSWORD_ATTEMPTS:
            return paramiko.AUTH_FAILED
        match = transfer.SFTP_USER_RE.fullmatch(username or "")
        filename = transfer.ticket_filename(match.group(1), password) if match else None
        if filename is None:
            self.failures += 1
            logger.warning("SFTP login refused for %r from %s", username, self.client_ip)
            return paramiko.AUTH_FAILED
        self.ticket = (match.group(1), password, filename)
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == "session" and self.ticket is not None:
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name):
        if name != "sftp":
            return False
        return super().check_channel_subsystem_request(channel, name)

    def touch(self) -> None:
        self.last_activity = time.monotonic()


class _Handle(paramiko.SFTPHandle):
    def __init__(self, server: _Server, readfile, size: int):
        super().__init__(os.O_RDONLY)
        self.readfile = readfile
        self._server = server
        self._size = size

    def read(self, offset, length):
        self._server.touch()
        return super().read(offset, length)

    def stat(self):
        return _file_attributes(self._server.ticket[2], self._size)

    def write(self, offset, data):
        return paramiko.SFTP_PERMISSION_DENIED

    def chattr(self, attr):
        return paramiko.SFTP_PERMISSION_DENIED


def _file_attributes(filename: str, size: int) -> paramiko.SFTPAttributes:
    attributes = paramiko.SFTPAttributes()
    attributes.filename = filename
    attributes.st_size = size
    attributes.st_mode = 0o100400
    attributes.st_uid = attributes.st_gid = 0
    attributes.st_mtime = attributes.st_atime = int(time.time())
    return attributes


def _directory_attributes() -> paramiko.SFTPAttributes:
    attributes = paramiko.SFTPAttributes()
    attributes.st_size = 0
    attributes.st_mode = 0o040500
    attributes.st_uid = attributes.st_gid = 0
    attributes.st_mtime = attributes.st_atime = int(time.time())
    return attributes


class _Files(paramiko.SFTPServerInterface):
    """The ticket's single file, read-only."""

    def __init__(self, server: _Server, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self._server = server

    @property
    def _filename(self) -> str:
        return self._server.ticket[2]

    def _size(self) -> int:
        if self._server._payload_size is None:
            token_id, secret, filename = self._server.ticket
            grant = transfer.redeem(token_id, secret, filename, consume=False)
            if grant is None:
                raise PermissionError("ticket expired")
            payload = transfer.open_payload(grant.kind, grant.ref_id)
            self._server._payload_size = len(payload) if isinstance(payload, bytes) else payload.stat().st_size
        return self._server._payload_size

    def canonicalize(self, path):
        return posixpath.normpath("/" + (path or "").lstrip("/")) if path not in ("", ".") else "/"

    def _attributes(self, path):
        self._server.touch()
        path = self.canonicalize(path)
        if path == "/":
            return _directory_attributes()
        if path != f"/{self._filename}":
            return paramiko.SFTP_NO_SUCH_FILE
        try:
            return _file_attributes(self._filename, self._size())
        except (PermissionError, LookupError, ValueError, OSError):
            return paramiko.SFTP_NO_SUCH_FILE

    def stat(self, path):
        return self._attributes(path)

    def lstat(self, path):
        return self._attributes(path)

    def list_folder(self, path):
        self._server.touch()
        if self.canonicalize(path) != "/":
            return paramiko.SFTP_NO_SUCH_FILE
        attributes = self._attributes(f"/{self._filename}")
        return [attributes] if isinstance(attributes, paramiko.SFTPAttributes) else []

    def open(self, path, flags, attr):
        self._server.touch()
        if flags & _WRITE_FLAGS:
            return paramiko.SFTP_PERMISSION_DENIED
        if self.canonicalize(path) != f"/{self._filename}":
            return paramiko.SFTP_NO_SUCH_FILE
        token_id, secret, filename = self._server.ticket
        grant = transfer.redeem(token_id, secret, filename)
        if grant is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            payload = transfer.open_payload(grant.kind, grant.ref_id)
            if isinstance(payload, bytes):
                readfile, size = io.BytesIO(payload), len(payload)
            else:
                readfile, size = open(payload, "rb"), payload.stat().st_size  # noqa: SIM115
        except (LookupError, ValueError, OSError) as exc:
            logger.error("SFTP payload %s %s unavailable: %s", grant.kind, grant.ref_id, exc)
            transfer.audit_download(grant, "sftp", self._server.client_ip, status="error")
            return paramiko.SFTP_FAILURE
        transfer.audit_download(grant, "sftp", self._server.client_ip)
        return _Handle(self._server, readfile, size)

    def remove(self, path):
        return paramiko.SFTP_PERMISSION_DENIED

    def rename(self, oldpath, newpath):
        return paramiko.SFTP_PERMISSION_DENIED

    def posix_rename(self, oldpath, newpath):
        return paramiko.SFTP_PERMISSION_DENIED

    def mkdir(self, path, attr):
        return paramiko.SFTP_PERMISSION_DENIED

    def rmdir(self, path):
        return paramiko.SFTP_PERMISSION_DENIED

    def chattr(self, path, attr):
        return paramiko.SFTP_PERMISSION_DENIED

    def symlink(self, target_path, path):
        return paramiko.SFTP_PERMISSION_DENIED

    def readlink(self, path):
        return paramiko.SFTP_PERMISSION_DENIED


class _Listener:
    def __init__(self, bind: str, port: int, key: paramiko.RSAKey):
        self.key = key
        self.fingerprint = fingerprint(key)
        self.stop_event = threading.Event()
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((bind, port))
            self.sock.listen(16)
        except OSError:
            self.sock.close()
            raise
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._accept_loop, name="sftp-listener", daemon=True)
        self.thread.start()

    def _accept_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                client, address = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self.stop_event.is_set():
                    logger.exception("SFTP listener failed")
                return
            if not self.slots.acquire(blocking=False):
                logger.warning("SFTP connection from %s refused: too many connections", address[0])
                client.close()
                continue
            threading.Thread(
                target=self._serve, args=(client, address[0]), name="sftp-connection", daemon=True,
            ).start()

    def _serve(self, client: socket.socket, client_ip: str) -> None:
        transport = None
        try:
            client.settimeout(None)
            transport = paramiko.Transport(client)
            transport.add_server_key(self.key)
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, _Files)
            transport.handshake_timeout = AUTH_TIMEOUT_SECONDS
            transport.banner_timeout = AUTH_TIMEOUT_SECONDS
            server = _Server()
            server.client_ip = client_ip
            transport.start_server(server=server)
            deadline = time.monotonic() + AUTH_TIMEOUT_SECONDS
            while (
                transport.is_active() and not transport.is_authenticated() and not self.stop_event.is_set()
                and server.failures < MAX_PASSWORD_ATTEMPTS and time.monotonic() < deadline
            ):
                time.sleep(0.1)
            if not transport.is_authenticated():
                return
            server.touch()
            while transport.is_active() and not self.stop_event.is_set():
                if time.monotonic() - server.last_activity > IDLE_TIMEOUT_SECONDS:
                    logger.info("SFTP connection from %s closed after idle timeout", client_ip)
                    break
                time.sleep(0.2)
        except (paramiko.SSHException, OSError, EOFError) as exc:
            logger.info("SFTP connection from %s ended: %s", client_ip, exc)
        finally:
            if transport is not None:
                transport.close()
            client.close()
            self.slots.release()

    def close(self) -> None:
        self.stop_event.set()
        self.sock.close()
        self.thread.join(timeout=5)


def start(settings) -> None:
    """Start listening on ``settings.sftp_bind:sftp_port`` (``OSError`` when the bind fails)."""
    with _lock:
        if _state["listener"] is not None:
            return
        listener = _Listener(settings.sftp_bind, settings.sftp_port, _load_host_key())
        _state["listener"] = listener
    logger.info("SFTP transfer server listening on %s:%s", settings.sftp_bind, listener.port)


def stop() -> None:
    with _lock:
        listener, _state["listener"] = _state["listener"], None
    if listener is not None:
        listener.close()
        logger.info("SFTP transfer server stopped")


def restart(settings) -> None:
    """Apply new settings: stop, then start if ``sftp_enabled`` (``OSError`` when the bind fails)."""
    stop()
    if settings.sftp_enabled:
        start(settings)


def status() -> dict:
    """``{"running", "fingerprint", "port"}``; the fingerprint is shown once a host key exists."""
    listener = _state["listener"]
    if listener is not None:
        return {"running": True, "fingerprint": listener.fingerprint, "port": listener.port}
    path = host_key_path()
    key_fingerprint = None
    if path.exists():
        try:
            key_fingerprint = fingerprint(paramiko.RSAKey(filename=str(path)))
        except (paramiko.SSHException, OSError):
            key_fingerprint = None
    return {"running": False, "fingerprint": key_fingerprint, "port": None}
