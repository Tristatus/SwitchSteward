"""Device connections: SSH via Netmiko and HTTPS via httpx.

Settings are read from ``config.settings`` at call time. Every connection is
logged with its duration in system.log.
"""

import logging
import re
import ssl
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

import httpx
import paramiko
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout

from .. import config, crypto
from ..i18n import t
from .errors import SwitchConnectionError

logger = logging.getLogger("switchsteward.switches.transport")

SSH_ERRORS = (NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout, paramiko.SSHException, EOFError,
              OSError)
SSH_TIMEOUT_ERRORS = (NetmikoTimeoutException, ReadTimeout)
SAVE_CONFIG_MIN_TIMEOUT_SECONDS = 100
HTTPS_MAX_RESPONSE_BYTES = 10 * 1024 * 1024

# Some older Cisco IOS releases only offer outdated key exchange and host key
# algorithms that current Paramiko versions disable. Only enabled on request
# (ssh.allow_legacy_algorithms) for trusted internal networks.
_LEGACY_KEX = ("diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1")
_PROMPT_ATTRIBUTE = "_switchsteward_read_prompt"


def apply_legacy_ssh_policy() -> None:
    """Add legacy algorithms to Paramiko's preferences when configured; call once at startup."""
    if not config.settings.ssh_allow_legacy:
        return
    for kex in _LEGACY_KEX:
        if kex not in paramiko.Transport._preferred_kex:
            paramiko.Transport._preferred_kex = paramiko.Transport._preferred_kex + (kex,)
    if "ssh-rsa" not in paramiko.Transport._preferred_keys:
        paramiko.Transport._preferred_keys = paramiko.Transport._preferred_keys + ("ssh-rsa",)


def validate_ssh_configuration() -> None:
    settings = config.settings
    if settings.ssh_known_hosts_file and not settings.ssh_known_hosts_file.is_file():
        raise RuntimeError("ssh.known_hosts_file verweist auf keine lesbare Datei.")
    if settings.ssh_allow_legacy:
        logger.warning("Legacy-SSH-Algorithmen sind explizit aktiviert.")
    if not settings.ssh_strict_host_keys:
        logger.warning("SSH-Host-Key-Prüfung ist explizit deaktiviert.")


def raise_connection_error(switch: dict, exc: Exception) -> NoReturn:
    logger.error("Device operation failed for switch id=%s (%s)", switch.get("id"), type(exc).__name__)
    raise SwitchConnectionError(t("SSH-Kommunikation fehlgeschlagen. Server-Log prüfen.")) from None


def netmiko_params(switch: dict, credentials: dict, netmiko_device_type: str) -> dict:
    settings = config.settings
    params = {
        "device_type": netmiko_device_type,
        "host": switch["ip"],
        "port": switch["port"],
        "username": credentials["username"],
        "password": crypto.decrypt(credentials["password_enc"]),
        "secret": crypto.decrypt(credentials["enable_secret_enc"]) if credentials.get("enable_secret_enc") else "",
        "timeout": settings.ssh_timeout_seconds,
        # send_command otherwise uses its own ten-second default; large status and
        # VLAN tables need the configured SSH timeout.
        "read_timeout_override": settings.ssh_timeout_seconds,
        "fast_cli": False,
        "ssh_strict": settings.ssh_strict_host_keys,
        "system_host_keys": True,
    }
    if not settings.ssh_allow_legacy:
        # Mitigates CVE-2026-44405 while Netmiko requires Paramiko < 5.
        params["disabled_algorithms"] = {"keys": ["ssh-rsa"], "pubkeys": ["ssh-rsa"]}
    if settings.ssh_known_hosts_file:
        params.update({"alt_host_keys": True, "alt_key_file": str(settings.ssh_known_hosts_file)})
    return params


def reset_prompt(conn) -> None:
    """Call before a privilege/context change on a connection used for reads."""
    if hasattr(conn, _PROMPT_ATTRIBUTE):
        delattr(conn, _PROMPT_ATTRIBUTE)


def send_show(conn, command: str) -> str:
    """Read through the full anchored prompt without rediscovering it per command.

    Netmiko's base_prompt may be truncated and lacks the exec terminator. Keep
    the full discovered prompt so a hostname inside command output cannot end
    a read early. Connections and this prompt cache are never shared globally.
    """
    expected = getattr(conn, _PROMPT_ATTRIBUTE, None)
    if expected is None:
        try:
            prompt = conn.find_prompt().strip()
        except ValueError:
            raise ReadTimeout("Der SSH-Prompt konnte nicht sicher ermittelt werden.") from None
        if not prompt:
            raise ReadTimeout("Der SSH-Prompt konnte nicht sicher ermittelt werden.")
        expected = rf"(?m)^{re.escape(prompt)}[ \t]*$"
        setattr(conn, _PROMPT_ATTRIBUTE, expected)
    logger.info("Show command on %s: %s", getattr(conn, "host", "-"), command)
    return conn.send_command(command, expect_string=expected)


def ensure_privileged(conn, credentials: dict) -> None:
    """Enter privileged mode only when the session is not already privileged (reads and writes)."""
    reset_prompt(conn)
    try:
        if not conn.check_enable_mode():
            conn.enable()
    except Exception as exc:
        logger.warning("Could not enter privileged mode (%s)", type(exc).__name__)
        raise SwitchConnectionError(t("Der privilegierte Modus (Enable) konnte nicht aktiviert werden.")) from None
    finally:
        reset_prompt(conn)


@dataclass
class SshSession:
    """One open device session; drivers keep per-session state here."""

    conn: Any
    switch: dict
    credentials: dict
    warnings: list[str] = field(default_factory=list)
    # Set after a read timeout: a late response could still arrive on the channel,
    # so no further command may be sent on this connection.
    broken: bool = False
    cache: dict[str, Any] = field(default_factory=dict)


@contextmanager
def open_ssh(
    switch: dict, credentials: dict, netmiko_device_type: str, *, privileged: bool = True,
) -> Iterator[SshSession]:
    """Open a Netmiko connection, enter privileged mode and log the session duration.

    ``privileged=False`` skips the enable step (platforms without an enable mode, e.g. AOS-CX).

    Netmiko/Paramiko exceptions propagate unchanged; see ``ssh_session``.
    """
    logger.info(
        "SSH connection to switch %s (%s) %s:%s",
        switch.get("name"), switch.get("device_type"), switch.get("ip"), switch.get("port"),
    )
    started = time.monotonic()
    outcome = "error"
    try:
        with ConnectHandler(**netmiko_params(switch, credentials, netmiko_device_type)) as conn:
            if privileged:
                ensure_privileged(conn, credentials)
            yield SshSession(conn=conn, switch=switch, credentials=credentials)
        outcome = "ok"
    finally:
        logger.info(
            "SSH session to switch %s closed after %.2f s (%s)",
            switch.get("name"), time.monotonic() - started, outcome,
        )


@contextmanager
def ssh_session(
    switch: dict, credentials: dict, netmiko_device_type: str, *, privileged: bool = True,
) -> Iterator[SshSession]:
    """Like ``open_ssh`` but translates SSH failures into ``SwitchConnectionError``."""
    try:
        with open_ssh(switch, credentials, netmiko_device_type, privileged=privileged) as session:
            yield session
    except SSH_ERRORS as exc:
        raise_connection_error(switch, exc)


def tls_verification() -> bool | ssl.SSLContext:
    """TLS verification for switch HTTPS APIs (switch_api.* settings)."""
    settings = config.settings
    if settings.switch_api_allow_unverified_tls:
        return False
    ca_file = settings.switch_api_ca_cert_file
    try:
        context = ssl.create_default_context(cafile=str(Path(ca_file))) if ca_file else ssl.create_default_context()
    except (OSError, ssl.SSLError):
        raise SwitchConnectionError(t("Die konfigurierte CA-Datei für die Switch-API ist nicht lesbar.")) from None
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


@contextmanager
def https_client(
    switch: dict,
    credentials: dict,
    *,
    base_path: str = "",
    transport: httpx.BaseTransport | None = None,
) -> Iterator[httpx.Client]:
    """httpx client for ``https://{ip}:{port}{base_path}`` with Basic-Auth; logs the session duration.

    Redirects are not followed and proxies from the environment are ignored.
    Drivers must reject responses larger than ``HTTPS_MAX_RESPONSE_BYTES``.
    """
    host = str(switch["ip"])
    if not host or any(char in host for char in "/@?#\\ ") or "://" in host:
        raise SwitchConnectionError(t("Die Geräteadresse ist für HTTPS ungültig."))
    if ":" in host:
        host = f"[{host}]"
    timeout = float(config.settings.switch_api_timeout_seconds)
    options: dict[str, Any] = {
        "base_url": f"https://{host}:{int(switch['port'])}{base_path}",
        "auth": httpx.BasicAuth(credentials["username"], crypto.decrypt(credentials["password_enc"])),
        "verify": tls_verification(),
        "timeout": httpx.Timeout(timeout),
        "follow_redirects": False,
        "trust_env": False,
    }
    if transport is not None:
        options["transport"] = transport
    logger.info("HTTPS session to switch %s (%s) %s", switch.get("name"), switch.get("device_type"),
                options["base_url"])
    started = time.monotonic()
    outcome = "error"
    try:
        with httpx.Client(**options) as client:
            yield client
        outcome = "ok"
    finally:
        logger.info(
            "HTTPS session to switch %s closed after %.2f s (%s)",
            switch.get("name"), time.monotonic() - started, outcome,
        )
