"""NETCONF/YANG adapter for Cisco Catalyst 9800 controllers.

The adapter deliberately advertises only NETCONF base:1.0.  This keeps the wire
format deterministic (``]]>]]>`` end-of-message framing) on IOS XE releases
which offer both base:1.0 and base:1.1. Monitoring uses ``<get>``; the separate
configuration workflow uses guarded, explicit RPCs with uncertain write outcomes.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, urlsplit

import paramiko

from ... import config, crypto
from ...i18n import t
from ..models import (
    PLATFORM_CATALYST_9800,
    TRANSPORT_NETCONF,
    CollectionResult,
    WlanAuthenticationError,
    WlanCapabilityError,
    WlanConfigurationError,
    WlanConnectionError,
    WlanError,
    WlanProtocolError,
)
from .base import WlanControllerAdapter
from .catalyst_9800 import (
    AP_MODULE,
    AP_SUBTREES,
    CLIENT_MODULE,
    CLIENT_SUBTREES,
    REQUIRED_MODULES,
    _normalise_access_points,
    _normalise_clients,
)

logger = logging.getLogger("switchsteward.wlan.catalyst_9800_netconf")

NETCONF_BASE_NAMESPACE = "urn:ietf:params:xml:ns:netconf:base:1.0"
NETCONF_BASE_1_0_CAPABILITY = "urn:ietf:params:netconf:base:1.0"
YANG_LIBRARY_NAMESPACE = "urn:ietf:params:xml:ns:yang:ietf-yang-library"
CISCO_NAMESPACE_PREFIX = "http://cisco.com/ns/yang/"
AP_ROOT = "access-point-oper-data"
CLIENT_ROOT = "client-oper-data"
END_OF_MESSAGE = b"]]>]]>"

_DEFAULT_CONNECT_TIMEOUT_SECONDS = 10
_DEFAULT_READ_TIMEOUT_SECONDS = 30
_DEFAULT_MAX_RESPONSE_BYTES = 10_485_760
_MAX_HELLO_BYTES = 1_048_576
_MAX_XML_ELEMENTS = 200_000
_MAX_XML_DEPTH = 128


class _NetconfUnsupportedSubtree(WlanCapabilityError):
    """An RPC error that an optional collection may safely downgrade to a warning."""


class WlanWriteRejected(WlanError):
    """The server explicitly rejected a mutation; its payload is never exposed."""

    code = "write_rejected"
    status = "rejected"

    def __init__(self, message: str, *, error_tags: tuple[str, ...] = ()):
        super().__init__(message)
        self.error_tags = error_tags


class WlanWriteConflict(WlanWriteRejected):
    code = "write_conflict"


class WlanWriteOutcomeUnknown(WlanError):
    """A transmitted mutation has no reliable reply and must never be retried."""

    code = "write_outcome_unknown"
    status = "unknown"


_SAFE_ERROR_TAGS = frozenset({
    "in-use", "invalid-value", "too-big", "missing-attribute", "bad-attribute",
    "unknown-attribute", "missing-element", "bad-element", "unknown-element",
    "unknown-namespace", "access-denied", "lock-denied", "resource-denied",
    "rollback-failed", "data-exists", "data-missing", "operation-not-supported",
    "operation-failed", "partial-operation", "malformed-message",
})


class _BoundedTreeBuilder(ET.TreeBuilder):
    """Reject pathological element counts/depth in addition to the byte limit."""

    def __init__(self):
        super().__init__()
        self._elements = 0
        self._depth = 0

    def start(self, tag: str, attrs: dict[str, str]) -> ET.Element:
        self._elements += 1
        self._depth += 1
        if self._elements > _MAX_XML_ELEMENTS or self._depth > _MAX_XML_DEPTH:
            raise WlanProtocolError(t("Die NETCONF-XML-Struktur überschreitet das Sicherheitslimit."))
        return super().start(tag, attrs)

    def end(self, tag: str) -> ET.Element:
        element = super().end(tag)
        self._depth -= 1
        return element


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _namespace(tag: str) -> str | None:
    return tag[1:].split("}", 1)[0] if tag.startswith("{") and "}" in tag else None


def _parse_xml(raw: bytes, *, expected: str) -> ET.Element:
    """Parse RFC-6242 UTF-8 XML and reject DTD/entities before ElementTree."""

    try:
        document = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise WlanProtocolError(
            t("Der WLAN-Controller hat keine gültige UTF-8-codierte NETCONF-Antwort geliefert.")
        ) from None
    # RFC 6242 requires UTF-8 on the SSH transport. Embedded NULs are rejected
    # explicitly as well, so BOM-less UTF-16 cannot reach the XML parser merely
    # because each individual byte happens to be legal UTF-8.
    if "\x00" in document:
        raise WlanProtocolError(
            t("Der WLAN-Controller hat keine gültige UTF-8-codierte NETCONF-Antwort geliefert.")
        )
    lowered = document.casefold()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise WlanProtocolError(t("Die NETCONF-Antwort enthält unzulässige XML-Deklarationen."))
    try:
        parser = ET.XMLParser(target=_BoundedTreeBuilder())  # noqa: S314
        # DTD/entity declarations were rejected above; the bounded TreeBuilder also
        # caps depth and element count. ElementTree is retained to avoid relying on
        # an unpinned transitive dependency.
        root = ET.fromstring(document, parser=parser)  # noqa: S314
    except ET.ParseError:
        raise WlanProtocolError(
            t("Der WLAN-Controller hat keine gültige NETCONF-XML-Antwort geliefert.")
        ) from None
    if _local_name(root.tag) != expected:
        raise WlanProtocolError(
            t("Die NETCONF-Antwort enthält kein erwartetes {expected}-Element.", expected=expected)
        )
    return root


def _xml_value(element: ET.Element) -> Any:
    """Convert a YANG XML subtree to the mapping/list shape used by normalisers."""

    children = list(element)
    if not children:
        return (element.text or "").strip()
    result: dict[str, Any] = {}
    for child in children:
        key = _local_name(child.tag)
        value = _xml_value(child)
        if key not in result:
            result[key] = value
        elif isinstance(result[key], list):
            result[key].append(value)
        else:
            result[key] = [result[key], value]
    return result


def _find_data(reply: ET.Element) -> ET.Element:
    for element in reply.iter():
        if _local_name(element.tag) == "data" and _namespace(element.tag) in {
            None,
            NETCONF_BASE_NAMESPACE,
        }:
            return element
    raise WlanProtocolError(t("Die NETCONF-RPC-Antwort enthält kein data-Element."))


def _rpc_error(reply: ET.Element, *, write: bool = False) -> None:
    errors = [element for element in reply.iter() if _local_name(element.tag) == "rpc-error"]
    if not errors:
        return

    tags: set[str] = set()
    for error in errors:
        for element in error.iter():
            if _local_name(element.tag) == "error-tag" and element.text:
                tag = element.text.strip().casefold().replace("_", "-")
                tags.add(tag if tag in _SAFE_ERROR_TAGS else "operation-failed")
    if write:
        safe_tags = tuple(sorted(tags))
        if tags.intersection({"lock-denied", "in-use"}):
            raise WlanWriteConflict(
                t("Die Running-Konfiguration ist durch eine andere Sitzung gesperrt."),
                error_tags=safe_tags,
            )
        if tags.intersection({"rollback-failed", "partial-operation"}):
            raise WlanWriteOutcomeUnknown(
                t("Der Controller meldet eine unvollständige Änderung; aktuelle Werte erneut prüfen.")
            )
        message = (
            t("Der NETCONF-Benutzer besitzt keine Berechtigung für diese Änderung.")
            if "access-denied" in tags
            else t("Der Controller hat die Änderung abgelehnt. Eingaben und Abhängigkeiten prüfen.")
        )
        raise WlanWriteRejected(message, error_tags=safe_tags)
    if tags.intersection({"access-denied", "lock-denied"}):
        raise WlanAuthenticationError(
            t("NETCONF-Authentifizierung oder Leseberechtigung fehlgeschlagen.")
        )
    if tags.intersection(
        {
            "data-missing",
            "invalid-value",
            "operation-not-supported",
            "unknown-element",
            "unknown-namespace",
        }
    ):
        raise _NetconfUnsupportedSubtree(
            t("Der Controller unterstützt den angeforderten NETCONF/YANG-Teilbaum nicht.")
        )
    raise WlanProtocolError(t("Der WLAN-Controller hat einen NETCONF-RPC-Fehler geliefert."))


class _NetconfSession:
    """Small synchronous NETCONF base:1.0 session over a Paramiko channel."""

    def __init__(
        self,
        channel: Any,
        *,
        max_response_bytes: int,
        read_timeout: float = _DEFAULT_READ_TIMEOUT_SECONDS,
    ):
        self._channel = channel
        self._max_response_bytes = max_response_bytes
        self._read_timeout = read_timeout
        self._buffer = bytearray()
        self._next_message_id = 1
        self.capabilities: frozenset[str] = frozenset()
        self.module_metadata: dict[str, dict] = {}
        self.endpoint: tuple[str, int] | None = None

    def _read_message(self, *, limit: int) -> bytes:
        deadline = time.monotonic() + self._read_timeout
        search_from = 0
        while True:
            if time.monotonic() >= deadline:
                raise WlanConnectionError(
                    t("Zeitüberschreitung beim Lesen der NETCONF-Antwort.")
                )
            delimiter_at = self._buffer.find(END_OF_MESSAGE, search_from)
            if delimiter_at >= 0:
                if delimiter_at > limit:
                    raise WlanProtocolError(
                        t("Die NETCONF-Antwort überschreitet das konfigurierte Größenlimit.")
                    )
                message = bytes(self._buffer[:delimiter_at])
                del self._buffer[: delimiter_at + len(END_OF_MESSAGE)]
                if not message.strip():
                    raise WlanProtocolError(t("Der WLAN-Controller hat eine leere NETCONF-Antwort geliefert."))
                return message
            # Framing bytes do not count toward the payload limit. A delimiter
            # split across SSH packets is valid even after a full-sized payload.
            if len(self._buffer) > limit + len(END_OF_MESSAGE) - 1:
                raise WlanProtocolError(
                    t("Die NETCONF-Antwort überschreitet das konfigurierte Größenlimit.")
                )
            try:
                self._channel.settimeout(max(0.001, deadline - time.monotonic()))
                chunk = self._channel.recv(
                    min(65_536, limit + len(END_OF_MESSAGE) - len(self._buffer))
                )
            except (socket.timeout, TimeoutError):
                raise WlanConnectionError(
                    t("Zeitüberschreitung beim Lesen der NETCONF-Antwort.")
                ) from None
            except (OSError, paramiko.SSHException):
                raise WlanConnectionError(
                    t("Die NETCONF-SSH-Verbindung wurde beim Lesen unterbrochen.")
                ) from None
            if not chunk:
                raise WlanConnectionError(
                    t("Die NETCONF-SSH-Verbindung wurde vorzeitig geschlossen.")
                )
            search_from = max(0, len(self._buffer) - len(END_OF_MESSAGE) + 1)
            self._buffer.extend(chunk)

    def _send(self, payload: bytes) -> None:
        try:
            self._channel.settimeout(self._read_timeout)
            self._channel.sendall(payload + END_OF_MESSAGE)
        except (socket.timeout, TimeoutError, OSError, paramiko.SSHException):
            raise WlanConnectionError(
                t("Die NETCONF-SSH-Verbindung wurde beim Senden unterbrochen.")
            ) from None

    def handshake(self) -> None:
        server_hello = _parse_xml(
            self._read_message(limit=min(self._max_response_bytes, _MAX_HELLO_BYTES)),
            expected="hello",
        )
        capabilities = {
            (element.text or "").strip()
            for element in server_hello.iter()
            if _local_name(element.tag) == "capability" and (element.text or "").strip()
        }
        if NETCONF_BASE_1_0_CAPABILITY not in capabilities:
            raise WlanCapabilityError(
                t("Der WLAN-Controller bietet NETCONF base:1.0 nicht an.")
            )
        self.capabilities = frozenset(capabilities)

        hello = ET.Element(f"{{{NETCONF_BASE_NAMESPACE}}}hello")
        container = ET.SubElement(hello, f"{{{NETCONF_BASE_NAMESPACE}}}capabilities")
        capability = ET.SubElement(container, f"{{{NETCONF_BASE_NAMESPACE}}}capability")
        capability.text = NETCONF_BASE_1_0_CAPABILITY
        self._send(ET.tostring(hello, encoding="utf-8", xml_declaration=True))

    def request(self, operation: ET.Element, *, write: bool = False) -> ET.Element:
        """Send exactly one RPC. A lost write reply is an unknown outcome, never a retry."""

        logger.info(
            "NETCONF RPC %s on %s", _local_name(operation.tag), getattr(self, "endpoint", None) or "-",
        )
        message_id = str(self._next_message_id)
        self._next_message_id += 1
        rpc = ET.Element(
            f"{{{NETCONF_BASE_NAMESPACE}}}rpc",
            {"message-id": message_id},
        )
        rpc.append(operation)
        try:
            # Even sendall may have sent part/all of the request before failing.
            self._send(ET.tostring(rpc, encoding="utf-8", xml_declaration=True))
            reply = _parse_xml(
                self._read_message(limit=self._max_response_bytes),
                expected="rpc-reply",
            )
            if reply.attrib.get("message-id") != message_id:
                raise WlanProtocolError(
                    t("Die NETCONF-Antwort besitzt eine unerwartete message-id.")
                )
        except (WlanConnectionError, WlanProtocolError):
            if write:
                raise WlanWriteOutcomeUnknown(
                    t(
                        "Die Änderung wurde gesendet, ihr Ausgang ist unbekannt. "
                        "Vor einer erneuten Aktion die aktuellen Gerätewerte prüfen."
                    )
                ) from None
            raise
        _rpc_error(reply, write=write)
        return reply

    def get(self, filter_element: ET.Element) -> ET.Element:
        get_element = ET.Element(f"{{{NETCONF_BASE_NAMESPACE}}}get")
        filter_node = ET.SubElement(
            get_element,
            f"{{{NETCONF_BASE_NAMESPACE}}}filter",
            {"type": "subtree"},
        )
        filter_node.append(filter_element)
        return _find_data(self.request(get_element))

    def supports(self, capability: str) -> bool:
        prefix = f"urn:ietf:params:netconf:capability:{capability}:"
        return any(value.startswith(prefix) for value in self.capabilities)

    def get_config(self, filter_element: ET.Element) -> ET.Element:
        operation = ET.Element(f"{{{NETCONF_BASE_NAMESPACE}}}get-config")
        source = ET.SubElement(operation, f"{{{NETCONF_BASE_NAMESPACE}}}source")
        ET.SubElement(source, f"{{{NETCONF_BASE_NAMESPACE}}}running")
        filter_node = ET.SubElement(operation, f"{{{NETCONF_BASE_NAMESPACE}}}filter", {"type": "subtree"})
        filter_node.append(filter_element)
        return _find_data(self.request(operation))

    def get_schema(self, identifier: str, revision: str | None = None) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", identifier):
            raise WlanConfigurationError(t("Die YANG-Modulkennung ist ungültig."))
        namespace = "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"
        operation = ET.Element(f"{{{namespace}}}get-schema")
        ET.SubElement(operation, f"{{{namespace}}}identifier").text = identifier
        if revision:
            ET.SubElement(operation, f"{{{namespace}}}version").text = revision
        ET.SubElement(operation, f"{{{namespace}}}format").text = "yang"
        reply = self.request(operation)
        data = reply.find(f"{{{namespace}}}data")
        if data is None or not data.text or not data.text.strip():
            raise WlanProtocolError(t("Der Controller hat kein lesbares YANG-Schema geliefert."))
        return data.text

    @staticmethod
    def _require_ok(reply: ET.Element) -> None:
        if reply.find(f"{{{NETCONF_BASE_NAMESPACE}}}ok") is None:
            raise WlanWriteOutcomeUnknown(t("Der Controller hat den Schreibvorgang nicht eindeutig bestätigt."))

    def lock(self, datastore: str = "running") -> None:
        self._datastore_rpc("lock", datastore)

    def unlock(self, datastore: str = "running") -> None:
        self._datastore_rpc("unlock", datastore)

    def _datastore_rpc(self, name: str, datastore: str) -> None:
        if datastore != "running":
            raise WlanConfigurationError(t("Dieser Ablauf unterstützt ausschließlich den Running-Datastore."))
        operation = ET.Element(f"{{{NETCONF_BASE_NAMESPACE}}}{name}")
        target = ET.SubElement(operation, f"{{{NETCONF_BASE_NAMESPACE}}}target")
        ET.SubElement(target, f"{{{NETCONF_BASE_NAMESPACE}}}{datastore}")
        self._require_ok(self.request(operation, write=True))

    def edit_config(self, config: ET.Element) -> None:
        if not self.supports("writable-running"):
            raise WlanCapabilityError(t("Der Controller bietet keinen beschreibbaren Running-Datastore an."))
        if config.tag != f"{{{NETCONF_BASE_NAMESPACE}}}config":
            raise WlanConfigurationError(t("Die Änderung besitzt keinen gültigen NETCONF-Konfigurationsknoten."))
        operation = ET.Element(f"{{{NETCONF_BASE_NAMESPACE}}}edit-config")
        target = ET.SubElement(operation, f"{{{NETCONF_BASE_NAMESPACE}}}target")
        ET.SubElement(target, f"{{{NETCONF_BASE_NAMESPACE}}}running")
        ET.SubElement(operation, f"{{{NETCONF_BASE_NAMESPACE}}}default-operation").text = "none"
        if self.supports("validate"):
            ET.SubElement(operation, f"{{{NETCONF_BASE_NAMESPACE}}}test-option").text = "test-then-set"
        if self.supports("rollback-on-error"):
            ET.SubElement(operation, f"{{{NETCONF_BASE_NAMESPACE}}}error-option").text = "rollback-on-error"
        else:
            # A multi-leaf merge can partially apply without rollback support.
            # The higher-level adapter disables such edits on these controllers.
            raise WlanCapabilityError(t("Sicheres Bearbeiten erfordert NETCONF rollback-on-error."))
        operation.append(config)
        self._require_ok(self.request(operation, write=True))

    def action(self, operation: ET.Element) -> ET.Element:
        return self.request(operation, write=True)

    def save_config(self) -> ET.Element:
        return self.action(ET.Element("{http://cisco.com/yang/cisco-ia}save-config"))

    def close(self) -> None:
        """Request a graceful close without delaying cleanup for another read timeout."""

        message_id = str(self._next_message_id)
        rpc = ET.Element(
            f"{{{NETCONF_BASE_NAMESPACE}}}rpc",
            {"message-id": message_id},
        )
        ET.SubElement(rpc, f"{{{NETCONF_BASE_NAMESPACE}}}close-session")
        try:
            self._send(ET.tostring(rpc, encoding="utf-8", xml_declaration=True))
        except WlanError:
            pass


class Catalyst9800NetconfAdapter(WlanControllerAdapter):
    """Read Catalyst-9800 operational YANG data through NETCONF over SSH."""

    platform = PLATFORM_CATALYST_9800
    transport = TRANSPORT_NETCONF
    label = "NETCONF (SSH/YANG)"
    default_port = 830

    def __init__(
        self,
        *,
        ssh_client_factory: Callable[[], Any] = paramiko.SSHClient,
        channel_factory: Callable[[Any, float], Any] | None = None,
    ):
        self._ssh_client_factory = ssh_client_factory
        self._channel_factory = channel_factory
        self._schema_cache: dict[tuple, tuple[float, str]] = {}
        self._schema_cache_lock = threading.Lock()

    @staticmethod
    def _endpoint(controller: Mapping[str, Any]) -> tuple[str, int]:
        host_value = controller.get("host")
        if not isinstance(host_value, str) or not host_value.strip():
            raise WlanConfigurationError(t("Für den WLAN-Controller ist kein Host konfiguriert."))
        host = host_value.strip()
        if any(ord(character) < 33 or ord(character) == 127 for character in host):
            raise WlanConfigurationError(t("Der konfigurierte WLAN-Controller-Host ist ungültig."))
        if any(character in host for character in "/?#@[]"):
            raise WlanConfigurationError(
                t("Der WLAN-Controller-Host darf weder Schema, Pfad noch Zugangsdaten enthalten.")
            )
        try:
            host = ipaddress.ip_address(host).compressed
        except ValueError:
            try:
                host = host.rstrip(".").encode("idna").decode("ascii").lower()
            except UnicodeError:
                raise WlanConfigurationError(
                    t("Der konfigurierte WLAN-Controller-Host ist ungültig.")
                ) from None
            labels = host.split(".")
            if len(host) > 253 or not host or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels
            ):
                raise WlanConfigurationError(
                    t("Der konfigurierte WLAN-Controller-Host ist ungültig.")
                ) from None

        port_value = controller.get("port", 830)
        if isinstance(port_value, bool):
            raise WlanConfigurationError(t("Der NETCONF-Port muss zwischen 1 und 65535 liegen."))
        try:
            port = int(port_value)
        except (TypeError, ValueError):
            raise WlanConfigurationError(
                t("Der NETCONF-Port muss zwischen 1 und 65535 liegen.")
            ) from None
        if not 1 <= port <= 65_535:
            raise WlanConfigurationError(t("Der NETCONF-Port muss zwischen 1 und 65535 liegen."))
        return host, port

    @staticmethod
    def _plaintext_credentials(credentials: Mapping[str, Any]) -> tuple[str, str]:
        username = credentials.get("username")
        password_enc = credentials.get("password_enc")
        if not isinstance(username, str) or not username.strip() or password_enc is None:
            raise WlanConfigurationError(
                t("Für den WLAN-Controller sind keine vollständigen Zugangsdaten hinterlegt.")
            )
        try:
            password = crypto.decrypt(password_enc)
        except Exception as exc:
            logger.warning("WLAN credential decryption failed (%s)", type(exc).__name__)
            raise WlanConfigurationError(
                t("Die Zugangsdaten des WLAN-Controllers konnten nicht entschlüsselt werden.")
            ) from None
        if not isinstance(password, str):
            raise WlanConfigurationError(
                t("Die Zugangsdaten des WLAN-Controllers konnten nicht entschlüsselt werden.")
            )
        return username.strip(), password

    @staticmethod
    def _timeouts_and_limit() -> tuple[float, float, int]:
        try:
            connect_timeout = float(config.settings.wireless_connect_timeout_seconds)
            read_timeout = float(config.settings.wireless_read_timeout_seconds)
            max_response_bytes = int(config.settings.wireless_max_response_bytes)
        except (TypeError, ValueError):
            raise WlanConfigurationError(t("Die NETCONF-Laufzeitparameter sind ungültig.")) from None
        if connect_timeout <= 0 or read_timeout <= 0 or max_response_bytes <= 0:
            raise WlanConfigurationError(t("Die NETCONF-Laufzeitparameter sind ungültig."))
        return connect_timeout, read_timeout, max_response_bytes

    @staticmethod
    def _invoke_netconf_subsystem(channel: Any, timeout: float) -> None:
        """Bound Paramiko's otherwise unbounded subsystem request wait."""

        completed = threading.Event()
        failures: list[BaseException] = []

        def invoke() -> None:
            try:
                channel.invoke_subsystem("netconf")
            except BaseException as exc:  # propagated as a typed, payload-free error below
                failures.append(exc)
            finally:
                completed.set()

        thread = threading.Thread(
            target=invoke,
            name="wlan-netconf-subsystem",
            daemon=True,
        )
        thread.start()
        if not completed.wait(timeout):
            # Paramiko wakes its pending channel-request event when the channel is
            # closed. The thread is daemonized as a final guard for a broken custom
            # transport which ignores close altogether.
            try:
                channel.close()
            except Exception as exc:
                logger.debug(
                    "Closing timed-out NETCONF channel failed (%s)",
                    type(exc).__name__,
                )
            thread.join(timeout=min(timeout, 0.25))
            raise WlanConnectionError(
                t("Zeitüberschreitung beim Aktivieren des NETCONF-SSH-Subsystems.")
            )
        if failures:
            raise WlanConnectionError(
                t("Das NETCONF-SSH-Subsystem konnte nicht aktiviert werden.")
            ) from None

    @staticmethod
    def _configure_host_keys(client: Any) -> None:
        settings = config.settings
        strict = bool(settings.wireless_netconf_strict_host_keys)
        known_hosts = settings.wireless_netconf_known_hosts_file
        client.load_system_host_keys()
        if known_hosts:
            path = Path(known_hosts)
            if not path.is_file():
                raise WlanConfigurationError(
                    t("Die konfigurierte Known-Hosts-Datei für NETCONF ist nicht lesbar.")
                )
            try:
                client.load_host_keys(str(path))
            except (OSError, paramiko.SSHException):
                raise WlanConfigurationError(
                    t("Die konfigurierte Known-Hosts-Datei für NETCONF ist ungültig.")
                ) from None
        # WarningPolicy is reachable only through an explicit false setting.  The
        # default is RejectPolicy and therefore never trusts a new key on first use.
        policy = paramiko.RejectPolicy() if strict else paramiko.WarningPolicy()
        client.set_missing_host_key_policy(policy)

    @contextmanager
    def _session(
        self,
        controller: Mapping[str, Any],
        credentials: Mapping[str, Any],
    ) -> Iterator[_NetconfSession]:
        host, port = self._endpoint(controller)
        logger.info("NETCONF connection to controller %s %s:%s", controller.get("name"), host, port)
        username, password = self._plaintext_credentials(credentials)
        connect_timeout, read_timeout, max_response_bytes = self._timeouts_and_limit()
        client = self._ssh_client_factory()
        channel = None
        session = None
        try:
            self._configure_host_keys(client)
            client.connect(
                **self._connect_options(
                    host,
                    port,
                    username,
                    password,
                    connect_timeout,
                )
            )
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise WlanConnectionError(
                    t("Der WLAN-Controller hat keinen aktiven NETCONF-SSH-Transport bereitgestellt.")
                )
            channel = (
                self._channel_factory(transport, connect_timeout)
                if self._channel_factory is not None
                else transport.open_session(timeout=connect_timeout)
            )
            channel.settimeout(read_timeout)
            self._invoke_netconf_subsystem(channel, connect_timeout)
            session = _NetconfSession(
                channel,
                max_response_bytes=max_response_bytes,
                read_timeout=read_timeout,
            )
            session.endpoint = (host, port)
            session.handshake()
            yield session
        except WlanError:
            raise
        except paramiko.AuthenticationException:
            raise WlanAuthenticationError(
                t("NETCONF-Authentifizierung am WLAN-Controller fehlgeschlagen.")
            ) from None
        except paramiko.BadHostKeyException:
            raise WlanConnectionError(
                t("Der SSH-Host-Key des WLAN-Controllers stimmt nicht mit Known Hosts überein.")
            ) from None
        except (socket.timeout, TimeoutError):
            raise WlanConnectionError(
                t("Zeitüberschreitung bei der NETCONF-Verbindung zum WLAN-Controller.")
            ) from None
        except paramiko.SSHException as exc:
            message = str(exc).casefold()
            if "known_hosts" in message or "host key" in message:
                raise WlanConnectionError(
                    t("Der SSH-Host-Key des WLAN-Controllers konnte nicht verifiziert werden.")
                ) from None
            logger.warning(
                "NETCONF SSH failed for controller id=%s (%s)",
                controller.get("id"),
                type(exc).__name__,
            )
            raise WlanConnectionError(
                t("Der NETCONF-Dienst des WLAN-Controllers ist nicht erreichbar.")
            ) from None
        except OSError as exc:
            logger.warning(
                "NETCONF transport failed for controller id=%s (%s)",
                controller.get("id"),
                type(exc).__name__,
            )
            raise WlanConnectionError(
                t("Der NETCONF-Dienst des WLAN-Controllers ist nicht erreichbar.")
            ) from None
        finally:
            # A failing close must neither mask the original typed error nor
            # prevent the remaining transport resources from being released.
            for resource in (session, channel, client):
                if resource is None:
                    continue
                try:
                    resource.close()
                except Exception as exc:
                    logger.debug("Closing NETCONF resource failed (%s)", type(exc).__name__)

    @staticmethod
    def _connect_options(
        host: str,
        port: int,
        username: str,
        password: str,
        connect_timeout: float,
    ) -> dict[str, Any]:
        options: dict[str, Any] = {
            "hostname": host,
            "port": port,
            "username": username,
            "password": password,
            "timeout": connect_timeout,
            "banner_timeout": connect_timeout,
            "auth_timeout": connect_timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        allow_legacy = bool(config.settings.wireless_netconf_allow_legacy_algorithms)
        if not allow_legacy:
            options["disabled_algorithms"] = {
                "keys": ["ssh-rsa"],
                "pubkeys": ["ssh-rsa"],
            }
        return options

    @staticmethod
    def _yang_library_filter() -> ET.Element:
        modules_state = ET.Element(f"{{{YANG_LIBRARY_NAMESPACE}}}modules-state")
        module = ET.SubElement(modules_state, f"{{{YANG_LIBRARY_NAMESPACE}}}module")
        ET.SubElement(module, f"{{{YANG_LIBRARY_NAMESPACE}}}name")
        ET.SubElement(module, f"{{{YANG_LIBRARY_NAMESPACE}}}revision")
        ET.SubElement(module, f"{{{YANG_LIBRARY_NAMESPACE}}}feature")
        ET.SubElement(module, f"{{{YANG_LIBRARY_NAMESPACE}}}deviation")
        ET.SubElement(module, f"{{{YANG_LIBRARY_NAMESPACE}}}conformance-type")
        return modules_state

    @staticmethod
    def _collection_filter(module: str, root: str, subtree: str) -> ET.Element:
        namespace = f"{CISCO_NAMESPACE_PREFIX}{module}"
        root_element = ET.Element(f"{{{namespace}}}{root}")
        ET.SubElement(root_element, f"{{{namespace}}}{subtree}")
        return root_element

    @staticmethod
    def _modules_from_data(data: ET.Element) -> dict[str, str | None]:
        modules: dict[str, str | None] = {}
        for module in data.iter():
            if _local_name(module.tag) != "module" or _namespace(module.tag) != YANG_LIBRARY_NAMESPACE:
                continue
            name = None
            revision = None
            for child in module:
                if _local_name(child.tag) == "name":
                    name = (child.text or "").strip() or None
                elif _local_name(child.tag) == "revision":
                    revision = (child.text or "").strip() or None
            if name:
                modules[name] = revision
        if not modules:
            raise WlanProtocolError(
                t("Die YANG-Library des Controllers enthält keine lesbaren Module.")
            )
        return modules

    def _discover_modules(self, session: _NetconfSession) -> dict[str, str | None]:
        hello_modules: dict[str, str | None] = {}
        for capability in session.capabilities:
            query = parse_qs(urlsplit(capability).query)
            names = query.get("module", [])
            if names and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", names[0]):
                hello_modules[names[0]] = (query.get("revision") or [None])[0]
                session.module_metadata[names[0]] = {
                    "features": sorted(filter(None, (query.get("features") or [""])[0].split(","))),
                    "deviations": sorted(filter(None, (query.get("deviations") or [""])[0].split(","))),
                    "conformance": "implement",
                }
        try:
            data = session.get(self._yang_library_filter())
            library_modules = self._modules_from_data(data)
        except (WlanCapabilityError, WlanAuthenticationError):
            if not hello_modules:
                raise
            return hello_modules
        for module in data.iter(f"{{{YANG_LIBRARY_NAMESPACE}}}module"):
            name = module.findtext(f"{{{YANG_LIBRARY_NAMESPACE}}}name")
            if not name:
                continue
            session.module_metadata[name] = {
                "features": sorted(child.text for child in module.findall(f"{{{YANG_LIBRARY_NAMESPACE}}}feature") if child.text),
                "deviations": sorted(child.findtext(f"{{{YANG_LIBRARY_NAMESPACE}}}name") or "unknown" for child in module.findall(f"{{{YANG_LIBRARY_NAMESPACE}}}deviation")),
                "conformance": module.findtext(f"{{{YANG_LIBRARY_NAMESPACE}}}conformance-type") or "implement",
            }
        return {**hello_modules, **library_modules}

    @staticmethod
    def _require_module(modules: Mapping[str, str | None], module: str) -> None:
        if module not in modules:
            raise WlanCapabilityError(
                t("Der Controller stellt das benötigte YANG-Modul {module} nicht bereit.", module=module)
            )

    def _read_collection(
        self,
        session: _NetconfSession,
        modules: Mapping[str, str | None],
        module: str,
        root: str,
        subtree: str,
    ) -> tuple[list[Mapping[str, Any]], bool]:
        self._require_module(modules, module)
        data = session.get(self._collection_filter(module, root, subtree))
        namespace = f"{CISCO_NAMESPACE_PREFIX}{module}"
        records: list[Mapping[str, Any]] = []
        roots = [
            element
            for element in data
            if _local_name(element.tag) == root and _namespace(element.tag) == namespace
        ]
        for root_element in roots:
            for element in root_element:
                if _local_name(element.tag) != subtree or _namespace(element.tag) != namespace:
                    continue
                value = _xml_value(element)
                if isinstance(value, Mapping):
                    records.append(value)
        return records, not records

    def _read_subtrees(
        self,
        session: _NetconfSession,
        modules: Mapping[str, str | None],
        module: str,
        root: str,
        subtrees: tuple[tuple[str, bool], ...],
    ) -> tuple[dict[str, Any], list[str], bool]:
        combined: dict[str, Any] = {root: {}}
        warnings: list[str] = []
        complete = True
        for subtree, required in subtrees:
            unsupported = False
            restricted = False
            try:
                records, absent = self._read_collection(
                    session,
                    modules,
                    module,
                    root,
                    subtree,
                )
            except _NetconfUnsupportedSubtree:
                if required:
                    raise
                records, absent, unsupported = [], True, True
            except WlanAuthenticationError:
                if required:
                    raise
                records, absent, restricted = [], True, True
            combined[root][subtree] = records
            if absent:
                complete = False
                if restricted:
                    warning = (
                        t("Der erforderliche YANG-Teilbaum {subtree} konnte nicht gelesen werden.", subtree=subtree)
                        if required
                        else t("Der optionale YANG-Teilbaum {subtree} konnte nicht gelesen werden.", subtree=subtree)
                    )
                elif unsupported:
                    warning = (
                        t("Der erforderliche YANG-Teilbaum {subtree} wird nicht unterstützt.", subtree=subtree)
                        if required
                        else t("Der optionale YANG-Teilbaum {subtree} wird nicht unterstützt.", subtree=subtree)
                    )
                else:
                    warning = (
                        t("Der erforderliche YANG-Teilbaum {subtree} hat keine Daten geliefert.", subtree=subtree)
                        if required
                        else t("Der optionale YANG-Teilbaum {subtree} hat keine Daten geliefert.", subtree=subtree)
                    )
                warnings.append(warning)
        return combined, warnings, complete

    def test_connection(self, controller: dict, credentials: dict) -> dict:
        try:
            with self._session(controller, credentials) as session:
                modules = self._discover_modules(session)
                missing = sorted(REQUIRED_MODULES.difference(modules))
                if missing:
                    raise WlanCapabilityError(
                        t(
                            "Dem Controller fehlen benötigte WLAN-YANG-Module: {modules}",
                            modules=", ".join(missing),
                        )
                    )
                _, access_points_absent = self._read_collection(
                    session,
                    modules,
                    AP_MODULE,
                    AP_ROOT,
                    "capwap-data",
                )
                _, clients_absent = self._read_collection(
                    session,
                    modules,
                    CLIENT_MODULE,
                    CLIENT_ROOT,
                    "common-oper-data",
                )
                server_capability_count = len(session.capabilities)
        except WlanError as exc:
            logger.warning(
                "WLAN NETCONF connection test failed for controller id=%s (%s)",
                controller.get("id"),
                exc.code,
            )
            return {"ok": False, "message": exc.message, "error": exc.code}

        return {
            "ok": True,
            "message": (
                t("NETCONF, WLAN-YANG-Module und Pflichtendpunkte sind verfügbar.")
                if not access_points_absent and not clients_absent
                else t(
                    "NETCONF und WLAN-YANG-Module sind verfügbar; mindestens "
                    "eine Pflicht-Collection war leer."
                )
            ),
            "platform": self.platform,
            "capabilities": {
                "netconf": True,
                "netconf_base": "1.0",
                "server_capability_count": server_capability_count,
                "yang_library": True,
                "access_points": not access_points_absent,
                "clients": not clients_absent,
                "module_revisions": {
                    module: modules.get(module) for module in sorted(REQUIRED_MODULES)
                },
            },
        }

    def list_access_points(self, controller: dict, credentials: dict) -> CollectionResult:
        with self._session(controller, credentials) as session:
            modules = self._discover_modules(session)
            payload, warnings, complete = self._read_subtrees(
                session,
                modules,
                AP_MODULE,
                AP_ROOT,
                AP_SUBTREES,
            )
        result = _normalise_access_points(payload)
        result.complete = result.complete and complete
        result.warnings = warnings + result.warnings
        return result

    def list_clients(self, controller: dict, credentials: dict) -> CollectionResult:
        with self._session(controller, credentials) as session:
            modules = self._discover_modules(session)
            payload, warnings, complete = self._read_subtrees(
                session,
                modules,
                CLIENT_MODULE,
                CLIENT_ROOT,
                CLIENT_SUBTREES,
            )
        result = _normalise_clients(payload)
        result.complete = result.complete and complete
        result.warnings = warnings + result.warnings
        return result

    def get_configuration(self, controller: dict, credentials: dict) -> dict:
        from .netconf_config import read_configuration

        with self._session(controller, credentials) as session:
            return read_configuration(self, session)

    def apply_configuration(
        self, controller: dict, credentials: dict, change: dict, expected_revision: str,
    ) -> dict:
        from .netconf_config import apply_configuration, read_back_unknown

        with self._session(controller, credentials) as session:
            result = apply_configuration(self, session, change, expected_revision)
        if result.get("status") == "unknown":
            return read_back_unknown(self, controller, credentials, change, result)
        return result
