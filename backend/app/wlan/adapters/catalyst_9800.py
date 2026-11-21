"""RESTCONF/YANG-Adapter fuer Cisco Catalyst-9800-Controller.

Der Adapter liest ausschliesslich operative Daten. Die URL wird aus dem validierten
``host``- und ``port``-Feld des Controller-Datensatzes aufgebaut; Redirects sind
deaktiviert. Die Zertifikatspruefung kann ueber eine explizite WLAN-Ausnahme
abgeschaltet werden.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import ssl
import time
from collections import OrderedDict, defaultdict
from collections.abc import Callable, Iterator, Mapping
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from ... import config, crypto
from ...i18n import t
from ..models import (
    PLATFORM_CATALYST_9800,
    TRANSPORT_RESTCONF,
    AccessPoint,
    CollectionResult,
    WirelessClient,
    WlanAuthenticationError,
    WlanCapabilityError,
    WlanConfigurationError,
    WlanConnectionError,
    WlanError,
    WlanProtocolError,
    WlanTlsError,
)
from .base import WlanControllerAdapter

logger = logging.getLogger("switchsteward.wlan.catalyst_9800")

YANG_LIBRARY_PATH = "/restconf/data/ietf-yang-library:modules-state"
ACCESS_POINTS_ROOT = (
    "/restconf/data/"
    "Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data"
)
CLIENTS_ROOT = "/restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data"

# Only the subtrees needed for inventory and client association are read. The
# unrestricted oper root contains many large counters and statistics that, even
# for a mid-sized AP fleet, are far larger than the inventory list itself.
AP_SUBTREES = (
    ("capwap-data", True),
    ("oper-data", False),
    ("radio-oper-data", False),
    ("radio-oper-stats", False),
)
CLIENT_SUBTREES = (
    ("common-oper-data", True),
    ("dot11-oper-data", False),
    ("traffic-stats", False),
    ("sisf-db-mac", False),
    ("policy-data", False),
)

AP_MODULE = "Cisco-IOS-XE-wireless-access-point-oper"
CLIENT_MODULE = "Cisco-IOS-XE-wireless-client-oper"
REQUIRED_MODULES = frozenset({AP_MODULE, CLIENT_MODULE})

_DEFAULT_CONNECT_TIMEOUT_SECONDS = 10
_DEFAULT_READ_TIMEOUT_SECONDS = 30
_DEFAULT_MAX_RESPONSE_BYTES = 10_485_760
_MAX_JSON_DEPTH = 128
_MAX_JSON_VALUES = 200_000


class _RestconfNotFound(WlanCapabilityError):
    """HTTP 404; nur bekannte Collection-Pfade duerfen dies als leer deuten."""


class _RestconfNoContent(WlanProtocolError):
    """HTTP 204; nur bekannte Collection-Pfade duerfen dies als leer deuten."""


def _key_token(value: Any) -> str:
    local_name = str(value).rsplit(":", 1)[-1]
    return re.sub(r"[^a-z0-9]", "", local_name.casefold())


def _alias_tokens(aliases: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    return tuple(_key_token(alias) for alias in aliases)


def _iter_leaf_values(value: Any) -> Iterator[tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(child, Mapping):
                yield from _iter_leaf_values(child)
            elif isinstance(child, list):
                for item in child:
                    yield from _iter_leaf_values(item)
            elif child is not None:
                yield _key_token(key), child


def _leaf_map(record: Mapping[str, Any]) -> dict[str, list[Any]]:
    result: dict[str, list[Any]] = defaultdict(list)
    for key, value in _iter_leaf_values(record):
        result[key].append(value)
    return result


def _first_in_map(values: Mapping[str, list[Any]], aliases: tuple[str, ...]) -> Any:
    for token in _alias_tokens(aliases):
        for value in values.get(token, []):
            if value is not None and (not isinstance(value, str) or value.strip()):
                return value
    return None


def _field_reader(records: list[Mapping[str, Any]]) -> Callable[[tuple[str, ...]], Any]:
    """Flatten each record once, then reuse it for all normalized output fields."""

    maps = [_leaf_map(record) for record in records]

    def first(aliases: tuple[str, ...]) -> Any:
        for token in _alias_tokens(aliases):
            for values in maps:
                for value in values.get(token, []):
                    if value is not None and (not isinstance(value, str) or value.strip()):
                        return value
        return None

    return first


def _first_across(records: list[Mapping[str, Any]], aliases: tuple[str, ...]) -> Any:
    return _field_reader(records)(aliases)


def _direct_value(record: Mapping[str, Any], aliases: tuple[str, ...]) -> Any:
    tokens = set(_alias_tokens(aliases))
    for key, value in record.items():
        if _key_token(key) in tokens and not isinstance(value, (Mapping, list)):
            return value
    return None


def _walk_identified_records(value: Any, identity_aliases: tuple[str, ...]) -> Iterator[Mapping[str, Any]]:
    """Findet YANG-Listeneintraege ohne feste Annahmen ueber Container-Tiefen."""

    if isinstance(value, Mapping):
        if _direct_value(value, identity_aliases) is not None:
            yield value
        for child in value.values():
            yield from _walk_identified_records(child, identity_aliases)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_identified_records(child, identity_aliases)


def _walk_container_records(
    value: Any,
    container_aliases: tuple[str, ...],
    identity_aliases: tuple[str, ...],
) -> Iterator[Mapping[str, Any]]:
    """Liefert nur Eintraege aus bekannten YANG-Listcontainern.

    Das ist bei APs wichtig: ein generisches ``name`` kommt auch in vielen
    untergeordneten Statistikobjekten vor und darf nicht als eigener AP gelten.
    """

    container_tokens = set(_alias_tokens(container_aliases))
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _key_token(key) in container_tokens:
                if isinstance(child, list):
                    for entry in child:
                        if isinstance(entry, Mapping):
                            yield entry
                elif isinstance(child, Mapping):
                    if _direct_value(child, identity_aliases) is not None:
                        yield child
            yield from _walk_container_records(child, container_aliases, identity_aliases)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_container_records(child, container_aliases, identity_aliases)


def _contains_key(value: Any, expected: str) -> bool:
    token = _key_token(expected)
    if isinstance(value, Mapping):
        return any(
            _key_token(key) == token or _contains_key(child, expected)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_key(child, expected) for child in value)
    return False


def _extract_collection_payload(
    payload: Mapping[str, Any],
    module: str,
    subtree: str,
) -> list[Mapping[str, Any]]:
    """Validiert die standardisierte RESTCONF-Huelle einer YANG-Liste."""

    allowed_keys = (f"{module}:{subtree}", subtree)
    matching_keys = [key for key in allowed_keys if key in payload]
    if len(matching_keys) != 1:
        raise WlanProtocolError(
            t("Die RESTCONF-Antwort enthält nicht den erwarteten YANG-Schlüssel {subtree}.", subtree=subtree)
        )
    collection = payload[matching_keys[0]]
    if not isinstance(collection, list) or any(
        not isinstance(entry, Mapping) for entry in collection
    ):
        raise WlanProtocolError(
            t("Der YANG-Schlüssel {subtree} enthält keine gültige Liste.", subtree=subtree)
        )
    return collection


def _decode_json(raw: bytes | bytearray) -> Any:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise WlanProtocolError(
            t("Der WLAN-Controller hat keine gültige YANG-JSON-Antwort geliefert.")
        ) from None
    # Bound recursive normalisation and module discovery before either starts.
    # Store iterators, not a tuple for every child: a wide JSON array must not
    # allocate another unbounded work list merely to enforce the value limit.
    stack = [(iter((payload,)), 0)]
    values = 0
    while stack:
        children, depth = stack[-1]
        try:
            value = next(children)
        except StopIteration:
            stack.pop()
            continue
        values += 1
        if depth > _MAX_JSON_DEPTH or values > _MAX_JSON_VALUES:
            raise WlanProtocolError(t("Die RESTCONF-JSON-Struktur überschreitet das Sicherheitslimit."))
        if isinstance(value, dict):
            stack.append((iter(value.values()), depth + 1))
        elif isinstance(value, list):
            stack.append((iter(value), depth + 1))
    return payload


def _restconf_error_tags(raw: bytes | bytearray) -> set[str]:
    """Extrahiert RFC-8040-error-tag-Werte aus einer JSON-Fehlerantwort."""

    if not raw:
        return set()
    try:
        payload = _decode_json(raw)
    except WlanProtocolError:
        return set()
    if not isinstance(payload, Mapping):
        return set()

    roots = [
        value
        for key, value in payload.items()
        if _key_token(key) == "errors" and isinstance(value, Mapping)
    ]
    tags: set[str] = set()
    for root in roots:
        for key, value in root.items():
            if _key_token(key) != "error":
                continue
            entries = value if isinstance(value, list) else [value]
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                tag = _string(_direct_value(entry, ("error-tag",)))
                if tag:
                    tags.add(tag.casefold().replace("_", "-"))
    return tags


def _string(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    result = str(value).strip()
    return result or None


def _integer(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _number_or_string(value: Any) -> int | str | None:
    integer = _integer(value)
    if integer is not None:
        return integer
    return _string(value)


def _normalise_mac(value: Any) -> str | None:
    raw = _string(value)
    if not raw:
        return None
    compact = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(compact) != 12 or not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
        return None
    compact = compact.lower()
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def _normalise_ip(value: Any) -> str | None:
    raw = _string(value)
    if not raw:
        return None
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    if address.is_unspecified:
        return None
    return address.compressed


def _normalise_enum(value: Any) -> str | None:
    raw = _string(value)
    if not raw:
        return None
    return raw.rsplit(":", 1)[-1].replace("_", "-")


def _seconds_since(value: Any) -> int | None:
    raw = _string(value)
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        seconds = int((datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds())
    except (ValueError, OverflowError):
        return None
    return max(0, seconds)


def _normalise_ap_status(value: Any) -> str:
    raw = (_normalise_enum(value) or "unknown").casefold()
    if raw in {
        "up",
        "ap-up",
        "joined",
        "registered",
        "enabled",
        "ap-operation-state-registered",
    }:
        return "up"
    if raw in {
        "down",
        "ap-down",
        "disjoined",
        "not-joined",
        "disabled",
        "ap-operation-state-not-registered",
    }:
        return "down"
    return raw


def _records_for_container(
    payload: Mapping[str, Any],
    container: str,
    identity_aliases: tuple[str, ...],
) -> list[Mapping[str, Any]]:
    records: list[Mapping[str, Any]] = []
    seen: set[int] = set()
    for record in _walk_container_records(payload, (container,), identity_aliases):
        if id(record) in seen:
            continue
        seen.add(id(record))
        records.append(record)
    return records


def _normalise_radio(records: list[Mapping[str, Any]]) -> dict[str, Any] | None:
    first = _field_reader(records)
    slot = first(("radio-slot-id", "slot-id", "slot"))
    band = first(("current-band-id", "radio-band", "band", "radio-type"))
    channel = first(("current-channel", "channel-number", "curr-freq", "channel"))
    width = first(("channel-width", "chan-width"))
    state = first(("radio-operation-state", "oper-state", "radio-state"))
    # Ein blosses ``oper-state`` kann auch der AP-Zustand sein. Mindestens ein
    # radiospezifisches Merkmal verhindert einen zusaetzlichen Phantom-Radioeintrag.
    if all(value is None for value in (slot, band, channel, width)):
        return None
    return {
        "slot": _number_or_string(slot),
        "band": _normalise_enum(band),
        "channel": _number_or_string(channel),
        "channel_width": _number_or_string(width),
        "state": _normalise_enum(state),
        "client_count": _integer(first(("aid-user-list",))),
    }


def _radio_sort_key(radio: Mapping[str, Any]) -> tuple[int, int | str]:
    slot = radio.get("slot")
    if isinstance(slot, int):
        return (0, slot)
    return (1, str(slot or radio.get("band") or ""))


def _normalise_access_points(payload: Mapping[str, Any]) -> CollectionResult:
    if not _contains_key(payload, "access-point-oper-data"):
        raise WlanProtocolError(t("Die YANG-Antwort enthält keine Access-Point-Daten."))

    identity_aliases = (
        "wtp-mac",
        "ap-ethernet-mac",
        "ethernet-mac",
        "ap-mac",
        "ap-name",
        "wtp-name",
        "name",
    )
    mac_aliases = ("wtp-mac", "ap-ethernet-mac", "ethernet-mac", "ap-mac")
    name_aliases = ("ap-name", "wtp-name", "name")
    groups: OrderedDict[str, list[Mapping[str, Any]]] = OrderedDict()
    invalid_capwap = 0
    for record in _records_for_container(payload, "capwap-data", identity_aliases):
        mac = _normalise_mac(_first_across([record], mac_aliases))
        name = _string(_first_across([record], name_aliases))
        if not mac and not name:
            invalid_capwap += 1
            continue
        key = mac or f"name:{name.casefold()}"
        groups.setdefault(key, []).append(record)

    unmatched_optional = 0
    for record in _records_for_container(payload, "oper-data", identity_aliases):
        mac = _normalise_mac(_first_across([record], mac_aliases))
        if not mac or mac not in groups:
            unmatched_optional += 1
            continue
        groups[mac].append(record)

    radio_groups: dict[str, OrderedDict[str, list[Mapping[str, Any]]]] = defaultdict(
        OrderedDict
    )
    invalid_radio = 0
    for container in ("radio-oper-data", "radio-oper-stats"):
        for record in _records_for_container(payload, container, identity_aliases):
            mac = _normalise_mac(_first_across([record], mac_aliases))
            slot = _number_or_string(
                _direct_value(record, ("radio-slot-id", "slot-id"))
            )
            if not mac or mac not in groups:
                unmatched_optional += 1
                continue
            if slot is None:
                invalid_radio += 1
                continue
            radio_groups[mac].setdefault(str(slot), []).append(record)

    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    complete = True
    for key, records in groups.items():
        first = _field_reader(records)
        mac = _normalise_mac(first(mac_aliases))
        name = _string(first(name_aliases))
        if not name:
            name = mac or key
            complete = False
            warnings.append(t("Access Point {name} besitzt im YANG-Datensatz keinen Namen.", name=name))

        radios = [
            radio
            for radio_records in radio_groups.get(key, {}).values()
            if (radio := _normalise_radio(radio_records)) is not None
        ]
        radio_client_counts = [
            radio["client_count"]
            for radio in radios
            if radio.get("client_count") is not None
        ]

        item = AccessPoint(
            name=name,
            mac=mac,
            ip=_normalise_ip(
                first(
                    (
                        "wtp-ip",
                        "ap-ip-addr",
                        "ap-ip-address",
                        "ip-addr",
                        "management-ip",
                        "ip-address",
                    ),
                )
            ),
            status=_normalise_ap_status(
                first(("ap-operation-state", "ap-oper-state", "operation-state", "oper-state", "status"))
            ),
            model=_string(
                first(("ap-model", "model-number", "product-id", "model"))
            ),
            serial_number=_string(
                first(("wtp-serial-num", "serial-number", "serial-num"))
            ),
            location=_string(first(("ap-location", "location"))),
            site_tag=_string(first(("site-tag-name", "site-tag"))),
            policy_tag=_string(first(("policy-tag-name", "policy-tag"))),
            rf_tag=_string(first(("rf-tag-name", "rf-tag"))),
            uptime_seconds=_integer(
                first(("ap-uptime", "uptime-seconds", "uptime"))
            ),
            client_count=(
                sum(radio_client_counts)
                if radio_client_counts
                else _integer(
                    first(("client-count", "num-clients", "joined-clients"))
                )
            ),
            radios=sorted(radios, key=_radio_sort_key),
        ).to_dict()
        items.append(item)

    if invalid_capwap:
        complete = False
        warnings.append(
            t("{count} CAPWAP-Datensätze konnten nicht eindeutig zugeordnet werden.", count=invalid_capwap)
        )
    if unmatched_optional:
        complete = False
        warnings.append(
            t(
                "{count} optionale AP-Datensätze gehörten zu keinem aktuellen CAPWAP-AP.",
                count=unmatched_optional,
            )
        )
    if invalid_radio:
        complete = False
        warnings.append(
            t("{count} Radio-Datensätze besaßen keine gültige Slot-ID.", count=invalid_radio)
        )
    items.sort(key=lambda item: (item["name"].casefold(), item.get("mac") or ""))
    return CollectionResult(items=items, complete=complete, warnings=warnings)


def _normalise_clients(payload: Mapping[str, Any]) -> CollectionResult:
    if not _contains_key(payload, "client-oper-data"):
        raise WlanProtocolError(t("Die YANG-Antwort enthält keine Client-Daten."))

    client_mac_aliases = (
        "client-mac",
        "client-mac-address",
        "ms-mac-address",
        "station-mac",
        "sta-mac",
        "mac-addr",
        "mac",
    )
    groups: OrderedDict[str, list[Mapping[str, Any]]] = OrderedDict()
    invalid_identifiers = 0
    for record in _records_for_container(
        payload, "common-oper-data", client_mac_aliases
    ):
        mac = _normalise_mac(_first_across([record], client_mac_aliases))
        if not mac:
            invalid_identifiers += 1
            continue
        groups.setdefault(mac, []).append(record)

    unmatched_optional = 0
    for container in ("dot11-oper-data", "traffic-stats", "sisf-db-mac", "policy-data"):
        for record in _records_for_container(payload, container, client_mac_aliases):
            mac = _normalise_mac(_first_across([record], client_mac_aliases))
            if not mac or mac not in groups:
                unmatched_optional += 1
                continue
            groups[mac].append(record)

    items: list[dict[str, Any]] = []
    for mac, records in groups.items():
        first = _field_reader(records)
        connected_seconds = _integer(
            first(("connected-seconds", "session-duration", "client-uptime", "uptime"))
        )
        if connected_seconds is None:
            connected_seconds = _seconds_since(first(("ms-assoc-time", "association-time")))
        item = WirelessClient(
            mac=mac,
            ip=_normalise_ip(
                first(
                    (
                        "client-ip-address",
                        "client-ip-addr",
                        "ms-ip-address",
                        "ip-addr",
                        "ip-address",
                    ),
                )
            ),
            username=_string(
                first(("username", "ms-username", "user-name", "client-username"))
            ),
            hostname=_string(
                first(("device-hostname", "hostname", "host-name", "device-name"))
            ),
            ap_name=_string(first(("ap-name", "wtp-name"))),
            ap_mac=_normalise_mac(
                first(("ap-mac", "ap-mac-address", "ap-mac-addr", "wtp-mac"))
            ),
            ssid=_string(first(("vap-ssid", "wlan-ssid", "ssid"))),
            wlan_id=_number_or_string(
                first(("wlan-id", "ms-wlan-id", "vap-id"))
            ),
            vlan=_number_or_string(
                first(("vlan-id", "res-vlan-id", "vlan", "client-vlan"))
            ),
            band=_normalise_enum(
                first(("ms-radio-type", "current-band-id", "radio-band", "band", "radio-type"))
            ),
            channel=_number_or_string(
                first(("current-channel", "channel-number", "channel"))
            ),
            rssi=_integer(first(("current-rssi", "most-recent-rssi", "rssi"))),
            snr=_integer(first(("current-snr", "most-recent-snr", "snr"))),
            state=_normalise_enum(
                first(("co-state", "client-state", "mobility-state", "association-state", "state"))
            ),
            connected_seconds=connected_seconds,
        ).to_dict()
        items.append(item)

    warnings = []
    complete = invalid_identifiers == 0
    if invalid_identifiers:
        warnings.append(
            t(
                "{count} Common-Client-Datensätze enthielten keine gültige MAC-Adresse.",
                count=invalid_identifiers,
            )
        )
    if unmatched_optional:
        complete = False
        warnings.append(
            t(
                "{count} optionale Client-Datensätze gehörten zu keinem aktuell verbundenen Client.",
                count=unmatched_optional,
            )
        )
    items.sort(key=lambda item: (item.get("ap_name") or "", item["mac"]))
    return CollectionResult(items=items, complete=complete, warnings=warnings)


class Catalyst9800Adapter(WlanControllerAdapter):
    """Liest Catalyst-9800-Oper-Daten per HTTPS/RESTCONF."""

    platform = PLATFORM_CATALYST_9800
    transport = TRANSPORT_RESTCONF
    label = "RESTCONF (HTTPS)"
    default_port = 443

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        client_factory: Callable[..., httpx.Client] = httpx.Client,
    ):
        self._transport = transport
        self._client_factory = client_factory

    @staticmethod
    def _base_url(controller: Mapping[str, Any]) -> str:
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
            ip = ipaddress.ip_address(host)
        except ValueError:
            try:
                ascii_host = host.rstrip(".").encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise WlanConfigurationError(
                    t("Der konfigurierte WLAN-Controller-Host ist ungültig.")
                ) from exc
            if len(ascii_host) > 253 or not ascii_host:
                raise WlanConfigurationError(
                    t("Der konfigurierte WLAN-Controller-Host ist ungültig.")
                ) from None
            labels = ascii_host.split(".")
            if any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels
            ):
                raise WlanConfigurationError(
                    t("Der konfigurierte WLAN-Controller-Host ist ungültig.")
                ) from None
            url_host = ascii_host
        else:
            url_host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed

        port_value = controller.get("port", 443)
        if isinstance(port_value, bool):
            raise WlanConfigurationError(t("Der RESTCONF-Port muss zwischen 1 und 65535 liegen."))
        try:
            port = int(port_value)
        except (TypeError, ValueError):
            raise WlanConfigurationError(
                t("Der RESTCONF-Port muss zwischen 1 und 65535 liegen.")
            ) from None
        if not 1 <= port <= 65_535:
            raise WlanConfigurationError(t("Der RESTCONF-Port muss zwischen 1 und 65535 liegen."))
        return f"https://{url_host}:{port}"

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
    def _tls_context() -> ssl.SSLContext:
        ca_file = config.settings.wireless_restconf_ca_cert_file
        if ca_file:
            path = Path(ca_file)
            if not path.is_file():
                raise WlanConfigurationError(
                    t("Die konfigurierte CA-Datei für RESTCONF ist nicht lesbar.")
                )
            try:
                context = ssl.create_default_context(cafile=str(path))
            except (OSError, ssl.SSLError):
                raise WlanConfigurationError(
                    t("Die konfigurierte CA-Datei für RESTCONF ist ungültig.")
                ) from None
        else:
            context = ssl.create_default_context()
        # Explizit setzen, damit auch spaetere Refactorings nie versehentlich einen
        # permissiven SSLContext weiterverwenden.
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    @classmethod
    def _tls_verification(cls) -> bool | ssl.SSLContext:
        if config.settings.wireless_allow_unverified_restconf_tls:
            return False
        return cls._tls_context()

    @staticmethod
    def _is_tls_error(exc: BaseException) -> bool:
        current: BaseException | None = exc
        visited: set[int] = set()
        while current is not None and id(current) not in visited:
            visited.add(id(current))
            if isinstance(current, ssl.SSLError):
                return True
            text = str(current).casefold()
            if any(
                marker in text
                for marker in (
                    "certificate verify failed",
                    "certificate_verify_failed",
                    "ssl: certificate",
                    "tlsv1 alert",
                )
            ):
                return True
            current = current.__cause__ or current.__context__
        return False

    def _client_options(self, credentials: Mapping[str, Any]) -> dict[str, Any]:
        username, password = self._plaintext_credentials(credentials)
        connect_timeout = float(config.settings.wireless_connect_timeout_seconds)
        read_timeout = float(config.settings.wireless_read_timeout_seconds)
        if connect_timeout <= 0 or read_timeout <= 0:
            raise WlanConfigurationError(
                t("Die RESTCONF-Laufzeitparameter sind ungültig.")
            )

        options: dict[str, Any] = {
            "auth": httpx.BasicAuth(username, password),
            "verify": self._tls_verification(),
            "timeout": httpx.Timeout(
                connect=connect_timeout,
                read=read_timeout,
                write=read_timeout,
                pool=connect_timeout,
            ),
            "follow_redirects": False,
            "trust_env": False,
        }
        if self._transport is not None:
            options["transport"] = self._transport
        return options

    def _request_json(
        self,
        controller: Mapping[str, Any],
        credentials: Mapping[str, Any],
        path: str,
        *,
        client: httpx.Client | None = None,
    ) -> dict[str, Any]:
        if not path.startswith("/restconf/") or "://" in path:
            raise WlanConfigurationError(t("Interner RESTCONF-Pfad ist ungültig."))
        base_url = self._base_url(controller)
        logger.info("RESTCONF GET %s on controller %s", path, controller.get("name"))
        max_response_bytes = int(config.settings.wireless_max_response_bytes)
        if max_response_bytes <= 0:
            raise WlanConfigurationError(t("Die RESTCONF-Laufzeitparameter sind ungültig."))

        client_context = (
            nullcontext(client)
            if client is not None
            else self._client_factory(**self._client_options(credentials))
        )

        try:
            with client_context as request_client:
                with request_client.stream(
                    "GET",
                    f"{base_url}{path}",
                    headers={"Accept": "application/yang-data+json"},
                ) as response:
                    if response.status_code in {401, 403}:
                        raise WlanAuthenticationError(
                            t("RESTCONF-Authentifizierung oder Leseberechtigung fehlgeschlagen.")
                        )
                    if 300 <= response.status_code < 400:
                        raise WlanProtocolError(
                            t("Der WLAN-Controller hat einen nicht erlaubten HTTP-Redirect geliefert.")
                        )
                    if response.status_code == 204:
                        raise _RestconfNoContent(
                            t("Der RESTCONF-Endpunkt hat keinen Antwortinhalt geliefert.")
                        )
                    if response.status_code >= 500:
                        raise WlanConnectionError(
                            t("Der RESTCONF-Dienst des WLAN-Controllers meldet einen Serverfehler.")
                        )
                    if response.status_code >= 400 and response.status_code != 404:
                        raise WlanProtocolError(
                            t(
                                "Der RESTCONF-Dienst hat HTTP-Status {status} geliefert.",
                                status=response.status_code,
                            )
                        )

                    content_length = response.headers.get("content-length")
                    if content_length:
                        try:
                            declared_size = int(content_length)
                        except ValueError:
                            declared_size = 0
                        if declared_size > max_response_bytes:
                            raise WlanProtocolError(
                                t("Die RESTCONF-Antwort überschreitet das konfigurierte Größenlimit.")
                            )

                    chunks = bytearray()
                    deadline = time.monotonic() + float(config.settings.wireless_read_timeout_seconds)
                    for chunk in response.iter_bytes():
                        if time.monotonic() >= deadline:
                            raise WlanConnectionError(
                                t("Zeitüberschreitung beim Lesen der RESTCONF-Antwort.")
                            )
                        if len(chunks) + len(chunk) > max_response_bytes:
                            raise WlanProtocolError(
                                t("Die RESTCONF-Antwort überschreitet das konfigurierte Größenlimit.")
                            )
                        chunks.extend(chunk)

                    if response.status_code == 404:
                        error_tags = _restconf_error_tags(chunks)
                        if "access-denied" in error_tags:
                            raise WlanAuthenticationError(
                                t("RESTCONF-Authentifizierung oder Leseberechtigung fehlgeschlagen.")
                            )
                        if "data-missing" in error_tags:
                            raise _RestconfNotFound(
                                t("Die bekannte RESTCONF-Collection enthält keine Daten.")
                            )
                        raise WlanCapabilityError(
                            t("Der RESTCONF-Endpunkt ist nicht verfügbar oder durch Leserechte verborgen.")
                        )
        except WlanError:
            raise
        except httpx.TimeoutException:
            raise WlanConnectionError(
                t("Zeitüberschreitung bei der RESTCONF-Verbindung zum WLAN-Controller.")
            ) from None
        except httpx.ConnectError as exc:
            if self._is_tls_error(exc):
                raise WlanTlsError(
                    t("Der TLS-Verbindungsaufbau zum WLAN-Controller ist fehlgeschlagen.")
                ) from None
            raise WlanConnectionError(
                t("Der RESTCONF-Dienst des WLAN-Controllers ist nicht erreichbar.")
            ) from None
        except httpx.HTTPError as exc:
            logger.warning(
                "RESTCONF transport failed for controller id=%s (%s)",
                controller.get("id"),
                type(exc).__name__,
            )
            raise WlanConnectionError(
                t("Die RESTCONF-Kommunikation mit dem WLAN-Controller ist fehlgeschlagen.")
            ) from None

        if not chunks:
            raise WlanProtocolError(t("Der WLAN-Controller hat eine leere RESTCONF-Antwort geliefert."))
        payload = _decode_json(chunks)
        if not isinstance(payload, dict):
            raise WlanProtocolError(t("Die YANG-JSON-Antwort besitzt kein gültiges Wurzelobjekt."))
        return payload

    def _discover_modules(
        self,
        controller: Mapping[str, Any],
        credentials: Mapping[str, Any],
        *,
        client: httpx.Client | None = None,
    ) -> dict[str, str | None]:
        payload = self._request_json(
            controller,
            credentials,
            YANG_LIBRARY_PATH,
            client=client,
        )
        modules: dict[str, str | None] = {}

        def visit(value: Any) -> None:
            if isinstance(value, Mapping):
                for key, child in value.items():
                    if _key_token(key) == "module" and isinstance(child, (list, Mapping)):
                        entries = child if isinstance(child, list) else [child]
                        for entry in entries:
                            if not isinstance(entry, Mapping):
                                continue
                            values = _leaf_map(entry)
                            name = _string(_first_in_map(values, ("name",)))
                            revision = _string(_first_in_map(values, ("revision",)))
                            if name:
                                modules[name] = revision
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(payload)
        if not modules:
            raise WlanProtocolError(
                t("Die YANG-Library des Controllers enthält keine lesbaren Module.")
            )
        return modules

    @staticmethod
    def _require_module(modules: Mapping[str, str | None], module: str) -> None:
        if module not in modules:
            raise WlanCapabilityError(
                t("Der Controller stellt das benötigte YANG-Modul {module} nicht bereit.", module=module)
            )

    def _read_subtrees(
        self,
        controller: Mapping[str, Any],
        credentials: Mapping[str, Any],
        modules: Mapping[str, str | None],
        module: str,
        root_path: str,
        root_name: str,
        subtrees: tuple[tuple[str, bool], ...],
        *,
        client: httpx.Client | None = None,
    ) -> tuple[dict[str, Any], list[str], bool]:
        combined: dict[str, Any] = {root_name: {}}
        warnings: list[str] = []
        complete = True
        for subtree, required in subtrees:
            restricted = False
            try:
                records, absent = self._read_collection(
                    controller,
                    credentials,
                    modules,
                    module,
                    root_path,
                    subtree,
                    client=client,
                )
            except WlanAuthenticationError:
                if required:
                    raise
                records, absent, restricted = [], True, True
            combined[root_name][subtree] = records
            if absent:
                complete = False
                if required and restricted:
                    warning = t("Der erforderliche YANG-Teilbaum {subtree} konnte nicht gelesen werden.", subtree=subtree)
                elif required:
                    warning = t("Der erforderliche YANG-Teilbaum {subtree} hat keine Daten geliefert.", subtree=subtree)
                elif restricted:
                    warning = t("Der optionale YANG-Teilbaum {subtree} konnte nicht gelesen werden.", subtree=subtree)
                else:
                    warning = t("Der optionale YANG-Teilbaum {subtree} hat keine Daten geliefert.", subtree=subtree)
                warnings.append(warning)
        return combined, warnings, complete

    def _read_collection(
        self,
        controller: Mapping[str, Any],
        credentials: Mapping[str, Any],
        modules: Mapping[str, str | None],
        module: str,
        root_path: str,
        subtree: str,
        *,
        client: httpx.Client | None = None,
    ) -> tuple[list[Mapping[str, Any]], bool]:
        """Liest genau eine bekannte YANG-List-Collection.

        IOS XE liefert fuer eine leere Collection je nach RESTCONF-Revision eine
        leere Liste, HTTP 204 oder HTTP 404. Nur hier -- nach erfolgreicher
        Modulpruefung und fuer einen fest codierten Collection-Pfad -- werden 204
        und 404 als leer interpretiert.
        """

        self._require_module(modules, module)
        try:
            payload = self._request_json(
                controller,
                credentials,
                f"{root_path}/{subtree}",
                client=client,
            )
        except (_RestconfNotFound, _RestconfNoContent):
            return [], True
        return _extract_collection_payload(payload, module, subtree), False

    def test_connection(self, controller: dict, credentials: dict) -> dict:
        try:
            with self._client_factory(**self._client_options(credentials)) as client:
                modules = self._discover_modules(
                    controller,
                    credentials,
                    client=client,
                )
                missing = sorted(REQUIRED_MODULES.difference(modules))
                if missing:
                    raise WlanCapabilityError(
                        t(
                            "Dem Controller fehlen benötigte WLAN-YANG-Module: {modules}",
                            modules=", ".join(missing),
                        )
                    )
                _, access_points_absent = self._read_collection(
                    controller,
                    credentials,
                    modules,
                    AP_MODULE,
                    ACCESS_POINTS_ROOT,
                    "capwap-data",
                    client=client,
                )
                _, clients_absent = self._read_collection(
                    controller,
                    credentials,
                    modules,
                    CLIENT_MODULE,
                    CLIENTS_ROOT,
                    "common-oper-data",
                    client=client,
                )
        except WlanError as exc:
            logger.warning(
                "WLAN connection test failed for controller id=%s (%s)",
                controller.get("id"),
                exc.code,
            )
            return {"ok": False, "message": exc.message, "error": exc.code}

        return {
            "ok": True,
            "message": (
                t("RESTCONF, WLAN-YANG-Module und Pflichtendpunkte sind verfügbar.")
                if not access_points_absent and not clients_absent
                else t(
                    "RESTCONF und WLAN-YANG-Module sind verfügbar; mindestens "
                    "eine Pflicht-Collection war leer oder nicht als Ressource sichtbar."
                )
            ),
            "platform": self.platform,
            "capabilities": {
                "restconf": True,
                "yang_library": True,
                "access_points": not access_points_absent,
                "clients": not clients_absent,
                "module_revisions": {
                    module: modules.get(module) for module in sorted(REQUIRED_MODULES)
                },
            },
        }

    def list_access_points(self, controller: dict, credentials: dict) -> CollectionResult:
        with self._client_factory(**self._client_options(credentials)) as client:
            modules = self._discover_modules(
                controller,
                credentials,
                client=client,
            )
            self._require_module(modules, AP_MODULE)
            payload, warnings, complete = self._read_subtrees(
                controller,
                credentials,
                modules,
                AP_MODULE,
                ACCESS_POINTS_ROOT,
                "access-point-oper-data",
                AP_SUBTREES,
                client=client,
            )
        result = _normalise_access_points(payload)
        result.complete = result.complete and complete
        result.warnings = warnings + result.warnings
        return result

    def list_clients(self, controller: dict, credentials: dict) -> CollectionResult:
        with self._client_factory(**self._client_options(credentials)) as client:
            modules = self._discover_modules(
                controller,
                credentials,
                client=client,
            )
            self._require_module(modules, CLIENT_MODULE)
            payload, warnings, complete = self._read_subtrees(
                controller,
                credentials,
                modules,
                CLIENT_MODULE,
                CLIENTS_ROOT,
                "client-oper-data",
                CLIENT_SUBTREES,
                client=client,
            )
        result = _normalise_clients(payload)
        result.complete = result.complete and complete
        result.warnings = warnings + result.warnings
        return result
