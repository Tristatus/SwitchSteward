"""Plattformunabhaengiger WLAN-Service mit Filterung und kurzem Snapshot-Cache."""

from __future__ import annotations

import copy
import hashlib
import threading
import time
import weakref
from dataclasses import dataclass
from typing import Any

from ..config import settings
from ..i18n import current_language, t
from .adapters.base import WlanControllerAdapter
from .adapters.catalyst_9800 import Catalyst9800Adapter
from .adapters.catalyst_9800_netconf import Catalyst9800NetconfAdapter
from .models import (
    PLATFORM_CATALYST_9800,
    TRANSPORT_NETCONF,
    TRANSPORT_RESTCONF,
    CollectionResult,
    UnsupportedPlatformError,
    WlanConfigurationError,
    WlanError,
)

_DEFAULT_CACHE_TTL_SECONDS = 30
_MAX_PAGE_SIZE = 1_000
_MIN_REFRESH_INTERVAL_SECONDS = 2.0
_FAILURE_CACHE_TTL_SECONDS = 2.0
# (controller_id, resource, connection fingerprint, UI language): adapters
# translate warnings/errors at creation, so cached texts are per language.
_CacheKey = tuple[Any, str, str, str]


@dataclass(slots=True)
class _CacheEntry:
    result: CollectionResult
    expires_at: float
    stored_at: float


@dataclass(slots=True)
class _FailureEntry:
    error_type: type[WlanError]
    message: str
    expires_at: float
    stored_at: float


class _SnapshotCache:
    """Kleiner In-Memory-TTL-Cache; alle Zugaenge sind durch ein RLock geschuetzt."""

    def __init__(self, monotonic=time.monotonic):
        self._monotonic = monotonic
        self._entries: dict[_CacheKey, _CacheEntry] = {}
        self._failures: dict[_CacheKey, _FailureEntry] = {}
        # A running/waiting fetch keeps its lock alive. Completed requests must
        # not retain a lock for every historical endpoint/credential version.
        self._fetch_locks = weakref.WeakValueDictionary()
        self._global_generation = 0
        self._controller_generations: dict[Any, int] = {}
        self._lock = threading.RLock()

    def now(self) -> float:
        return self._monotonic()

    def get(
        self,
        key: _CacheKey,
        *,
        stored_since: float | None = None,
    ) -> CollectionResult | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at <= self._monotonic():
                del self._entries[key]
                return None
            if stored_since is not None and entry.stored_at < stored_since:
                return None
            result = entry.result
        # Stored snapshots are never mutated. Copy outside the global lock so a
        # large client inventory does not block reads for unrelated controllers.
        return copy.deepcopy(result)

    def get_failure(
        self,
        key: _CacheKey,
        *,
        stored_since: float | None = None,
    ) -> WlanError | None:
        """Liefert eine neue Exception-Instanz fuer einen kuerzlich gescheiterten Abruf."""

        with self._lock:
            entry = self._failures.get(key)
            if entry is None:
                return None
            if entry.expires_at <= self._monotonic():
                del self._failures[key]
                return None
            if stored_since is not None and entry.stored_at < stored_since:
                return None
            # Tracebacks und mutable Exception-Objekte werden nicht zwischen
            # Request-Threads geteilt. Die Meldungen der WLAN-Fehler enthalten
            # bewusst weder Zugangsdaten noch Controller-Payloads.
            return entry.error_type(entry.message)

    def generation(self, key: _CacheKey) -> tuple[int, int]:
        with self._lock:
            return (
                self._global_generation,
                self._controller_generations.get(key[0], 0),
            )

    def put(
        self,
        key: _CacheKey,
        result: CollectionResult,
        ttl_seconds: float,
        *,
        generation: tuple[int, int],
    ) -> bool:
        snapshot = copy.deepcopy(result)
        with self._lock:
            if generation != (
                self._global_generation,
                self._controller_generations.get(key[0], 0),
            ):
                return False
            now = self._monotonic()
            self._prune_expired(now)
            self._entries[key] = _CacheEntry(
                result=snapshot,
                expires_at=now + ttl_seconds,
                stored_at=now,
            )
            self._failures.pop(key, None)
            return True

    def put_failure(
        self,
        key: _CacheKey,
        error: WlanError,
        ttl_seconds: float,
        *,
        generation: tuple[int, int],
    ) -> bool:
        with self._lock:
            if generation != (
                self._global_generation,
                self._controller_generations.get(key[0], 0),
            ):
                return False
            now = self._monotonic()
            self._prune_expired(now)
            self._failures[key] = _FailureEntry(
                error_type=type(error),
                message=error.message,
                expires_at=now + ttl_seconds,
                stored_at=now,
            )
            return True

    def _prune_expired(self, now: float) -> None:
        # Also remove expired snapshots whose controller is no longer queried.
        for entries in (self._entries, self._failures):
            for key in list(entries):
                if entries[key].expires_at <= now:
                    del entries[key]

    def fetch_lock(self, key: _CacheKey) -> threading.Lock:
        with self._lock:
            return self._fetch_locks.setdefault(key, threading.Lock())

    def clear(self, controller_id: Any | None = None) -> None:
        with self._lock:
            if controller_id is None:
                self._global_generation += 1
                self._entries.clear()
                self._failures.clear()
                self._controller_generations.clear()
                return
            self._controller_generations[controller_id] = (
                self._controller_generations.get(controller_id, 0) + 1
            )
            for key in list(self._entries):
                if key[0] == controller_id:
                    del self._entries[key]
            for key in list(self._failures):
                if key[0] == controller_id:
                    del self._failures[key]


_ADAPTER_CLASSES: tuple[type[WlanControllerAdapter], ...] = (Catalyst9800Adapter, Catalyst9800NetconfAdapter)
_PLATFORM_LABELS = {PLATFORM_CATALYST_9800: "Cisco Catalyst 9800"}
_ADAPTERS: dict[tuple[str, str], WlanControllerAdapter] = {
    (adapter_class.platform, adapter_class.transport): adapter_class() for adapter_class in _ADAPTER_CLASSES
}
_CACHE = _SnapshotCache()


def platform_catalog() -> list[dict[str, Any]]:
    """Builds the platform/transport catalog from the registered adapter classes."""

    catalog: dict[str, dict[str, Any]] = {}
    for adapter_class in _ADAPTER_CLASSES:
        entry = catalog.setdefault(
            adapter_class.platform,
            {"id": adapter_class.platform, "label": _PLATFORM_LABELS[adapter_class.platform], "transports": []},
        )
        entry["transports"].append(
            {"id": adapter_class.transport, "label": adapter_class.label, "default_port": adapter_class.default_port}
        )
    return list(catalog.values())


def _cache_ttl_seconds() -> float:
    value = getattr(settings, "wireless_cache_ttl_seconds", _DEFAULT_CACHE_TTL_SECONDS)
    try:
        ttl = float(value)
    except (TypeError, ValueError):
        raise WlanConfigurationError(t("Die WLAN-Cache-Laufzeit ist ungültig.")) from None
    if ttl <= 0:
        raise WlanConfigurationError(t("Die WLAN-Cache-Laufzeit muss größer als null sein."))
    return ttl


def adapter_for(controller: dict) -> WlanControllerAdapter:
    platform = controller.get("platform")
    if not isinstance(platform, str) or not platform.strip():
        raise WlanConfigurationError(t("Für den WLAN-Controller ist keine Plattform hinterlegt."))
    normalized = platform.strip().casefold()
    transport = controller.get("transport", TRANSPORT_RESTCONF)
    if not isinstance(transport, str) or not transport.strip():
        raise WlanConfigurationError(
            t("Für den WLAN-Controller ist kein Transport hinterlegt.")
        )
    normalized_transport = transport.strip().casefold()
    if normalized_transport not in {TRANSPORT_RESTCONF, TRANSPORT_NETCONF}:
        raise WlanConfigurationError(
            t("Der WLAN-Transport {transport} wird nicht unterstützt.", transport=repr(transport))
        )
    adapter = _ADAPTERS.get((normalized, normalized_transport))
    if adapter is None:
        raise UnsupportedPlatformError(
            t(
                "Die WLAN-Controller-Plattform {platform} wird mit {transport} noch nicht unterstützt.",
                platform=repr(platform),
                transport=normalized_transport.upper(),
            )
        )
    return adapter


def _controller_id(controller: dict) -> Any:
    controller_id = controller.get("id")
    if controller_id is None or isinstance(controller_id, bool):
        raise WlanConfigurationError(t("Der WLAN-Controller besitzt keine gültige ID."))
    try:
        hash(controller_id)
    except TypeError:
        raise WlanConfigurationError(t("Der WLAN-Controller besitzt keine gültige ID.")) from None
    return controller_id


def _cache_fingerprint(controller: dict, credentials: dict) -> str:
    """Bindet einen Snapshot an Endpoint und Credential-Version, nie an Klartext."""

    digest = hashlib.sha256()
    values = (
        controller.get("platform"),
        controller.get("transport", TRANSPORT_RESTCONF),
        controller.get("host"),
        controller.get("port"),
        credentials.get("username"),
        credentials.get("password_enc"),
    )
    for value in values:
        if isinstance(value, memoryview):
            encoded = value.tobytes()
        elif isinstance(value, bytes):
            encoded = value
        else:
            encoded = str(value).encode("utf-8", errors="surrogatepass")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _validate_pagination(offset: int, limit: int) -> tuple[int, int]:
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise WlanConfigurationError(t("offset muss eine nichtnegative ganze Zahl sein."))
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_PAGE_SIZE:
        raise WlanConfigurationError(t("limit muss zwischen 1 und {max} liegen.", max=_MAX_PAGE_SIZE))
    return offset, limit


def _normalise_filter(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise WlanConfigurationError(t("{name} muss eine Zeichenkette sein.", name=name))
    value = value.strip()
    return value.casefold() if value else None


def _search_values(value: Any):
    if isinstance(value, dict):
        for child in value.values():
            yield from _search_values(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _search_values(child)
    elif value is not None:
        yield str(value).casefold()


def _matches_query(item: dict[str, Any], query: str | None) -> bool:
    return query is None or any(query in value for value in _search_values(item))


def _load_snapshot(
    controller: dict,
    credentials: dict,
    resource: str,
    *,
    refresh: bool,
) -> tuple[CollectionResult, bool]:
    controller_id = _controller_id(controller)
    key = (controller_id, resource, _cache_fingerprint(controller, credentials), current_language.get())
    request_started = _CACHE.now()
    refresh_cutoff = request_started - _MIN_REFRESH_INTERVAL_SECONDS
    if refresh:
        cached = _CACHE.get(key, stored_since=refresh_cutoff)
        failure = _CACHE.get_failure(key, stored_since=refresh_cutoff)
        if cached is not None:
            return cached, True
    else:
        cached = _CACHE.get(key)
        failure = _CACHE.get_failure(key)
        if cached is not None:
            return cached, True
    if failure is not None:
        raise failure

    # Der ressourcenspezifische Lock verhindert, dass parallele Browser-Requests
    # denselben grossen Controller-Snapshot mehrfach gleichzeitig abrufen.
    with _CACHE.fetch_lock(key):
        if refresh:
            cached = _CACHE.get(key, stored_since=refresh_cutoff)
            failure = _CACHE.get_failure(key, stored_since=refresh_cutoff)
            if cached is not None:
                return cached, True
        else:
            cached = _CACHE.get(key)
            failure = _CACHE.get_failure(key)
            if cached is not None:
                return cached, True
        if failure is not None:
            raise failure
        generation = _CACHE.generation(key)
        adapter = adapter_for(controller)
        try:
            if resource == "access_points":
                result = adapter.list_access_points(controller, credentials)
            elif resource == "clients":
                result = adapter.list_clients(controller, credentials)
            else:  # ausschliesslich ein interner Programmierfehler
                raise RuntimeError(f"Unbekannte WLAN-Ressource: {resource}")
        except WlanError as exc:
            _CACHE.put_failure(
                key,
                exc,
                _FAILURE_CACHE_TTL_SECONDS,
                generation=generation,
            )
            raise
        if not isinstance(result, CollectionResult):
            raise RuntimeError("WLAN-Adapter hat keinen CollectionResult geliefert.")
        _CACHE.put(
            key,
            result,
            _cache_ttl_seconds(),
            generation=generation,
        )
        return copy.deepcopy(result), False


def _envelope(
    result: CollectionResult,
    items: list[dict[str, Any]],
    *,
    offset: int,
    limit: int,
    cached: bool,
) -> dict[str, Any]:
    return {
        "items": copy.deepcopy(items[offset : offset + limit]),
        "total": len(items),
        "offset": offset,
        "limit": limit,
        "collected_at": result.collected_at,
        "complete": result.complete,
        "warnings": list(result.warnings),
        "cached": cached,
    }


def check_connection(controller: dict, credentials: dict) -> dict:
    """Prueft den konfigurierten Transport, Anmeldung und benoetigte YANG-Module."""

    return adapter_for(controller).test_connection(controller, credentials)


def list_access_points(
    controller: dict,
    credentials: dict,
    *,
    q: str | None = None,
    status: str | None = None,
    offset: int = 0,
    limit: int = 100,
    refresh: bool = False,
) -> dict[str, Any]:
    """Liest, filtert und paginiert Access Points eines Controllers."""

    offset, limit = _validate_pagination(offset, limit)
    query = _normalise_filter(q, "q")
    status_filter = _normalise_filter(status, "status")
    result, cached = _load_snapshot(
        controller, credentials, "access_points", refresh=bool(refresh)
    )
    items = [
        item
        for item in result.items
        if _matches_query(item, query)
        and (
            status_filter is None
            or str(item.get("status") or "").casefold() == status_filter
        )
    ]
    return _envelope(result, items, offset=offset, limit=limit, cached=cached)


def list_clients(
    controller: dict,
    credentials: dict,
    *,
    q: str | None = None,
    ap: str | None = None,
    ssid: str | None = None,
    offset: int = 0,
    limit: int = 100,
    refresh: bool = False,
) -> dict[str, Any]:
    """Liest, filtert und paginiert aktuell verbundene WLAN-Clients."""

    offset, limit = _validate_pagination(offset, limit)
    query = _normalise_filter(q, "q")
    ap_filter = _normalise_filter(ap, "ap")
    ssid_filter = _normalise_filter(ssid, "ssid")
    result, cached = _load_snapshot(controller, credentials, "clients", refresh=bool(refresh))
    items = [
        item
        for item in result.items
        if _matches_query(item, query)
        and (
            ap_filter is None
            or ap_filter
            in {
                str(item.get("ap_name") or "").casefold(),
                str(item.get("ap_mac") or "").casefold(),
            }
        )
        and (ssid_filter is None or str(item.get("ssid") or "").casefold() == ssid_filter)
    ]
    return _envelope(result, items, offset=offset, limit=limit, cached=cached)


def clear_cache(controller_id: Any | None = None) -> None:
    """Invalidiert alle Snapshots oder diejenigen eines geaenderten Controllers."""

    _CACHE.clear(controller_id)
