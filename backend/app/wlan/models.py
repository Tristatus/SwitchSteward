"""Gemeinsame Datenmodelle und Fehler der WLAN-Integrationsschicht."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

PLATFORM_CATALYST_9800 = "catalyst_9800"
TRANSPORT_RESTCONF = "restconf"
TRANSPORT_NETCONF = "netconf"


class WlanError(Exception):
    """Basisklasse fuer erwartbare Fehler bei WLAN-Abfragen."""

    code = "wlan_error"

    def __init__(self, message: str, *, detail: str | None = None):
        super().__init__(message)
        self.message = message
        # ``detail`` ist ausschliesslich fuer das Server-Log gedacht. Darin duerfen
        # weder Passwoerter noch vollstaendige Antwort-Payloads abgelegt werden.
        self.detail = detail


class UnsupportedPlatformError(WlanError):
    code = "unsupported_platform"


class WlanConfigurationError(WlanError):
    code = "invalid_configuration"


class WlanConnectionError(WlanError):
    code = "connection_failed"


class WlanAuthenticationError(WlanError):
    code = "authentication_failed"


class WlanTlsError(WlanConnectionError):
    code = "tls_failed"


class WlanProtocolError(WlanError):
    code = "invalid_response"


class WlanCapabilityError(WlanError):
    code = "missing_capability"


def utc_timestamp() -> str:
    """UTC-Zeitstempel im API-freundlichen RFC-3339-Format."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(slots=True)
class AccessPoint:
    """Kleinster gemeinsamer AP-Datensatz ueber Controllerfamilien hinweg."""

    name: str
    mac: str | None = None
    ip: str | None = None
    status: str = "unknown"
    model: str | None = None
    serial_number: str | None = None
    location: str | None = None
    site_tag: str | None = None
    policy_tag: str | None = None
    rf_tag: str | None = None
    uptime_seconds: int | None = None
    client_count: int | None = None
    radios: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "mac": self.mac,
            "ip": self.ip,
            "status": self.status,
            "model": self.model,
            "serial_number": self.serial_number,
            "location": self.location,
            "site_tag": self.site_tag,
            "policy_tag": self.policy_tag,
            "rf_tag": self.rf_tag,
            "uptime_seconds": self.uptime_seconds,
            "client_count": self.client_count,
            "radios": self.radios,
        }


@dataclass(slots=True)
class WirelessClient:
    """Normalisierter, aktuell am Controller sichtbarer WLAN-Client."""

    mac: str
    ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    ap_name: str | None = None
    ap_mac: str | None = None
    ssid: str | None = None
    wlan_id: int | str | None = None
    vlan: int | str | None = None
    band: str | None = None
    channel: int | str | None = None
    rssi: int | None = None
    snr: int | None = None
    state: str | None = None
    connected_seconds: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "mac": self.mac,
            "ip": self.ip,
            "username": self.username,
            "hostname": self.hostname,
            "ap_name": self.ap_name,
            "ap_mac": self.ap_mac,
            "ssid": self.ssid,
            "wlan_id": self.wlan_id,
            "vlan": self.vlan,
            "band": self.band,
            "channel": self.channel,
            "rssi": self.rssi,
            "snr": self.snr,
            "state": self.state,
            "connected_seconds": self.connected_seconds,
        }


@dataclass(slots=True)
class CollectionResult:
    """Ungefilterter Snapshot eines Controller-Adapters."""

    items: list[dict[str, Any]]
    collected_at: str = field(default_factory=utc_timestamp)
    complete: bool = True
    warnings: list[str] = field(default_factory=list)
