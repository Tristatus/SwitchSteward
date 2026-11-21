"""Abstrakter Vertrag fuer WLAN-Controller-Adapter."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ...i18n import t
from ..models import CollectionResult, WlanCapabilityError, utc_timestamp


class WlanControllerAdapter(ABC):
    """Jede Controllerfamilie wird hinter diesem Vertrag normalisiert."""

    # Registry/catalog metadata; service.platform_catalog() is derived from these.
    platform: str
    transport: str
    label: str
    default_port: int

    @abstractmethod
    def test_connection(self, controller: dict, credentials: dict) -> dict:
        """Prueft Transport, Anmeldung und benoetigte Datenmodelle."""

    @abstractmethod
    def list_access_points(self, controller: dict, credentials: dict) -> CollectionResult:
        """Liefert einen vollstaendigen, ungefilterten AP-Snapshot."""

    @abstractmethod
    def list_clients(self, controller: dict, credentials: dict) -> CollectionResult:
        """Liefert einen vollstaendigen, ungefilterten Client-Snapshot."""

    def get_configuration(self, controller: dict, credentials: dict) -> dict:
        """Existing monitoring adapters remain usable without write support."""
        return {
            "capabilities": {
                "supported_resources": [],
                "writable_running": False,
                "reason": t(
                    "Gerätekonfiguration steht für diesen Transport nicht zur Verfügung. NETCONF verwenden."
                ),
            },
            "device": {}, "collections": {}, "access_points": [], "catalog": [],
            "warnings": [], "complete": False, "collected_at": utc_timestamp(),
        }

    def apply_configuration(
        self, controller: dict, credentials: dict, change: dict, expected_revision: str,
    ) -> dict:
        raise WlanCapabilityError(t("Dieser Controlleradapter unterstützt keine Konfigurationsänderungen."))
