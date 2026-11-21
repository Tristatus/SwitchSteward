"""Feature IDs and capability resolution: driver ∩ model profile ∩ runtime findings."""

from collections.abc import Mapping
from dataclasses import dataclass, replace

from ..i18n import t
from .catalog import ModelProfile
from .errors import UnsupportedFeatureError

# Order = display order.
FEATURES = (
    "device_summary",
    "poe_budget",
    "interfaces",
    "port_detail",
    "port_description",
    "port_mode",
    "access_vlan",
    "native_vlan",
    "trunk_allowed_vlans",
    "voice_vlan",
    "vlans",
    "vlan_create",
    "vlan_rename",
    "vlan_delete",
    "vlan_voice",
    "vtp",
    "edge_port",
    "speed",
    "duplex",
    "port_state",
    "port_bounce",
    "poe",
    "poe_mode",
    "poe_limit",
    "poe_cycle",
    "errdisable_recovery",
    "neighbors",
    "clients",
    "client_search",
    "save_config",
    "config_backup",
    "config_compare",
    "config_restore",
    "config_rollback",
    "management_path",
    "port_security",
    "port_security_sticky",
    "dot1x",
    "dot1x_host_mode",
    "dot1x_fallback_vlans",
    "stp_guard",
    "storm_control",
    "storm_control_action",
    "dhcp_snooping",
    "arp_inspection",
    "ip_source_guard",
    "lag",
    "stp",
    "stp_mst",
    "device_identity",
    "device_services",
    "device_snmp",
    "device_aaa",
    "device_users",
    "device_ssh",
    "device_l3",
    "acl",
    "qos",
    "qos_voice",
    "firmware",
    "reload",
    "diag_counters",
    "diag_transceivers",
    "cable_test",
    "device_log",
    "environment",
)
POE_FEATURES = ("poe", "poe_mode", "poe_limit", "poe_cycle", "poe_budget")

UNKNOWN_DRIVER_REASON = "Unbekannter Gerätetyp – bitte im Bearbeiten-Dialog einen unterstützten Typ wählen."
NOT_IMPLEMENTED_REASON = "Diese Funktion wird vom Treiber nicht unterstützt."
NO_POE_MODEL_REASON = "Das Modell {model} hat keine PoE-Ports."
UNKNOWN_MODEL_POE_REASON = "Das Modell ist nicht bekannt; PoE-Leistungsprofile bleiben gesperrt."
VTP_CISCO_ONLY_REASON = "VTP ist ein Cisco-Protokoll und wird von diesem Switch-Typ nicht unterstützt."


@dataclass(frozen=True)
class FeatureSupport:
    supported: bool
    reason: str | None = None  # German message ID, translated on output
    options: tuple[str, ...] | None = None
    requires: tuple[str, ...] = ()
    reason_params: tuple[tuple[str, str], ...] = ()

    def message(self) -> str | None:
        return t(self.reason, **dict(self.reason_params)) if self.reason else None

    def error(self, feature: str) -> UnsupportedFeatureError:
        return UnsupportedFeatureError(feature, self.reason or NOT_IMPLEMENTED_REASON, **dict(self.reason_params))


def supported(options: tuple[str, ...] | None = None, requires: tuple[str, ...] = ()) -> FeatureSupport:
    return FeatureSupport(True, options=options, requires=requires)


def unsupported(reason: str, **params) -> FeatureSupport:
    return FeatureSupport(False, reason=reason, reason_params=tuple(sorted(params.items())))


def selected_profile(driver, switch: Mapping) -> ModelProfile | None:
    """Detected model wins over the selected one; unknown IDs count as no profile."""
    if driver is None:
        return None
    return driver.catalog.get(switch.get("detected_model_id")) or driver.catalog.get(switch.get("model_id"))


def resolve(driver, profile: ModelProfile | None, overrides: Mapping[str, str] | None = None) -> dict[str, FeatureSupport]:
    """Effective capabilities for a driver, a model profile and runtime overrides (feature -> reason)."""
    if driver is None:
        return {feature: unsupported(UNKNOWN_DRIVER_REASON) for feature in FEATURES}
    result = {feature: driver.features.get(feature) or unsupported(NOT_IMPLEMENTED_REASON) for feature in FEATURES}
    if profile is not None and profile.poe_standards == ():
        for feature in POE_FEATURES:
            if result[feature].supported:
                result[feature] = unsupported(NO_POE_MODEL_REASON, model=profile.label)
    elif (profile is None or profile.poe_standards is None) and result["poe_limit"].supported:
        result["poe_limit"] = unsupported(UNKNOWN_MODEL_POE_REASON)
    speed = result["speed"]
    if profile is not None and profile.speeds is not None and speed.supported and speed.options is not None:
        result["speed"] = replace(speed, options=tuple(option for option in speed.options if option in profile.speeds))
    for feature, reason in (overrides or {}).items():
        if feature in result and result[feature].supported:
            result[feature] = unsupported(reason)
    return result


def for_switch(driver, switch: Mapping, overrides: Mapping[str, str] | None = None) -> dict[str, FeatureSupport]:
    return resolve(driver, selected_profile(driver, switch), overrides)


def require(capabilities: Mapping[str, FeatureSupport], feature: str) -> FeatureSupport:
    """Return the feature's support or raise ``UnsupportedFeatureError``."""
    support = capabilities[feature]
    if not support.supported:
        raise support.error(feature)
    return support


def to_json(capabilities: Mapping[str, FeatureSupport]) -> dict:
    return {
        feature: {
            "supported": support.supported,
            "reason": support.message(),
            "options": list(support.options) if support.options is not None else None,
            "requires": list(support.requires),
        }
        for feature, support in capabilities.items()
    }
