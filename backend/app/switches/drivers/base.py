"""Driver interface and shared row/snapshot constructors.

Row formats (all drivers):
- interface row (``read_interfaces``): port, description, status, vlan, admin_state
  ("enabled" | "disabled" | "unknown"), link_state ("up" | "down" | "unknown").
- switchport detail (``read_switchports``, keyed by ``interface_key``): see
  ``empty_switchport_detail``; mode is "access" | "trunk" | "routed" | "dynamic" |
  "private-vlan-*" | "unknown", trunk_allowed_vlan is display text.
- PoE port (``read_poe_ports``, keyed by ``interface_key``): see ``empty_poe_detail``.
- neighbor (``read_neighbors``): see ``neighbor_row``.
- client snapshot (``read_client_snapshot``): see ``client_snapshot``.
"""

import re
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, fields
from typing import Any, ClassVar, Literal, TypedDict

from ...i18n import t
from .. import clients
from .. import transport as ssh_transport
from ..catalog import Catalog
from ..errors import UnsupportedFeatureError
from ..features import NOT_IMPLEMENTED_REASON, FeatureSupport
from ..validation import VlanSelection, format_vlan_list
from ..vlans import VlanConstraints
from . import cli
from .plans import (
    AaaChange,
    AclEntry,
    ChangePlan,
    CliCommand,
    CliLines,
    FirmwareImage,
    IdentityChange,
    Pause,
    SecurityChange,
    SecurityGlobalChange,
    ServicesChange,
    SnmpUserChange,
    TransferLocation,
    redact,
)

BROKEN_SESSION_REASON = (
    "Die Verbindung zum Switch ist nach einem Zeitlimit nicht mehr sicher nutzbar; es wurde nichts gesendet. "
    "Bitte erneut versuchen."
)


@dataclass(frozen=True)
class PortChange:
    """Requested port settings; ``None`` leaves a setting unchanged."""

    description: str | None = None  # "" removes the description
    mode: Literal["access", "trunk"] | None = None
    access_vlan: int | None = None
    native_vlan: int | None = None
    trunk_allowed_vlans: VlanSelection | None = None
    voice_vlan: int | None = None  # 0 removes the voice VLAN
    edge_port: bool | None = None
    speed: str | None = None  # option value of feature "speed"
    duplex: str | None = None  # option value of feature "duplex"
    shutdown: bool | None = None
    poe_mode: str | None = None  # "auto" | "static" | "never"
    poe_standard: str | None = None  # "default" or a catalog PoE standard ID

    def audit_items(self) -> list[tuple[str, str]]:
        """Only the fields that are set, in declaration order."""
        items = []
        for field in fields(self):
            value = getattr(self, field.name)
            if value is None:
                continue
            if field.name == "description":
                text = repr(value)
            elif field.name == "trunk_allowed_vlans":
                text = format_vlan_list(value)
            else:
                text = str(value)
            items.append((field.name, text))
        return items


@dataclass(frozen=True)
class VtpChange:
    """Requested VTP settings; ``None`` leaves a setting unchanged."""

    domain: str | None = None
    version: int | None = None
    mode: str | None = None
    pruning: bool | None = None
    password: str | None = None
    password_hidden: bool = False
    clear_password: bool = False

    def changed(self, current: Mapping) -> frozenset[str]:
        """Fields that differ from ``current`` (a ``read_vtp`` dict); a given password always counts."""
        result = {
            name for name in ("domain", "version", "mode", "pruning")
            if getattr(self, name) is not None and getattr(self, name) != current.get(name)
        }
        if self.password:
            result.add("password")
        if self.clear_password and current.get("password_configured") is not False:
            result.add("clear_password")
        return frozenset(result)


class WriteResult(TypedDict):
    ok: bool
    message: str
    raw: str  # device output; removed before the API response


def write_result(ok: bool, message: str, raw: str = "") -> WriteResult:
    return {"ok": ok, "message": message, "raw": raw}


def empty_switchport_detail(interface: str) -> dict:
    return {
        "interface": interface,
        "switchport_enabled": None,
        "administrative_mode": None,
        "operational_mode": None,
        "mode": "unknown",
        "access_vlan": None,
        "voice_vlan": None,
        "native_vlan": None,
        "trunk_allowed_vlan": None,
    }


def empty_poe_detail(supported: bool | None = None) -> dict:
    return {
        "poe_supported": supported,
        "poe_mode": None,
        "poe_status": None,
        "poe_used_watts": None,
        "poe_max_watts": None,
    }


def empty_poe_summary() -> dict:
    """``poe`` block of the device summary when no budget can be read."""
    return {
        "supported": None,
        "max_watts": None,
        "used_watts": None,
        "remaining_watts": None,
        "standards": None,
        "standards_source": None,
        "modules": [],
        "warnings": [],
    }


def merge_interface_details(interfaces: list[dict], switchports: Mapping[str, dict], driver) -> list[dict]:
    merged = []
    for interface in interfaces:
        item = dict(interface)
        detail = switchports.get(driver.interface_key(interface["port"]))
        item.update(detail or empty_switchport_detail(interface["port"]))
        merged.append(item)
    return merged


def merge_poe_details(
    interfaces: list[dict], ports: Mapping[str, dict] | None, driver,
) -> list[dict]:
    """``ports=None``: PoE state unknown; otherwise absent ports have no PoE."""
    missing = empty_poe_detail(None if ports is None else False)
    return [
        {**interface, **(ports or {}).get(driver.interface_key(interface["port"]), missing)}
        for interface in interfaces
    ]


def neighbor_row(protocol: str, **values) -> dict:
    """Neighbor in the common response format; unknown fields stay ``None``."""
    row = {
        "protocol": protocol,
        "device_id": None,
        "system_name": None,
        "chassis_id": None,
        "platform": None,
        "capabilities": None,
        "ip_addresses": [],
        "local_interface": None,
        "remote_interface": None,
        "holdtime_seconds": None,
        "software_version": None,
        "native_vlan": None,
        "duplex": None,
        "vtp_domain": None,
        "advertisement_version": None,
    }
    unknown = set(values) - set(row)
    if unknown:
        raise ValueError(f"Unknown neighbor fields: {sorted(unknown)}")
    row.update(values)
    return row


def client_snapshot(
    switch: dict,
    driver,
    *,
    mac_entries: list[dict],
    interfaces: list[dict],
    switchports: dict[str, dict],
    ip_bindings: dict[str, str] | None = None,
    ip_sources: dict[str, str] | None = None,
    ip_binding_records: list[dict] | None = None,
    neighbors: list[dict] | None = None,
    port_security_entries: dict | None = None,
    authentication_sessions: set | None = None,
    source_status: dict[str, str] | None = None,
    mac_table_diagnostics: dict | None = None,
    warnings: list[str] | None = None,
    **extra: Any,
) -> dict:
    """Build the client snapshot consumed by ``switches.clients``.

    - mac_entries: {"vlan": "10", "mac": 12 lowercase hex digits, "type": "DYNAMIC"|..., "interface"}
    - interfaces: interface rows; switchports: details keyed by ``interface_key``
    - ip_bindings: normalized MAC -> IPv4, ip_sources: MAC -> "arp" | "device_tracking" | ...
    - ip_binding_records: {"mac", "vlan", "interface" (key), "source", "ip"} (sticky MAC proof)
    - neighbors: ``neighbor_row`` dicts
    - port_security_entries: (mac, vlan, interface_key) -> {"type", "source"}
    - authentication_sessions: {(mac, interface_key)}
    """
    if switchports:
        interfaces = merge_interface_details(interfaces, switchports, driver)
    return {
        "switch": switch,
        "mac_entries": mac_entries,
        "interfaces": interfaces,
        "switchports": switchports,
        **clients.classify_client_ports(driver, interfaces, switchports),
        "mac_table_diagnostics": mac_table_diagnostics
        or {"parsed_entries": len(mac_entries), "unparsed_data_lines": 0, "ignored_data_lines": 0},
        "port_security_entries": port_security_entries or {},
        "authentication_sessions": authentication_sessions or set(),
        "warnings": warnings or [],
        "ip_bindings": ip_bindings or {},
        "ip_sources": ip_sources or {},
        "ip_binding_records": ip_binding_records or [],
        "source_status": source_status or {},
        "neighbors": neighbors or [],
        **extra,
    }


class SwitchDriver(ABC):
    """One supported device platform; instances are stateless and shared."""

    id: str  # = switches.device_type
    vendor: str  # "Cisco" | "Aruba" | "Netgear" | "MikroTik"
    label: str
    transport: Literal["ssh", "https"]
    default_port: int
    experimental: bool = True
    features: Mapping[str, FeatureSupport]
    catalog: Catalog = Catalog()
    max_vlan_id: ClassVar[int] = 4094

    @abstractmethod
    @contextmanager
    def session(self, switch: dict, credentials: dict) -> Iterator[Any]:
        """Open a device session; failures raise ``SwitchConnectionError``.

        The yielded object must expose ``warnings: list[str]`` (user-visible read
        warnings collected during the session, e.g. ``transport.SshSession``).
        """

    def _unsupported(self, feature: str):
        raise UnsupportedFeatureError(feature, NOT_IMPLEMENTED_REASON)

    def check_connection(self, switch: dict, credentials: dict) -> dict:
        """Opens its own session; returns {"ok", "message", "model"} and never raises for device errors."""
        self._unsupported("device_summary")

    def read_device_info(self, session) -> dict:
        """hostname, model, serial_number, software_version, uptime (missing values None)."""
        self._unsupported("device_summary")

    def read_interfaces(self, session) -> list[dict]:
        self._unsupported("interfaces")

    def read_vlans(self, session) -> list[dict]:
        """[{"id": int, "name": str, "status": str}] of VLANs existing on the device."""
        self._unsupported("interfaces")

    def read_switchports(self, session, interfaces: list[dict]) -> dict[str, dict]:
        self._unsupported("interfaces")

    def read_poe_ports(self, session) -> dict[str, dict] | None:
        """PoE per interface key; ``None`` when the PoE state is unknown (warning added)."""
        self._unsupported("poe")

    def read_poe_budget(self, session, device_info: dict) -> dict:
        """``poe`` block of the device summary (see ``empty_poe_summary``)."""
        self._unsupported("poe_budget")

    def read_port_detail(self, session, interface: str) -> dict:
        self._unsupported("port_detail")

    def validate_port_change(self, interface: str, change: PortChange) -> None:
        """Reject invalid values before a session is opened (``InvalidInputError``); default accepts all."""
        return None

    def read_port_state(self, session, interface: str, change: PortChange) -> dict:
        """Current port state for ``plan_port_change``; always contains ``mode`` (operator rule and stale
        detection of port-configure) and is checked against ``runtime_overrides``."""
        return self.read_port_detail(session, interface)

    def read_neighbors(self, session) -> list[dict]:
        self._unsupported("neighbors")

    def read_client_snapshot(self, session, switch: dict) -> dict:
        self._unsupported("clients")

    # --- Writes: every write is a ChangePlan built here and run by ``execute_plan`` ------
    # Plans may read the device; they must not change it. Feature IDs in the defaults are
    # the ones that gate the operation.

    def execute_plan(self, session, plan: ChangePlan) -> WriteResult:
        """Send ``plan.steps`` in order; stop at the first failed step. Clears ``session.cache``."""
        self._unsupported("port_state")

    def plan_port_change(self, session, interface: str, change: PortChange, detail: dict) -> ChangePlan:
        self._unsupported("port_mode")

    def plan_port_state(self, session, interface: str, enabled: bool) -> ChangePlan:
        self._unsupported("port_state")

    def plan_save_config(self, session) -> ChangePlan:
        self._unsupported("save_config")

    # VLAN tab: existence, usage and protection checks and the verification read are done
    # by the operation (see ``switches.vlans``).

    def read_vlan_constraints(self, session) -> VlanConstraints:
        """Protected VLANs (id -> German reason), layer-3 VLAN interfaces and the VLAN limit."""
        self._unsupported("vlans")

    def plan_vlan_create(self, session, vlan_id: int, name: str | None) -> ChangePlan:
        self._unsupported("vlan_create")

    def plan_vlan_rename(self, session, vlan_id: int, name: str) -> ChangePlan:
        self._unsupported("vlan_rename")

    def plan_vlan_delete(self, session, vlan_id: int) -> ChangePlan:
        self._unsupported("vlan_delete")

    def plan_vlan_voice(self, session, vlan_id: int, voice: bool) -> ChangePlan:
        """Mark/unmark a VLAN as voice VLAN (AOS-CX, AOS-S)."""
        self._unsupported("vlan_voice")

    # --- Management path / uplink detection ----------------------

    def local_address(self, session) -> str | None:
        """SwitchSteward's own source address of this session (None if unknown)."""
        return None

    def read_management_path(self, session) -> dict:
        """{"gateway", "management_ip", "management_interface", "management_vlan"} (unknown = None)."""
        self._unsupported("management_path")

    def lookup_arp(self, session, ip: str) -> str | None:
        """MAC address (lowercase ``aa:bb:cc:dd:ee:ff``) for an IPv4 address, or None."""
        self._unsupported("management_path")

    def lookup_mac_port(self, session, mac: str) -> str | None:
        """Interface (as ``read_interfaces`` names it) where ``mac`` was learned, or None."""
        self._unsupported("management_path")

    # --- Port actions -----------------------------------------------------------

    def plan_port_bounce(self, session, interface: str) -> ChangePlan:
        self._unsupported("port_bounce")

    def plan_poe_cycle(self, session, interface: str) -> ChangePlan:
        self._unsupported("poe_cycle")

    def plan_errdisable_recover(self, session, interface: str) -> ChangePlan:
        """Refuses ports that are not disabled by a protection feature (``InvalidInputError``)."""
        self._unsupported("errdisable_recovery")

    # --- Configuration files, restore, rollback ---------------------------------

    # Transfer protocol the switch uses to download files from SwitchSteward.
    transfer_method: ClassVar[Literal["http", "sftp"]] = "http"
    # AOS-S/Netgear: SFTP downloads only from port 22.
    sftp_port_22_only: ClassVar[bool] = False
    # Regexes of config lines ignored for comparison/deduplication (timestamps, uptime).
    volatile_config_patterns: ClassVar[tuple[str, ...]] = ()
    # Restore file name the switch expects (AOS-CX "startup.json").
    restore_filename: ClassVar[str] = "startup.cfg"

    def read_running_config(self, session) -> str:
        self._unsupported("config_backup")

    def read_startup_config(self, session) -> str | None:
        """None when the platform has no startup configuration (MikroTik)."""
        self._unsupported("config_backup")

    def plan_config_restore(self, session, transfer: TransferLocation) -> ChangePlan:
        """Download into the startup configuration and restart (``reloads=True``)."""
        self._unsupported("config_restore")

    def plan_rollback_arm(self, session, minutes: int) -> ChangePlan:
        """Steps run before the change; may set ``config_mode_command`` for the change lines."""
        self._unsupported("config_rollback")

    def plan_rollback_confirm(self, session) -> ChangePlan:
        self._unsupported("config_rollback")

    def plan_rollback_revert(self, session) -> ChangePlan:
        self._unsupported("config_rollback")

    # --- Port security ----------------------------------------------------------

    def read_port_security(self, session) -> dict:
        """{"global": {...}, "ports": {interface_key: {...}}}."""
        self._unsupported("port_security")

    def plan_port_security(self, session, interface: str, change: SecurityChange, detail: dict) -> ChangePlan:
        self._unsupported("port_security")

    def plan_security_global(self, session, change: SecurityGlobalChange) -> ChangePlan:
        self._unsupported("dhcp_snooping")

    # --- Link aggregation and spanning tree -------------------------------------

    max_lag_id: ClassVar[int] = 0

    def lag_interface_name(self, lag_id: int) -> str:
        self._unsupported("lag")

    def read_lags(self, session) -> list[dict]:
        self._unsupported("lag")

    def plan_lag_create(self, session, lag_id: int, mode: str, members: tuple[str, ...]) -> ChangePlan:
        self._unsupported("lag")

    def plan_lag_update(self, session, lag_id: int, add: tuple[str, ...], remove: tuple[str, ...]) -> ChangePlan:
        self._unsupported("lag")

    def plan_lag_delete(self, session, lag_id: int) -> ChangePlan:
        self._unsupported("lag")

    def read_stp(self, session) -> dict:
        self._unsupported("stp")

    def plan_stp_mode(self, session, mode: str) -> ChangePlan:
        self._unsupported("stp")

    def plan_stp_priority(
        self, session, priority: int, vlans: tuple[int, ...] | None, instance: int | None,
    ) -> ChangePlan:
        self._unsupported("stp")

    def plan_stp_mst(
        self, session, name: str, revision: int, instances: tuple[tuple[int, tuple[int, ...]], ...],
    ) -> ChangePlan:
        """Replaces the instance mapping completely (instances not listed are removed)."""
        self._unsupported("stp_mst")

    def plan_stp_port(
        self, session, interface: str, instance_or_vlan: int | None, cost: int | None, priority: int | None,
    ) -> ChangePlan:
        self._unsupported("stp")

    # --- VTP (Cisco) ----------------------------------------------------------------------

    def read_vtp(self, session) -> dict:
        """``show vtp status`` facts (see cisco/vtp.py) plus ``password_configured``."""
        self._unsupported("vtp")

    def plan_vtp_configure(self, session, change: VtpChange) -> ChangePlan:
        self._unsupported("vtp")

    def plan_vtp_primary(self, session, password: str | None) -> ChangePlan:
        self._unsupported("vtp")

    # --- Device settings --------------------------------------------------------

    def read_device_config(self, session) -> dict:
        """identity/services/snmp/aaa/users/ssh/l3/acls/qos blocks; unsupported blocks None, never secrets."""
        self._unsupported("device_identity")

    def plan_device_identity(self, session, change: IdentityChange) -> ChangePlan:
        self._unsupported("device_identity")

    def plan_device_services(self, session, change: ServicesChange) -> ChangePlan:
        self._unsupported("device_services")

    def plan_snmp_user_set(self, session, user: SnmpUserChange) -> ChangePlan:
        self._unsupported("device_snmp")

    def plan_snmp_user_delete(self, session, name: str) -> ChangePlan:
        self._unsupported("device_snmp")

    def plan_device_aaa(self, session, change: AaaChange) -> ChangePlan:
        self._unsupported("device_aaa")

    def plan_device_user_set(self, session, name: str, password: str | None, privilege: str) -> ChangePlan:
        """privilege: "admin" | "read_only"; password None keeps the current password."""
        self._unsupported("device_users")

    def plan_device_user_delete(self, session, name: str) -> ChangePlan:
        self._unsupported("device_users")

    def plan_device_ssh(
        self, session, timeout_seconds: int | None, telnet_enabled: bool | None, web_enabled: bool | None,
    ) -> ChangePlan:
        self._unsupported("device_ssh")

    def plan_svi_set(
        self, session, vlan: int, address: str, prefix_length: int, dhcp_relay: tuple[str, ...],
    ) -> ChangePlan:
        self._unsupported("device_l3")

    def plan_svi_delete(self, session, vlan: int) -> ChangePlan:
        self._unsupported("device_l3")

    def plan_gateway(self, session, gateway: str) -> ChangePlan:
        self._unsupported("device_l3")

    def plan_route_add(
        self, session, prefix: str, prefix_length: int, next_hop: str, distance: int | None,
    ) -> ChangePlan:
        self._unsupported("device_l3")

    def plan_route_delete(self, session, prefix: str, prefix_length: int, next_hop: str) -> ChangePlan:
        self._unsupported("device_l3")

    def plan_acl_create(self, session, name: str, acl_type: str) -> ChangePlan:
        self._unsupported("acl")

    def plan_acl_delete(self, session, name: str) -> ChangePlan:
        self._unsupported("acl")

    def plan_acl_entry_add(self, session, name: str, entry: AclEntry) -> ChangePlan:
        self._unsupported("acl")

    def plan_acl_entry_delete(self, session, name: str, seq: int) -> ChangePlan:
        self._unsupported("acl")

    def plan_acl_bind(self, session, name: str, interface: str, direction: str) -> ChangePlan:
        self._unsupported("acl")

    def plan_acl_unbind(self, session, name: str, interface: str, direction: str) -> ChangePlan:
        self._unsupported("acl")

    def plan_qos_port(self, session, interface: str, trust: str | None, voice_preset: bool | None) -> ChangePlan:
        self._unsupported("qos")

    # --- Firmware, reload, diagnostics ------------------------------------------

    can_clear_counters: ClassVar[bool] = True

    def read_firmware(self, session) -> dict:
        """{running_version, boot_images, next_boot, install_mode, free_bytes, files}."""
        self._unsupported("firmware")

    def plan_firmware_stage(
        self, session, image: FirmwareImage, transfer: TransferLocation, firmware: dict,
    ) -> ChangePlan:
        """Download (and verify) ``image``; ``firmware`` = ``read_firmware`` result."""
        self._unsupported("firmware")

    def plan_firmware_activate(self, session, image: FirmwareImage, firmware: dict, reload_now: bool) -> ChangePlan:
        """Set the next boot image; ``reload_now`` appends the reload steps (``reloads=True``)."""
        self._unsupported("firmware")

    def plan_reload(self, session) -> ChangePlan:
        """Reload without saving (save question answered "no"); ``expect_disconnect``."""
        self._unsupported("reload")

    def read_counters(self, session, interface: str | None) -> list[dict]:
        self._unsupported("diag_counters")

    def plan_counters_clear(self, session, interface: str) -> ChangePlan:
        self._unsupported("diag_counters")

    def read_transceivers(self, session) -> list[dict]:
        self._unsupported("diag_transceivers")

    def read_log(self, session, lines: int = 500) -> list[str]:
        self._unsupported("device_log")

    def read_environment(self, session) -> dict:
        self._unsupported("environment")

    def plan_cable_test(self, session, interface: str) -> ChangePlan:
        self._unsupported("cable_test")

    def read_cable_test(self, session, interface: str) -> dict:
        self._unsupported("cable_test")

    @abstractmethod
    def validate_interface(self, name: str) -> str:
        """Return the accepted interface name or raise ``InvalidInputError``."""

    @abstractmethod
    def interface_key(self, name: str) -> str:
        """Canonical comparison key (e.g. long and short Cisco names map to one key)."""

    @abstractmethod
    def is_physical_interface(self, name: str) -> bool: ...

    def has_switchport(self, name: str) -> bool:
        """Interfaces whose VLAN membership ``read_switchports`` must report; such ports without details block
        VLAN deletion."""
        return self.is_physical_interface(name)

    def runtime_overrides(self, detail: dict) -> dict[str, str]:
        """Feature ID -> German reason for features the port cannot use right now."""
        return {}


class _CommandUnfinished(Exception):
    """An exec step hit its deadline without the device prompt; the channel is no longer in sync."""


class SshSwitchDriver(SwitchDriver):
    """Base for Netmiko drivers; sessions are ``transport.SshSession`` objects."""

    transport = "ssh"
    default_port = 22
    netmiko_device_type: ClassVar[str]

    @contextmanager
    def session(self, switch: dict, credentials: dict) -> Iterator[ssh_transport.SshSession]:
        with ssh_transport.ssh_session(switch, credentials, self.netmiko_device_type) as session:
            yield session

    # Set by every SSH driver: error markers and line check used for CliLines steps.
    config_error_markers: ClassVar[tuple] = ()
    config_check: ClassVar[Callable[[str, str, list[str]], list[str]] | None] = None

    def local_address(self, session: ssh_transport.SshSession) -> str | None:
        """Local IP of the SSH socket (SwitchSteward's address as the switch sees it)."""
        try:
            return session.conn.remote_conn.get_transport().sock.getsockname()[0]
        except Exception:
            return None

    def execute_plan(self, session: ssh_transport.SshSession, plan: ChangePlan) -> WriteResult:
        if session.broken:
            # A late response of a timed-out read could still arrive on this channel.
            return write_result(False, t(BROKEN_SESSION_REASON))
        conn = session.conn
        outputs: list[str] = []
        check = type(self).config_check
        secrets = plan.secrets

        def failed(message: str) -> WriteResult:
            return write_result(False, redact(message, secrets), redact("\n".join(outputs), secrets))

        try:
            for step in plan.steps:
                if isinstance(step, CliLines):
                    output, errors = cli.run_config_lines(
                        conn, step.lines, self.config_error_markers, enter=step.enter, exit=step.exit,
                        check=check, config_mode_command=step.config_mode_command, secrets=secrets,
                    )
                    outputs.append(output)
                    if errors:
                        return failed(t("Der Switch hat einen Befehl abgelehnt: {errors}", errors="; ".join(errors)))
                elif isinstance(step, CliCommand):
                    try:
                        failure = self._run_command(conn, step, outputs, secrets)
                    except _CommandUnfinished as exc:
                        # The command may still be running: nothing more may be sent on this channel.
                        session.broken = True
                        return failed(str(exc))
                    if failure is not None:
                        return failed(failure)
                elif isinstance(step, Pause):
                    time.sleep(step.seconds)
                else:
                    raise TypeError(f"Unsupported step for SSH drivers: {type(step).__name__}")
        finally:
            session.cache.clear()
            ssh_transport.reset_prompt(conn)
        return write_result(True, plan.message or t("Änderung übernommen."), redact("\n".join(outputs), secrets))

    def _run_command(self, conn, step: CliCommand, outputs: list[str], secrets: tuple[str, ...] = ()) -> str | None:
        """Run one exec step; returns the German failure message (may contain secrets: caller redacts) or None."""
        finished, output, question = cli.run_exec(
            conn, step.command, step.prompts, timeout=step.timeout, expect_disconnect=step.expect_disconnect,
            secrets=secrets,
        )
        outputs.append(output)
        if question is not None:
            return t("Unerwartete Rückfrage des Switches: {prompt}", prompt=question)
        if not finished:
            raise _CommandUnfinished(
                t("Der Switch hat den Befehl nicht rechtzeitig abgeschlossen: {command}", command=step.command)
            )
        errors = cli.error_lines(output, self.config_error_markers)
        if errors:
            return t("Der Switch hat einen Befehl abgelehnt: {errors}", errors="; ".join(errors))
        if step.success and not re.search(step.success, output):
            return t("Der Switch hat den Befehl nicht bestätigt: {command}", command=step.command)
        return None
