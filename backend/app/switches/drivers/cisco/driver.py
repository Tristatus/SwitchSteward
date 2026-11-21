"""Cisco IOS / IOS-XE driver (Netmiko ``cisco_ios`` / ``cisco_xe``).

Every value interpolated into an IOS command is validated first, and every
switch response is checked for '%' error lines: IOS returns no error code.
"""

import ipaddress
import logging
import re

from netmiko import NetmikoAuthenticationException

from ....i18n import t
from ... import transport
from ...clients import normalize_mac_address
from ...errors import InvalidInputError, SwitchConnectionError, UnsupportedFeatureError, append_warning
from ...features import FeatureSupport, supported, unsupported
from ...validation import sanitize_description, validate_choice, validate_vlan_id, vlan_ranges
from ...vlans import DEFAULT_REASON, RESERVED_REASON, VlanConstraints, success_message, validate_vlan_name
from ..base import PortChange, SshSwitchDriver, VtpChange
from ..plans import (
    ChangePlan,
    CliCommand,
    CliLines,
    Pause,
    SecurityChange,
    SecurityGlobalChange,
    TransferLocation,
    cli_plan,
)
from . import client_sources, l2, parsers, poe, security, vtp
from .device import DEVICE_FEATURES, CiscoDeviceMixin
from .models import CATALOG

logger = logging.getLogger("switchsteward.switches.cisco")

_VLAN_COMMAND_MAX_LENGTH = 200
_DESCRIPTION_MAX_LENGTH = 200
SPEED_OPTIONS = ("auto", "10", "100", "1000")
DUPLEX_OPTIONS = ("auto", "half", "full")
# VLAN 1 is the default VLAN; 1002-1005 are the reserved FDDI/Token Ring VLANs.
_PROTECTED_VLANS = {1: DEFAULT_REASON, **{vlan: RESERVED_REASON for vlan in range(1002, 1006)}}
# ``write memory`` ends with "[OK]" once NVRAM was written.
SAVE_SUCCESS_RE = r"\[OK\]"
ROLLBACK_UNSUPPORTED_IOS = "Zeitgesteuertes Rollback ist unter IOS 15.2 nicht zuverlässig verfügbar."
VOICE_VLAN_PORT_PROPERTY = "Voice-VLAN ist auf dieser Plattform eine Port-Eigenschaft."
NOT_ERRDISABLED = "Der Port ist nicht durch eine Schutzfunktion deaktiviert."
POE_CYCLE_OFF = "PoE ist an Port {interface} ausgeschaltet; ein PoE-Neustart ist nicht möglich."
# Wait between "down" and "up" of a port or PoE restart.
PORT_ACTION_PAUSE_SECONDS = 5
ARCHIVE_PATH = "flash:sm-archive"
# Reload questions: never save (a restore must keep the downloaded file).
RELOAD_PROMPTS = ((r"(?i)Save\?\s*\[yes/no\]", "no"), (r"\[confirm\]", ""))
COPY_PROMPTS = ((r"Destination filename \[[^\]]*\]\?", ""), (r"(?i)over ?write\?\s*\[confirm\]", ""))
COPY_SUCCESS_RE = r"(?i)bytes copied|\[OK\]"
COPY_TIMEOUT_SECONDS = 300
RELOAD_TIMEOUT_SECONDS = 60
STORM_TYPES = ("broadcast", "multicast", "unknown_unicast")
STORM_TYPES_IOS = ("broadcast", "multicast")

FEATURES = {
    "device_summary": supported(),
    "poe_budget": supported(),
    "interfaces": supported(),
    "port_detail": supported(),
    "port_description": supported(),
    "port_mode": supported(("access", "trunk")),
    "access_vlan": supported(),
    "native_vlan": supported(),
    "trunk_allowed_vlans": supported(),
    "voice_vlan": supported(),
    "vlan_voice": unsupported(VOICE_VLAN_PORT_PROPERTY),
    "vtp": supported(vtp.VTP_MODES),
    "vlans": supported(),
    "vlan_create": supported(),
    "vlan_rename": supported(),
    "vlan_delete": supported(),
    "edge_port": supported(),
    "speed": supported(SPEED_OPTIONS),
    "duplex": supported(DUPLEX_OPTIONS),
    "port_state": supported(),
    "port_bounce": supported(),
    "poe": supported(),
    "poe_mode": supported(("auto", "static", "never")),
    "poe_limit": supported(),
    "poe_cycle": supported(),
    "errdisable_recovery": supported(),
    "neighbors": supported(),
    "clients": supported(),
    "client_search": supported(),
    "save_config": supported(),
    "config_backup": supported(),
    "config_compare": supported(),
    "config_restore": supported(),
    "config_rollback": supported(),
    "management_path": supported(),
    "port_security": supported(("protect", "restrict", "shutdown")),
    "port_security_sticky": supported(),
    "dot1x": supported(("dot1x", "mab", "dot1x_mab")),
    "dot1x_host_mode": supported(("single", "multi_auth", "multi_host", "multi_domain")),
    "dot1x_fallback_vlans": supported(),
    "stp_guard": supported(("bpdu_guard", "root_guard", "loop_guard")),
    "storm_control": supported(STORM_TYPES),
    "storm_control_action": supported(("drop", "shutdown")),
    "dhcp_snooping": supported(),
    "arp_inspection": supported(),
    "ip_source_guard": supported(),
    "lag": supported(tuple(l2.LAG_MODES)),
    "stp": supported(tuple(l2.STP_MODES)),
    "stp_mst": supported(),
    "reload": supported(),
    **DEVICE_FEATURES,
}

# Per-platform differences to FEATURES.
_PLATFORM_FEATURES: dict[str, dict[str, FeatureSupport]] = {
    "cisco_ios": {
        "config_rollback": unsupported(ROLLBACK_UNSUPPORTED_IOS),
        "storm_control": supported(STORM_TYPES_IOS),
    },
    "cisco_xe": {},
}


def allowed_vlan_commands(selection) -> list[str]:
    """Replace the allowed list completely, with short follow-up commands for long lists."""
    if isinstance(selection, str):
        return [f"switchport trunk allowed vlan {selection}"]
    prefix = "switchport trunk allowed vlan "
    commands = []
    chunk = ""
    for item in vlan_ranges(selection):
        candidate = f"{chunk},{item}" if chunk else item
        if len(prefix) + len(candidate) > _VLAN_COMMAND_MAX_LENGTH:
            commands.append(prefix + chunk)
            prefix = "switchport trunk allowed vlan add "
            chunk = item
        else:
            chunk = candidate
    commands.append(prefix + chunk)
    return commands


def _config_check(line: str, output: str, errors: list[str]) -> list[str]:
    if line.startswith("power inline "):
        # Some IOS releases reject power allocation without a '%' prefix.
        errors = errors + [
            text.strip() for text in output.splitlines()
            if re.match(r"\s*(?:Command rejected\s*:|Error\s*:)", text, re.IGNORECASE)
        ]
    # Tolerate only missing syntax of this one optional command. Authorization
    # and other errors must stop the remaining sequence.
    if line == "switchport trunk encapsulation dot1q" and parsers.unsupported_command_errors(output):
        return []
    return errors


class CiscoDriver(CiscoDeviceMixin, SshSwitchDriver):
    vendor = "Cisco"
    experimental = False
    config_error_markers = parsers.IOS_ERROR_MARKERS
    config_check = _config_check
    catalog = CATALOG
    transfer_method = "http"
    max_lag_id = 48
    volatile_config_patterns = (
        r"^Building configuration\.\.\.\s*$",
        r"^Current configuration\s*:",
        r"^Using \d+ out of \d+ bytes",
        r"^ntp clock-period \d+\s*$",
        r"^! Last configuration change at ",
        r"^! NVRAM config last updated at ",
        r"^! No configuration change since last restart",
    )

    def __init__(self, driver_id: str, label: str):
        self.id = driver_id
        self.label = label
        self.netmiko_device_type = driver_id
        self._platform_features = _PLATFORM_FEATURES[driver_id]

    @property
    def features(self) -> dict[str, FeatureSupport]:
        """Shared FEATURES plus the platform differences of this instance."""
        return {**FEATURES, **self._platform_features}

    # --- Interface names -------------------------------------------------------------

    def validate_interface(self, name: str) -> str:
        return parsers.validate_interface(name)

    def interface_key(self, name: str) -> str:
        return parsers.interface_key(name)

    def is_physical_interface(self, name: str) -> bool:
        return parsers.is_physical_interface_name(name)

    def has_switchport(self, name: str) -> bool:
        """Physical ports and port-channels (both appear in the status table and the bulk switchport output)."""
        return self.is_physical_interface(name) or bool(re.fullmatch(r"po\d+", parsers.interface_key(name)))

    # --- Reads -----------------------------------------------------------------------

    def check_connection(self, switch: dict, credentials: dict) -> dict:
        try:
            with transport.open_ssh(switch, credentials, self.netmiko_device_type) as session:
                prompt = session.conn.find_prompt()
                model = None
                try:
                    version_out = transport.send_show(session.conn, "show version")
                    parsers.ensure_show_output(version_out, "show version")
                    model = parsers.parse_show_version(version_out)["model"]
                except (*transport.SSH_ERRORS, SwitchConnectionError) as exc:
                    logger.warning("Model detection failed for switch id=%s (%s)", switch.get("id"), type(exc).__name__)
            return {"ok": True, "message": t("Verbindung erfolgreich, Prompt: {prompt}", prompt=prompt), "model": model}
        except NetmikoAuthenticationException:
            return {"ok": False, "message": t("Authentifizierung fehlgeschlagen (Benutzername/Passwort prüfen)"),
                    "model": None}
        except transport.SSH_TIMEOUT_ERRORS:
            return {"ok": False, "message": t("Zeitüberschreitung - Switch nicht erreichbar (IP/Port/Firewall prüfen)"),
                    "model": None}
        except Exception as exc:
            logger.warning("SSH connection test failed for switch id=%s (%s)", switch.get("id"), type(exc).__name__)
            return {"ok": False, "message": t("SSH-Verbindung fehlgeschlagen. Server-Log prüfen."), "model": None}

    def read_device_info(self, session: transport.SshSession) -> dict:
        version_out = transport.send_show(session.conn, "show version")
        parsers.ensure_show_output(version_out, "show version")
        session.cache["show version"] = version_out
        return parsers.parse_show_version(version_out)

    def read_interfaces(self, session: transport.SshSession) -> list[dict]:
        """Status rows; err-disabled ports carry the reason from ``show interfaces status err-disabled``."""
        rows = parsers.parse_interface_status(transport.send_show(session.conn, "show interfaces status"))
        reasons = {}
        if any(row["status"].casefold() == "err-disabled" for row in rows):
            reasons = self._errdisabled_reasons(session)
        for row in rows:
            reason = None
            if row["status"].casefold() == "err-disabled":
                reason = (reasons or {}).get(parsers.interface_key(row["port"]), "unknown")
            row["errdisabled_reason"] = reason
        return rows

    def _errdisabled_reasons(self, session: transport.SshSession) -> dict[str, str] | None:
        """Interface key -> err-disabled reason; None (warning added) when the table cannot be read."""
        command = "show interfaces status err-disabled"
        if session.broken:
            return None
        try:
            output = transport.send_show(session.conn, command)
            parsers.ensure_show_output(output, command)
        except transport.SSH_TIMEOUT_ERRORS:
            session.broken = True
            append_warning(session.warnings, t("'{command}' lief in ein Zeitlimit.", command=command))
            return None
        except SwitchConnectionError as exc:
            append_warning(session.warnings, str(exc))
            return None
        return parsers.parse_errdisabled(output)

    def read_vlans(self, session: transport.SshSession) -> list[dict]:
        return parsers.parse_vlan_brief(transport.send_show(session.conn, "show vlan brief"))

    def read_vlan_constraints(self, session: transport.SshSession) -> VlanConstraints:
        """Default/reserved VLANs and the SVIs from ``show ip interface brief`` (``None`` if unreadable)."""
        l3_interfaces = None
        if not session.broken:
            try:
                l3_interfaces = parsers.parse_vlan_interfaces(
                    transport.send_show(session.conn, "show ip interface brief"),
                )
            except transport.SSH_TIMEOUT_ERRORS:
                session.broken = True
        return VlanConstraints(protected=_PROTECTED_VLANS, l3_interfaces=l3_interfaces)

    def read_switchports(self, session: transport.SshSession, interfaces: list[dict]) -> dict[str, dict]:
        """Bulk ``show interfaces switchport`` with the per-port fallback (max. 64 ports)."""
        warnings = session.warnings
        try:
            bulk_output = transport.send_show(session.conn, "show interfaces switchport")
        except transport.SSH_TIMEOUT_ERRORS:
            logger.warning("Bulk switchport read timed out for switch id=%s", session.switch.get("id"))
            session.broken = True
            append_warning(
                warnings,
                t("Die optionale Bulk-Switchport-Abfrage lief in ein Zeitlimit; Einzelport-Fallback wird verwendet."),
            )
            switchports, needs_fallback = {}, True
        else:
            switchports, needs_fallback = parsers.parse_optional_switchport_output(bulk_output, warnings)
        if needs_fallback:
            switchports = client_sources.fallback_switchports(
                session, self.netmiko_device_type, interfaces, warnings,
            )
        missing = [
            interface["port"]
            for interface in interfaces
            if switchports and parsers.interface_key(interface["port"]) not in switchports
        ]
        if missing:
            append_warning(warnings, t("Keine Switchport-Details fuer: {ports}.", ports=", ".join(missing)))
        return switchports

    def read_poe_ports(self, session: transport.SshSession) -> dict[str, dict] | None:
        if session.broken:
            return None
        return poe.read_optional_poe(session)

    def read_poe_budget(self, session: transport.SshSession, device_info: dict) -> dict:
        """Last command of the summary session: a timeout must not leave a stale response."""
        power_out = None
        warnings = []
        if session.broken:
            warnings.append(t("Die PoE-Abfrage lief in ein Zeitlimit; das Gesamtbudget ist nicht verfügbar."))
        else:
            try:
                power_out = transport.send_show(session.conn, "show power inline")
                parsers.ensure_show_output(power_out, "show power inline")
            except transport.SSH_TIMEOUT_ERRORS:
                session.broken = True
                power_out = None
                warnings.append(t("Die PoE-Abfrage lief in ein Zeitlimit; das Gesamtbudget ist nicht verfügbar."))
            except transport.SSH_ERRORS:
                power_out = None
                warnings.append(t("Die PoE-Abfrage ist fehlgeschlagen; das Gesamtbudget ist nicht verfügbar."))
            except SwitchConnectionError:
                power_out = None
                warnings.append(
                    t("Der Switch liefert kein PoE-Gesamtbudget. Befehlsunterstützung und SSH-Berechtigungen prüfen.")
                )
        summary = poe.build_poe_summary(power_out, session.cache.get("show version", ""), device_info.get("model"))
        for warning in warnings:
            append_warning(summary["warnings"], warning)
        return summary

    def read_port_detail(self, session: transport.SshSession, interface: str) -> dict:
        """Mode, VLANs, PortFast, speed/duplex, shutdown, PoE and speed/duplex options of one port."""
        interface = self.validate_interface(interface)
        warnings = session.warnings
        switchport_out = transport.send_show(session.conn, f"show interfaces {interface} switchport")
        running_out = transport.send_show(session.conn, f"show running-config interface {interface}")
        poe_ports = poe.read_optional_poe(session)
        poe_detail = poe.port_poe_detail(poe_ports, interface)
        poe_capabilities = poe.read_optional_poe_capabilities(session, interface, poe_detail["poe_supported"])
        port_options = self._read_port_options(session, interface)

        parsers.ensure_show_output(switchport_out, f"show interfaces {interface} switchport")
        parsers.ensure_show_output(running_out, f"show running-config interface {interface}")

        detail = {
            "interface": interface,
            "description": None,
            "switchport_enabled": None,
            "administrative_mode": None,
            "operational_mode": None,
            "mode": "unknown",
            "access_vlan": None,
            "voice_vlan": None,
            "native_vlan": None,
            "trunk_allowed_vlan": None,
            "portfast": False,
            "speed": "auto",
            "duplex": "auto",
            "shutdown": False,
            **poe_detail,
            **poe_capabilities,
            "poe_configured_max_watts": poe.configured_poe_limit(running_out, interface),
            "port_options": port_options,
            "warnings": warnings,
        }

        m = re.search(r"^\s*description\s+(.+)$", running_out, re.MULTILINE)
        if m:
            detail["description"] = m.group(1).strip()

        # 'shutdown' in the running config: administratively disabled ('no shutdown' must not match).
        if re.search(r"^\s*shutdown\s*$", running_out, re.MULTILINE):
            detail["shutdown"] = True

        switchport_detail = parsers.parse_interfaces_switchport(switchport_out).get(parsers.interface_key(interface))
        if switchport_detail is None:
            raise SwitchConnectionError(t("Switchport-Details fuer {interface} fehlen in der Switch-Ausgabe.", interface=interface))
        for field in (
            "switchport_enabled",
            "administrative_mode",
            "operational_mode",
            "mode",
            "access_vlan",
            "voice_vlan",
            "native_vlan",
            "trunk_allowed_vlan",
        ):
            detail[field] = switchport_detail[field]

        if re.search(r"^\s*spanning-tree portfast(?!\s+disable)", running_out, re.MULTILINE):
            detail["portfast"] = True

        m = re.search(r"^\s*speed\s+(\S+)", running_out, re.MULTILINE)
        if m:
            detail["speed"] = m.group(1)

        m = re.search(r"^\s*duplex\s+(\S+)", running_out, re.MULTILINE)
        if m:
            detail["duplex"] = m.group(1)

        return detail

    def _read_port_options(self, session: transport.SshSession, interface: str) -> dict[str, list[str]]:
        """Speed/duplex options from ``show interfaces <if> capabilities``; {} = driver options."""
        if session.broken:
            return {}
        command = f"show interfaces {interface} capabilities"
        try:
            output = transport.send_show(session.conn, command)
        except transport.SSH_TIMEOUT_ERRORS:
            session.broken = True
            return {}
        if not isinstance(output, str) or parsers.extract_ios_errors(output):
            return {}
        return parsers.parse_interface_capabilities(output)

    def runtime_overrides(self, detail: dict) -> dict[str, str]:
        overrides = {}
        if detail.get("poe_supported") is False:
            for feature in ("poe", "poe_mode", "poe_limit", "poe_cycle"):
                overrides[feature] = "Dieses Interface stellt kein PoE bereit."
        elif "poe_supported" in detail and detail["poe_supported"] is None:
            overrides["poe_limit"] = "Die PoE-Unterstuetzung dieses Interfaces konnte nicht bestaetigt werden."
        return overrides

    def read_neighbors(self, session: transport.SshSession) -> list[dict]:
        """CDP and LLDP neighbors; fails only when neither protocol can be read."""
        neighbors = []
        failures = []
        for command, parse in (
            ("show cdp neighbors detail", parsers.parse_cdp_neighbors_detail),
            ("show lldp neighbors detail", parsers.parse_lldp_neighbors_detail),
        ):
            if session.broken:
                failures.append(t("'{command}' wurde nach einem Zeitlimit nicht mehr abgefragt.", command=command))
                continue
            try:
                output = transport.send_show(session.conn, command)
            except transport.SSH_TIMEOUT_ERRORS:
                session.broken = True
                failures.append(t("'{command}' lief in ein Zeitlimit.", command=command))
                continue
            try:
                parsers.ensure_show_output(output, command)
            except SwitchConnectionError as exc:
                failures.append(str(exc))
                continue
            neighbors.extend(parse(output))
        if len(failures) == 2:
            raise SwitchConnectionError(t("Nachbarn konnten nicht gelesen werden: {failures}", failures=" ".join(failures)))
        return neighbors

    def read_client_snapshot(self, session: transport.SshSession, switch: dict) -> dict:
        return client_sources.read_client_snapshot(self, session)

    # --- Writes ----------------------------------------------------------------------

    def validate_port_change(self, interface: str, change: PortChange) -> None:
        """Validate every value before SSH: PoE profile and all interpolated command values."""
        poe.validate_poe_settings(change.poe_mode, change.poe_standard)
        self.port_change_commands(self.validate_interface(interface), change, {})

    def read_port_state(self, session: transport.SshSession, interface: str, change: PortChange) -> dict:
        """Current switchport mode (operator rule, stale-preview check and the edge-port keyword)."""
        command = f"show interfaces {interface} switchport"
        output = transport.send_show(session.conn, command)
        parsers.ensure_show_output(output, command)
        detail = parsers.parse_interfaces_switchport(output).get(parsers.interface_key(interface))
        if detail is None:
            raise SwitchConnectionError(t("Switchport-Details fuer {interface} fehlen in der Switch-Ausgabe.", interface=interface))
        return {"mode": detail["mode"]}

    def port_change_commands(self, interface: str, change: PortChange, detail: dict) -> list[str]:
        """IOS commands for a validated change (PoE is inserted separately after the fresh hardware check)."""
        commands = [f"interface {interface}"]
        if change.description is not None:
            clean = sanitize_description(change.description, _DESCRIPTION_MAX_LENGTH)
            commands.append("no description" if clean == "" else f"description {clean}")

        if change.mode == "access":
            commands.append("switchport mode access")
        elif change.mode == "trunk":
            # Needed on multi-encapsulation platforms (older Catalyst 3560/3750)
            # before 'switchport mode trunk'; rejected as unsupported syntax elsewhere.
            commands.append("switchport trunk encapsulation dot1q")
            commands.append("switchport mode trunk")
        if change.access_vlan is not None and change.mode != "trunk":
            commands.append(f"switchport access vlan {validate_vlan_id(change.access_vlan)}")
        if change.native_vlan is not None and change.mode != "access":
            commands.append(f"switchport trunk native vlan {validate_vlan_id(change.native_vlan)}")
        if change.voice_vlan is not None:
            commands.append(
                f"switchport voice vlan {validate_vlan_id(change.voice_vlan)}" if change.voice_vlan
                else "no switchport voice vlan"
            )

        # Allowed VLANs can be configured on access ports too and apply once the
        # port becomes a trunk. None keeps the existing list.
        if change.trunk_allowed_vlans is not None:
            commands.extend(allowed_vlan_commands(change.trunk_allowed_vlans))

        if change.speed is not None:
            commands.append(f"speed {validate_choice(str(change.speed), SPEED_OPTIONS, 'Speed')}")
        if change.duplex is not None:
            commands.append(f"duplex {validate_choice(str(change.duplex), DUPLEX_OPTIONS, 'Duplex')}")

        if change.edge_port is not None:
            trunk = (change.mode or detail.get("mode")) == "trunk"
            # Trunk ports need the explicit 'trunk' keyword in both directions.
            command = "spanning-tree portfast trunk" if trunk else "spanning-tree portfast"
            commands.append(command if change.edge_port else f"no {command}")

        # Shutdown last: configure first, then enable the port if requested.
        if change.shutdown is True:
            commands.append("shutdown")
        elif change.shutdown is False:
            commands.append("no shutdown")
        return commands

    def plan_port_change(
        self, session: transport.SshSession, interface: str, change: PortChange, detail: dict,
    ) -> ChangePlan:
        interface = self.validate_interface(interface)
        milliwatts = poe.validate_poe_settings(change.poe_mode, change.poe_standard)
        commands = self.port_change_commands(interface, change, detail)
        conn = session.conn
        if change.poe_mode is not None:
            transport.reset_prompt(conn)
            poe_ports = poe.parse_power_inline(transport.send_show(conn, "show power inline"))
            if not poe_ports.get(parsers.interface_key(interface), {}).get("poe_supported"):
                raise InvalidInputError(t("Interface {interface} unterstuetzt kein PoE.", interface=interface))
            if milliwatts:
                # Never trust the browser's detail snapshot or the stack's aggregate
                # maximum: this target port's hardware must support the selection now.
                version_out = transport.send_show(conn, "show version")
                parsers.ensure_show_output(version_out, "show version")
                capabilities = poe.get_poe_capabilities(version_out, interface)
                if not any(option["id"] == change.poe_standard for option in capabilities["poe_standard_options"]):
                    raise InvalidInputError(t(
                        "Der ausgewaehlte PoE-Standard ist fuer Interface {interface} nicht bestaetigt. {reason}",
                        interface=interface,
                        reason=capabilities.get("poe_standards_reason") or t("Bitte die Interface-Details neu laden."),
                    ))
            if change.poe_mode != "never" and milliwatts is None:
                running_out = transport.send_show(conn, f"show running-config interface {interface}")
                configured_limit = poe.configured_poe_limit(running_out, interface)
                if configured_limit is not None:
                    # An omitted profile preserves even an existing custom limit; it
                    # must not silently become a higher hardware-default budget.
                    milliwatts = poe.poe_milliwatts(configured_limit)
            # An omitted max selects the device default. Send PoE first so an
            # unsupported limit stops before VLAN edits.
            poe_command = f"power inline {change.poe_mode}"
            if milliwatts:
                poe_command += f" max {milliwatts}"
            commands.insert(1, poe_command)
        return cli_plan(commands, message=t("Interface-Konfiguration übernommen (noch nicht dauerhaft gespeichert)"))

    def plan_port_state(self, session: transport.SshSession, interface: str, enabled: bool) -> ChangePlan:
        interface = self.validate_interface(interface)
        message = (
            "Port {interface} wurde eingeschaltet (noch nicht dauerhaft gespeichert)" if enabled
            else "Port {interface} wurde ausgeschaltet (noch nicht dauerhaft gespeichert)"
        )
        return cli_plan(
            [f"interface {interface}", "no shutdown" if enabled else "shutdown"],
            message=t(message, interface=interface),
        )

    def plan_save_config(self, session: transport.SshSession) -> ChangePlan:
        """``write memory``: make the last change persistent; IOS confirms with ``[OK]``."""
        timeout = max(session.conn.read_timeout_override or 0, transport.SAVE_CONFIG_MIN_TIMEOUT_SECONDS)
        step = CliCommand("write memory", timeout=int(timeout), success=SAVE_SUCCESS_RE)
        return ChangePlan(lines=(step.command,), steps=(step,), persistent=True, message=t("Konfiguration gespeichert"))

    # --- VLAN tab writes --------------------------------------------------------------

    def plan_vlan_create(self, session: transport.SshSession, vlan_id: int, name: str | None) -> ChangePlan:
        vlan_id = validate_vlan_id(vlan_id)
        commands = [f"vlan {vlan_id}"] + ([f"name {validate_vlan_name(name)}"] if name else [])
        return cli_plan(commands, message=success_message("create", vlan_id))

    def plan_vlan_rename(self, session: transport.SshSession, vlan_id: int, name: str) -> ChangePlan:
        vlan_id = validate_vlan_id(vlan_id)
        return cli_plan(
            [f"vlan {vlan_id}", f"name {validate_vlan_name(name)}"], message=success_message("rename", vlan_id),
        )

    def plan_vlan_delete(self, session: transport.SshSession, vlan_id: int) -> ChangePlan:
        vlan_id = validate_vlan_id(vlan_id)
        return cli_plan([f"no vlan {vlan_id}"], message=success_message("delete", vlan_id))

    # --- Management path (uplink protection) ------------------------------------------

    def _show(self, session: transport.SshSession, command: str) -> str:
        output = transport.send_show(session.conn, command)
        parsers.ensure_show_output(output, command)
        return output

    def read_management_path(self, session: transport.SshSession) -> dict:
        cached = session.cache.get("management_path")
        if cached is not None:
            return dict(cached)
        target_ip = str(session.switch.get("ip") or "")
        interfaces = parsers.parse_ip_interfaces(self._show(session, "show ip interface brief | exclude unassigned"))
        management_interface = next((name for name, ip in interfaces if ip == target_ip), None)
        out_of_band = management_interface is not None and parsers.is_management_port(management_interface)
        gateway = None
        if out_of_band:
            gateway = parsers.parse_gateway(
                transport.send_show(session.conn, "show ip route vrf Mgmt-vrf | include Gateway"),
            )
        else:
            gateway = parsers.parse_gateway(
                transport.send_show(session.conn, "show running-config | include ^ip default-gateway"),
            ) or parsers.parse_gateway(transport.send_show(session.conn, "show ip route | include Gateway"))
        vlan = re.fullmatch(r"(?:Vlan|Vl)(\d+)", management_interface or "", re.IGNORECASE)
        result = {
            "gateway": gateway,
            "management_ip": target_ip if management_interface else None,
            "management_interface": management_interface,
            "management_vlan": int(vlan.group(1)) if vlan else None,
        }
        session.cache["management_path"] = result
        return dict(result)

    def lookup_arp(self, session: transport.SshSession, ip: str) -> str | None:
        ip = str(ipaddress.IPv4Address(ip))
        mac = parsers.parse_arp_lookup(transport.send_show(session.conn, f"show ip arp {ip}"), ip)
        if mac is None and self.id == "cisco_xe":
            interface = self.read_management_path(session)["management_interface"]
            if interface and parsers.is_management_port(interface):
                mac = parsers.parse_arp_lookup(transport.send_show(session.conn, f"show ip arp vrf Mgmt-vrf {ip}"), ip)
        return mac

    def lookup_mac_port(self, session: transport.SshSession, mac: str) -> str | None:
        normalized = normalize_mac_address(mac)
        if not normalized:
            return None
        dotted = ".".join(normalized[index:index + 4] for index in range(0, 12, 4))
        entries, _ = parsers.parse_mac_table_with_diagnostics(
            transport.send_show(session.conn, f"show mac address-table address {dotted}"),
        )
        return next((entry["interface"] for entry in entries if entry["mac"] == normalized), None)

    # --- Read helpers -------------------------------------------------------------------

    def _read_lenient(self, session: transport.SshSession, command: str) -> str:
        """Show output that may legitimately be empty (``| include`` filters); '%' errors still raise."""
        output = transport.send_show(session.conn, command)
        if not isinstance(output, str):
            return ""
        if parsers.extract_ios_errors(output):
            parsers.ensure_show_output(output, command)
        return output

    def _optional_show(self, session: transport.SshSession, command: str) -> str | None:
        """Optional read: failures become a session warning and return None."""
        if session.broken:
            return None
        try:
            return self._read_lenient(session, command)
        except transport.SSH_TIMEOUT_ERRORS:
            session.broken = True
            append_warning(session.warnings, t("'{command}' lief in ein Zeitlimit.", command=command))
        except SwitchConnectionError as exc:
            append_warning(session.warnings, str(exc))
        return None

    def _show_long(self, session: transport.SshSession, command: str) -> str:
        """Full configuration read with at least the save timeout (large configurations)."""
        conn = session.conn
        previous = conn.read_timeout_override
        conn.read_timeout_override = max(previous or 0, transport.SAVE_CONFIG_MIN_TIMEOUT_SECONDS)
        try:
            output = transport.send_show(conn, command)
        finally:
            conn.read_timeout_override = previous
        parsers.ensure_show_output(output, command)
        return output

    # --- Port actions -----------------------------------------------------------

    def plan_port_bounce(self, session: transport.SshSession, interface: str) -> ChangePlan:
        """Two separate configuration blocks with a pause in between."""
        interface = self.validate_interface(interface)
        down = (f"interface {interface}", "shutdown")
        up = (f"interface {interface}", "no shutdown")
        return ChangePlan(
            lines=down + up, steps=(CliLines(down), Pause(PORT_ACTION_PAUSE_SECONDS), CliLines(up)),
        )

    def plan_poe_cycle(self, session: transport.SshSession, interface: str) -> ChangePlan:
        """``power inline never``, pause, then restore exactly the configured mode/limit."""
        interface = self.validate_interface(interface)
        output = self._read_lenient(session, f"show running-config interface {interface} | include power inline")
        match = re.search(r"^\s*power inline (never|auto|static)(?:\s+max\s+(\d+))?\s*$", output, re.MULTILINE)
        if match and match.group(1) == "never":
            raise InvalidInputError(t(POE_CYCLE_OFF, interface=interface))
        restore = "power inline auto"
        if match:
            restore = f"power inline {match.group(1)}" + (f" max {match.group(2)}" if match.group(2) else "")
        off = (f"interface {interface}", "power inline never")
        on = (f"interface {interface}", restore)
        return ChangePlan(lines=off + on, steps=(CliLines(off), Pause(PORT_ACTION_PAUSE_SECONDS), CliLines(on)))

    def plan_errdisable_recover(self, session: transport.SshSession, interface: str) -> ChangePlan:
        interface = self.validate_interface(interface)
        reasons = parsers.parse_errdisabled(self._read_lenient(session, "show interfaces status err-disabled"))
        if parsers.interface_key(interface) not in reasons:
            raise InvalidInputError(t(NOT_ERRDISABLED))
        return cli_plan([f"interface {interface}", "shutdown", "no shutdown"])

    # --- Configuration files, restore, rollback, reload ----------------------

    def read_running_config(self, session: transport.SshSession) -> str:
        return self._show_long(session, "show running-config")

    def read_startup_config(self, session: transport.SshSession) -> str:
        return self._show_long(session, "show startup-config")

    def plan_reload(self, session: transport.SshSession) -> ChangePlan:
        """``reload``; "Save?" is answered "no", "[confirm]" with Enter; the session drops."""
        step = CliCommand("reload", prompts=RELOAD_PROMPTS, timeout=RELOAD_TIMEOUT_SECONDS, expect_disconnect=True)
        return ChangePlan(lines=(step.command,), steps=(step,), reloads=True)

    def plan_config_restore(self, session: transport.SshSession, transfer: TransferLocation) -> ChangePlan:
        """``copy {url} startup-config`` and a reload without saving."""
        from ....transfer import location_secrets

        copy = CliCommand(
            f"copy {transfer.url} startup-config", prompts=COPY_PROMPTS, timeout=COPY_TIMEOUT_SECONDS,
            success=COPY_SUCCESS_RE,
        )
        reload = self.plan_reload(session)
        return ChangePlan(
            lines=(f"copy {transfer.display_url} startup-config", *reload.lines),
            steps=(copy, *reload.steps),
            reloads=True,
            secrets=location_secrets(transfer),
        )

    def _require_rollback(self) -> None:
        if not self.features["config_rollback"].supported:
            raise UnsupportedFeatureError("config_rollback", ROLLBACK_UNSUPPORTED_IOS)

    def plan_rollback_arm(self, session: transport.SshSession, minutes: int) -> ChangePlan:
        """Configuration Rollback Confirmed Change: the change lines run under
        ``configure terminal revert timer N``; the archive path is configured first when missing."""
        self._require_rollback()
        minutes = int(minutes)
        if not 1 <= minutes <= 120:
            raise InvalidInputError(t(security.UNSUPPORTED_VALUE, value=minutes))
        try:
            output = self._read_lenient(session, "show archive")
        except SwitchConnectionError:
            output = ""  # e.g. "% Archive feature not enabled": the archive block below configures it
        archive = ()
        if not re.search(r"^\s*The next archive file will be named\s+\S+", output, re.MULTILINE):
            archive = ("archive", f"path {ARCHIVE_PATH}", "maximum 14")
        mode_command = f"configure terminal revert timer {minutes}"
        return ChangePlan(
            lines=(*archive, mode_command),
            steps=(CliLines(archive),) if archive else (),
            config_mode_command=mode_command,
        )

    def plan_rollback_confirm(self, session: transport.SshSession) -> ChangePlan:
        self._require_rollback()
        step = CliCommand("configure confirm")
        return ChangePlan(lines=(step.command,), steps=(step,))

    def plan_rollback_revert(self, session: transport.SshSession) -> ChangePlan:
        self._require_rollback()
        step = CliCommand("configure revert now")
        return ChangePlan(lines=(step.command,), steps=(step,))

    # --- Port security ----------------------------------------------------------

    def read_port_security(self, session: transport.SshSession) -> dict:
        config = self.read_running_config(session)
        ports = {
            key: security.parse_port(lines)
            for key, (name, lines) in security.interface_blocks(config).items()
            if self.has_switchport(name)
        }
        summary = self._optional_show(session, "show port-security")
        for key, counters in security.parse_port_security_summary(summary or "").items():
            if key in ports:
                ports[key]["port_security"]["secure_macs"] = counters["secure_macs"]
                ports[key]["port_security"]["violation_count"] = counters["violation_count"]
        if any(port["dot1x"]["mode"] != "off" for port in ports.values()):
            command = "show access-session" if self.id == "cisco_xe" else "show authentication sessions"
            for key, status in security.parse_session_status(self._optional_show(session, command) or "").items():
                if key in ports:
                    ports[key]["dot1x"]["status"] = status
        return {"global": security.parse_global(config), "ports": ports}

    def plan_port_security(
        self, session: transport.SshSession, interface: str, change: SecurityChange, detail: dict,
    ) -> ChangePlan:
        interface = self.validate_interface(interface)
        running = self._read_lenient(session, f"show running-config interface {interface}")
        current = security.interface_blocks(running).get(parsers.interface_key(interface), (interface, []))[1]
        ibns2 = change.dot1x is not None and "policy-map type control subscriber" in self._read_lenient(
            session, security.IBNS2_PROBE,
        )
        storm_types = self.features["storm_control"].options or ()
        lines = security.port_security_lines(change, current, ibns2, storm_types)
        return cli_plan([f"interface {interface}", *lines])

    def plan_security_global(self, session: transport.SshSession, change: SecurityGlobalChange) -> ChangePlan:
        lines = security.global_lines(change, self._read_lenient(session, security.GLOBAL_PROBE))
        return cli_plan(lines) if lines else ChangePlan(lines=(), steps=())

    # --- Link aggregation ------------------------------------------------

    def lag_interface_name(self, lag_id: int) -> str:
        return f"Port-channel{int(lag_id)}"

    def read_lags(self, session: transport.SshSession) -> list[dict]:
        summary = self._show(session, "show etherchannel summary")
        channel_config = l2.parse_channel_config(self._read_lenient(session, l2.CHANNEL_CONFIG_PROBE))
        return l2.parse_etherchannel_summary(summary, channel_config)

    def plan_lag_create(
        self, session: transport.SshSession, lag_id: int, mode: str, members: tuple[str, ...],
    ) -> ChangePlan:
        keyword = l2.lag_mode_keyword(mode)
        lines = []
        for member in members:
            lines += [f"interface {self.validate_interface(member)}", f"channel-group {int(lag_id)} mode {keyword}"]
        return cli_plan(lines)

    def plan_lag_update(
        self, session: transport.SshSession, lag_id: int, add: tuple[str, ...], remove: tuple[str, ...],
    ) -> ChangePlan:
        """New members take the port-channel's switchport (VLAN) lines before joining it."""
        lag_id = int(lag_id)
        lines = []
        if add:
            lag = next((lag for lag in self.read_lags(session) if lag["id"] == lag_id), None)
            if lag is None:
                raise InvalidInputError(t("LAG {lag} existiert auf dem Switch nicht.", lag=lag_id))
            if lag["mode"] is None:
                raise InvalidInputError(t(l2.LAG_MODE_UNKNOWN, lag=lag_id))
            keyword = l2.lag_mode_keyword(lag["mode"])
            vlan_lines = l2.switchport_lines(
                self._show(session, f"show running-config interface {self.lag_interface_name(lag_id)}"),
            )
            for member in add:
                lines += [f"interface {self.validate_interface(member)}", *vlan_lines,
                          f"channel-group {lag_id} mode {keyword}"]
        for member in remove:
            lines += [f"interface {self.validate_interface(member)}", "no channel-group"]
        return cli_plan(lines)

    def plan_lag_delete(self, session: transport.SshSession, lag_id: int) -> ChangePlan:
        lag_id = int(lag_id)
        lag = next((lag for lag in self.read_lags(session) if lag["id"] == lag_id), None)
        if lag is None:
            raise InvalidInputError(t("LAG {lag} existiert auf dem Switch nicht.", lag=lag_id))
        lines = []
        for member in lag["members"]:
            lines += [f"interface {member['interface']}", "no channel-group"]
        lines.append(f"no interface {self.lag_interface_name(lag_id)}")
        return cli_plan(lines)

    # --- Spanning tree ---------------------------------------------------

    def read_stp(self, session: transport.SshSession) -> dict:
        mode = l2.parse_mode(self._show(session, "show spanning-tree summary"))
        mst = None
        if mode == "mstp":
            mst = l2.parse_mst_configuration(self._optional_show(session, "show spanning-tree mst configuration"))
        return {
            "mode": mode,
            "priority": l2.parse_bridge(self._optional_show(session, "show spanning-tree bridge")),
            "mst": mst,
            "roots": l2.parse_root(self._optional_show(session, "show spanning-tree root")),
            "ports": l2.parse_ports(self._optional_show(session, "show spanning-tree")),
        }

    def plan_stp_mode(self, session: transport.SshSession, mode: str) -> ChangePlan:
        if mode not in l2.STP_MODES:
            raise InvalidInputError(t(l2.UNSUPPORTED_VALUE, value=mode))
        return cli_plan([f"spanning-tree mode {l2.STP_MODES[mode]}"])

    def plan_stp_priority(
        self, session: transport.SshSession, priority: int, vlans: tuple[int, ...] | None, instance: int | None,
    ) -> ChangePlan:
        priority = int(priority)
        if not 0 <= priority <= 61440 or priority % 4096:
            raise InvalidInputError(t("Die Priorität muss ein Vielfaches von 4096 sein."))
        if instance is not None:
            return cli_plan([f"spanning-tree mst {int(instance)} priority {priority}"])
        if not vlans:
            raise InvalidInputError(t("Bitte entweder VLANs oder eine Instanz angeben."))
        vlan_list = l2.vlan_text(validate_vlan_id(vlan) for vlan in vlans)
        return cli_plan([f"spanning-tree vlan {vlan_list} priority {priority}"])

    def plan_stp_mst(
        self, session: transport.SshSession, name: str, revision: int,
        instances: tuple[tuple[int, tuple[int, ...]], ...],
    ) -> ChangePlan:
        """Region name/revision and the complete instance mapping (unlisted instances are removed)."""
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", name or ""):
            raise InvalidInputError(t(l2.UNSUPPORTED_VALUE, value=name))
        current = l2.parse_mst_configuration(self._read_lenient(session, "show spanning-tree mst configuration"))
        configured = l2.mst_mapping(current["instances"]) if current else {}
        wanted = {int(instance): frozenset(validate_vlan_id(vlan) for vlan in vlans) for instance, vlans in instances}
        lines = ["spanning-tree mst configuration", f"name {name}", f"revision {int(revision)}"]
        lines += [f"no instance {instance}" for instance in sorted(configured) if configured[instance] != wanted.get(instance)]
        lines += [
            f"instance {instance} vlan {l2.vlan_text(vlans)}"
            for instance, vlans in sorted(wanted.items()) if configured.get(instance) != vlans
        ]
        lines.append("exit")
        return cli_plan(lines)

    def plan_stp_port(
        self, session: transport.SshSession, interface: str, instance_or_vlan: int | None, cost: int | None,
        priority: int | None,
    ) -> ChangePlan:
        interface = self.validate_interface(interface)
        if cost is not None and not 1 <= int(cost) <= 200000000:
            raise InvalidInputError(t(l2.UNSUPPORTED_VALUE, value=cost))
        if priority is not None and (not 0 <= int(priority) <= 240 or int(priority) % 16):
            raise InvalidInputError(t("Die Port-Priorität muss ein Vielfaches von 16 sein."))
        mode = l2.parse_mode(self._show(session, "show spanning-tree summary"))
        if mode == "mstp":
            prefix = f"spanning-tree mst {int(instance_or_vlan or 0)}"
        elif instance_or_vlan is not None:
            prefix = f"spanning-tree vlan {validate_vlan_id(instance_or_vlan)}"
        else:
            prefix = "spanning-tree"
        lines = [f"interface {interface}"]
        if cost is not None:
            lines.append(f"{prefix} cost {int(cost)}")
        if priority is not None:
            lines.append(f"{prefix} port-priority {int(priority)}")
        return cli_plan(lines)

    # --- VTP --------------------------------------------------------------------------------

    def read_vtp(self, session: transport.SshSession) -> dict:
        cached = session.cache.get("vtp:status")
        if cached is not None:
            return dict(cached)
        status = vtp.parse_vtp_status(self._show(session, "show vtp status"))
        try:
            password_out = self._read_lenient(session, "show vtp password")
        except SwitchConnectionError:
            password_out = None
        status["password_configured"] = vtp.parse_vtp_password(password_out)
        session.cache["vtp:status"] = status
        return dict(status)

    def plan_vtp_configure(self, session: transport.SshSession, change: VtpChange) -> ChangePlan:
        current = self.read_vtp(session)
        target_domain = change.domain or current["domain"]
        target_version = change.version or current["version"]
        if target_version == 3 and not target_domain:
            raise InvalidInputError(t("VTP-Version 3 benötigt einen VTP-Domänennamen."))
        if (change.mode or current["mode"]) == "server" and not target_domain:
            raise InvalidInputError(t("Der Modus Server benötigt einen VTP-Domänennamen."))
        if change.password_hidden and target_version != 3:
            raise InvalidInputError(t("'hidden' ist nur mit VTP-Version 3 möglich."))
        return vtp.configure_plan(current, change)

    def plan_vtp_primary(self, session: transport.SshSession, password: str | None) -> ChangePlan:
        """``vtp primary vlan``: confirm with Enter, answer the password question when one is given."""
        prompts = ((r"\[confirm\]", ""),) + (((r"(?i)password\s*:\s*$", password),) if password else ())
        step = CliCommand("vtp primary vlan", prompts=prompts, timeout=60)
        return ChangePlan(
            lines=(step.command,), steps=(step,), secrets=(password,) if password else (),
            message=t("Der Switch ist jetzt VTP Primary Server."),
        )
