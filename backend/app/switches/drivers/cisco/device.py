"""Cisco IOS / IOS-XE device settings, firmware and diagnostics.

Mixed into ``CiscoDriver``; uses only ``self`` methods of the driver base and shared
helpers (no import of ``driver.py``). Plans read the running configuration first so that
lists replace the configured state (remove missing entries, add new ones) and the preview
shows only real changes. Secrets (SNMPv3 keys, RADIUS/TACACS keys, local passwords,
transfer tokens) only go into ``steps``/``secrets``; ``lines`` show ``REDACTED``.
"""

import ipaddress
import re

from ....i18n import t
from ... import transport
from ...errors import InvalidInputError, SwitchConnectionError, append_warning
from ...features import supported
from ...validation import (
    validate_acl_name,
    validate_banner,
    validate_choice,
    validate_host,
    validate_hostname,
    validate_ipv4,
    validate_ipv4_prefix,
    validate_secret,
    validate_snmp_text,
    validate_username,
    validate_vlan_id,
)
from ..plans import (
    REDACTED,
    AaaChange,
    AclEntry,
    ChangePlan,
    CliCommand,
    CliLines,
    FirmwareImage,
    IdentityChange,
    ServicesChange,
    SnmpUserChange,
    TransferLocation,
    cli_plan,
    combine_plans,
)
from . import device_parsers as dp
from . import parsers

DEVICE_FEATURES = {
    "device_identity": supported(),
    "device_services": supported(),
    "device_snmp": supported(),
    "device_aaa": supported(("radius", "tacacs", "login_order")),
    "device_users": supported(),
    "device_ssh": supported(("timeout", "telnet", "web")),
    "device_l3": supported(("svi", "gateway", "dhcp_relay", "static_routes")),
    "acl": supported(("port_in", "port_out", "vlan_in", "vlan_out")),
    "qos": supported(("none", "cos", "dscp")),
    "qos_voice": supported(),
    "firmware": supported(),
    "diag_counters": supported(),
    "diag_transceivers": supported(),
    "cable_test": supported(),
    "device_log": supported(),
    "environment": supported(),
}

SNMP_VIEW = "SM-VIEW"
FIRMWARE_TIMEOUT_SECONDS = 3600
_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TIMEZONE_RE = re.compile(r"^[A-Za-z]{1,6}$")
_COPY_PROMPTS = ((r"Destination filename", ""), (r"\[confirm\]", ""))
_INSTALL_PROMPTS = ((r"\[y/n(/q)?\]", "y"),)


def _no_change() -> InvalidInputError:
    return InvalidInputError(t("Keine Änderung nötig."))


def _mask(prefix_length: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{int(prefix_length)}").netmask)


def _wildcard(prefix_length: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{int(prefix_length)}").hostmask)


def _transfer_secrets(transfer: TransferLocation) -> tuple[str, ...]:
    # Imported here: ``app.transfer`` imports ``drivers.plans`` (and with it this package).
    from ....transfer import location_secrets

    return location_secrets(transfer)


def _acl_address(address: str | None, prefix_length: int | None) -> str:
    if address is None or prefix_length == 0:
        return "any"
    network = validate_ipv4_prefix(address, prefix_length)
    if network.prefixlen == 32:
        return f"host {network.network_address}"
    return f"{network.network_address} {_wildcard(network.prefixlen)}"


def _server_name(prefix: str, host: str) -> str:
    return f"SM-{prefix}-{host.replace('.', '-')}"


class _Lines:
    """Displayed and sent lines in parallel; ``secret`` values only reach the sent line."""

    def __init__(self):
        self.shown: list[str] = []
        self.sent: list[str] = []
        self.secrets: list[str] = []

    def add(self, line: str, secret_line: str | None = None, *secrets: str) -> None:
        self.shown.append(line)
        self.sent.append(secret_line if secret_line is not None else line)
        self.secrets.extend(secret for secret in secrets if secret)

    def plan(self, **kwargs) -> ChangePlan:
        if not self.sent:
            raise _no_change()
        return ChangePlan(
            lines=tuple(self.shown), steps=(CliLines(tuple(self.sent)),), secrets=tuple(self.secrets), **kwargs,
        )


class CiscoDeviceMixin:
    """Device settings, firmware and diagnostics reads and plans of the Cisco driver."""

    # --- Shared reads ---------------------------------------------------------------------

    def _device_show(self, session: transport.SshSession, command: str, *, empty_ok: bool = False) -> str:
        output = transport.send_show(session.conn, command)
        if empty_ok and isinstance(output, str) and not output.strip():
            return ""
        parsers.ensure_show_output(output, command)
        return output

    def _device_optional_show(
        self, session: transport.SshSession, command: str, quiet: tuple[str, ...] = (),
    ) -> str | None:
        """Output of an optional read; None (plus warning) when it times out or is rejected."""
        if session.broken:
            append_warning(session.warnings, t("'{command}' wurde nach einem Zeitlimit nicht mehr abgefragt.",
                                               command=command))
            return None
        try:
            output = transport.send_show(session.conn, command)
        except transport.SSH_TIMEOUT_ERRORS:
            session.broken = True
            append_warning(session.warnings, t("'{command}' lief in ein Zeitlimit.", command=command))
            return None
        if not isinstance(output, str):
            return None
        errors = parsers.extract_ios_errors(output)
        if errors:
            if not any(marker in output.lower() for marker in quiet):
                append_warning(session.warnings, t(
                    "Der Switch hat den Lesebefehl '{command}' abgelehnt: {errors}",
                    command=command, errors="; ".join(errors),
                ))
            return None
        return output

    def _running_config(self, session: transport.SshSession) -> str:
        """Full running configuration (cached per session, long read timeout like saving)."""
        cached = session.cache.get("device:running-config")
        if cached is not None:
            return cached
        conn = session.conn
        previous = getattr(conn, "read_timeout_override", None)
        conn.read_timeout_override = max(previous or 0, transport.SAVE_CONFIG_MIN_TIMEOUT_SECONDS)
        try:
            output = self._device_show(session, "show running-config")
        finally:
            conn.read_timeout_override = previous
        session.cache["device:running-config"] = output
        return output

    def _sections(self, session: transport.SshSession):
        return dp.config_sections(self._running_config(session))

    def _snmp_users(self, session: transport.SshSession) -> list[dict]:
        return dp.parse_snmp_users(self._device_optional_show(session, "show snmp user", quiet=("not enabled",)))

    def _access_lists(self, session: transport.SshSession) -> list[dict]:
        return dp.parse_access_lists(self._device_show(session, "show ip access-lists", empty_ok=True))

    def _qos_port(self, name: str) -> bool:
        """Switch ports carrying QoS settings (not the out-of-band management port)."""
        return self.is_physical_interface(name) and not parsers.is_management_port(name)

    @property
    def _mqc(self) -> bool:
        """IOS-XE uses MQC QoS and ``ip domain name``; IOS 15.2 MLS QoS and ``ip domain-name``."""
        return self.id == "cisco_xe"

    # --- Device settings read -----------------------------------------------------------------------

    def read_device_config(self, session: transport.SshSession) -> dict:
        sections = self._sections(session)
        services = {key: value for key, value in dp.parse_services(sections).items() if not key.startswith("_")}
        groups = dp.snmp_group_access(sections)
        snmp_users = [
            {"name": user["name"], "auth": user["auth"], "priv": user["priv"],
             "access": groups.get(user["group"], "ro")}
            for user in self._snmp_users(session)
        ]
        aaa = dp.parse_aaa(sections)
        acls = self._access_lists(session)
        bindings = dp.parse_acl_bindings(sections)
        for acl in acls:
            acl["bindings"] = bindings.get(acl["name"], [])
        return {
            "identity": dp.parse_identity(sections),
            "services": services,
            "snmp": {"users": snmp_users},
            "aaa": {
                "radius": [{key: server[key] for key in ("host", "auth_port", "acct_port", "key_configured")}
                           for server in aaa["radius"]],
                "tacacs": [{key: server[key] for key in ("host", "port", "key_configured")}
                           for server in aaa["tacacs"]],
                "login_order": aaa["login_order"],
            },
            "users": dp.parse_users(sections),
            "ssh": dp.parse_ssh(
                sections, self._device_optional_show(session, "show ip ssh"),
                self._device_optional_show(session, "show ip http server status"),
            ),
            "l3": dp.parse_l3(sections),
            "acls": acls,
            "qos": dp.parse_qos(sections, self._qos_port, self._mqc),
        }

    # --- Identity and services --------------------------------------------------------

    def plan_device_identity(self, session: transport.SshSession, change: IdentityChange) -> ChangePlan:
        current = dp.parse_identity(self._sections(session))
        lines = _Lines()
        if change.banner is not None:
            if change.banner == "":
                if current["banner"] is not None:
                    lines.add("no banner motd")
            else:
                body = [line for line in validate_banner(change.banner).split("\n") if line.strip()]
                existing = [line for line in (current["banner"] or "").split("\n") if line.strip()]
                if body != existing:
                    # Delimiter "^" never occurs in a validated banner; the device shows it as ^C.
                    for line in ("banner motd ^", *body, "^"):
                        lines.add(line)
        for field, keyword in (("snmp_location", "location"), ("snmp_contact", "contact")):
            value = getattr(change, field)
            if value is None:
                continue
            if value == "":
                if current[field] is not None:
                    lines.add(f"no snmp-server {keyword}")
            elif (text := validate_snmp_text(value)) != current[field]:
                lines.add(f"snmp-server {keyword} {text}")
        if change.hostname is not None and validate_hostname(change.hostname) != current["hostname"]:
            # Last: the prompt changes with the hostname.
            lines.add(f"hostname {change.hostname}")
        return lines.plan()

    def plan_device_services(self, session: transport.SshSession, change: ServicesChange) -> ChangePlan:
        sections = self._sections(session)
        current = dp.parse_services(sections)
        vrf = dp.management_vrf(sections, str(session.switch.get("ip") or ""))
        lines = _Lines()
        if change.ntp_servers is not None:
            wanted = list(dict.fromkeys(validate_host(server) for server in change.ntp_servers))
            for server, remove in current["_ntp_remove"].items():
                if server not in wanted:
                    lines.add(remove)
            for server in wanted:
                if server not in current["_ntp_remove"]:
                    lines.add(f"ntp server vrf {vrf} {server}" if vrf else f"ntp server {server}")
        if change.timezone_name is not None:
            name = change.timezone_name
            offset = int(change.timezone_offset_minutes or 0)
            if not _TIMEZONE_RE.fullmatch(name) or not -720 <= offset <= 840:
                raise InvalidInputError(t("Ungültige Zeitzone: {value}", value=repr(f"{name} {offset}")))
            if current["timezone"] != {"name": name, "offset_minutes": offset}:
                hours = int(offset / 60)
                minutes = abs(offset) % 60
                lines.add(f"clock timezone {name} {hours}" + (f" {minutes}" if minutes else ""))
        if change.dns_servers is not None:
            wanted = list(dict.fromkeys(validate_ipv4(server) for server in change.dns_servers))
            for server, remove in current["_dns_remove"].items():
                if server not in wanted:
                    lines.add(remove)
            for server in wanted:
                if server not in current["_dns_remove"]:
                    lines.add(f"ip name-server {server}")
        if change.domain_name is not None:
            keyword = "ip domain name" if self._mqc else "ip domain-name"
            if change.domain_name == "":
                if current["domain_name"] is not None:
                    lines.add(f"no {keyword}")
            elif validate_host(change.domain_name) != current["domain_name"]:
                lines.add(f"{keyword} {change.domain_name}")
        if change.syslog is not None:
            severities = {int(target.severity) for target in change.syslog}
            if len(severities) > 1:
                raise InvalidInputError(t("Diese Plattform erlaubt nur einen gemeinsamen Syslog-Schweregrad für alle Ziele."))
            wanted = list(dict.fromkeys(validate_host(target.host) for target in change.syslog))
            for host, remove in current["_syslog_remove"].items():
                if host not in wanted:
                    lines.add(remove)
            for host in wanted:
                if host not in current["_syslog_remove"]:
                    lines.add(f"logging host {host} vrf {vrf}" if vrf else f"logging host {host}")
            if severities:
                level = severities.pop()
                if not 0 <= level <= 7:
                    raise InvalidInputError(t("Ungültiger Wert für {label}: {value}", label="Severity", value=level))
                if level != current["_trap"]:
                    lines.add(f"logging trap {level}")
        return lines.plan()

    # --- Access: SNMPv3, AAA, users, SSH ------------------------------------------------

    def plan_snmp_user_set(self, session: transport.SshSession, user: SnmpUserChange) -> ChangePlan:
        name = validate_username(user.name)
        if user.auth != "sha":
            raise InvalidInputError(t("Diese Plattform unterstützt für SNMPv3 nur SHA."))
        auth_key = validate_secret(user.auth_key)
        priv_key = None
        if user.priv is not None:
            if not user.priv_key:
                raise InvalidInputError(t("Für die Verschlüsselung ist ein Schlüssel erforderlich."))
            priv_key = validate_secret(user.priv_key)
        access = validate_choice(user.access, ("ro", "rw"), "Zugriff")
        level = "priv" if priv_key else "auth"
        group = f"SM-SNMP-{access.upper()}-{level.upper()}"
        sections = self._sections(session)
        lines = _Lines()
        if SNMP_VIEW not in dp.snmp_views(sections):
            lines.add(f"snmp-server view {SNMP_VIEW} iso included")
        if group not in dp.snmp_group_access(sections):
            write = f" write {SNMP_VIEW}" if access == "rw" else ""
            lines.add(f"snmp-server group {group} v3 {level} read {SNMP_VIEW}{write}")
        for existing in self._snmp_users(session):
            if existing["name"] == name and existing["group"] and existing["group"] != group:
                lines.add(f"no snmp-server user {name} {existing['group']} v3")
        prefix = f"snmp-server user {name} {group} v3 auth sha "
        shown = prefix + REDACTED + (f" priv aes 128 {REDACTED}" if priv_key else "")
        sent = prefix + auth_key + (f" priv aes 128 {priv_key}" if priv_key else "")
        lines.add(shown, sent, auth_key, priv_key or "")
        return lines.plan()

    def plan_snmp_user_delete(self, session: transport.SshSession, name: str) -> ChangePlan:
        name = validate_username(name)
        groups = [user["group"] for user in self._snmp_users(session) if user["name"] == name and user["group"]]
        if not groups:
            raise InvalidInputError(t("SNMP-Benutzer {name} existiert auf dem Switch nicht.", name=name))
        return cli_plan([f"no snmp-server user {name} {group} v3" for group in dict.fromkeys(groups)])

    def plan_device_aaa(self, session: transport.SshSession, change: AaaChange) -> ChangePlan:
        """Server lists replace the configured servers; logins use the global ``radius``/``tacacs+`` groups."""
        current = dp.parse_aaa(self._sections(session))
        lines = _Lines()
        radius_hosts = [server["host"] for server in current["radius"] if server["host"]]
        tacacs_hosts = [server["host"] for server in current["tacacs"] if server["host"]]
        if change.radius is not None:
            radius_hosts = self._replace_servers(lines, "radius", current["radius"], change.radius)
        if change.tacacs is not None:
            tacacs_hosts = self._replace_servers(lines, "tacacs", current["tacacs"], change.tacacs)
        if change.login_order is not None:
            order = list(dict.fromkeys(change.login_order))
            if "local" not in order:
                raise InvalidInputError(t("Die lokale Anmeldung muss als Rückfallebene erhalten bleiben."))
            for method, hosts, label in (("radius", radius_hosts, "RADIUS"), ("tacacs", tacacs_hosts, "TACACS+")):
                if method in order and not hosts:
                    raise InvalidInputError(t("Für die Anmeldung über {method} ist kein Server konfiguriert.",
                                              method=label))
            methods = " ".join({"local": "local", "radius": "group radius", "tacacs": "group tacacs+"}[method]
                               for method in order)
            if not current["new_model"]:
                lines.add("aaa new-model")
            lines.add(f"aaa authentication login default {methods}")
            lines.add(f"aaa authorization exec default {methods} if-authenticated")
        return lines.plan()

    def _replace_servers(self, lines: _Lines, kind: str, configured: list[dict], wanted) -> list[str]:
        """Add the server blocks for ``wanted`` (RadiusServer/TacacsServer) and remove the others."""
        desired = {}
        for server in wanted:
            host = validate_ipv4(server.host)
            if host in desired:
                raise InvalidInputError(t("Jeder Server darf nur einmal angegeben werden."))
            desired[host] = server
        current = {server["host"]: server for server in configured if server["host"]}
        block, legacy, prefix = (
            ("radius server", "radius-server host", "RAD") if kind == "radius"
            else ("tacacs server", "tacacs-server host", "TAC")
        )
        for host, server in current.items():
            if host not in desired:
                lines.add(f"no {block} {server['name']}" if server["name"] else f"no {legacy} {host}")
        for host, server in desired.items():
            existing = current.get(host)
            key = validate_secret(server.key) if server.key is not None else None
            if kind == "radius":
                address = f"address ipv4 {host} auth-port {int(server.auth_port)} acct-port {int(server.acct_port)}"
                same_ports = existing is not None and (existing["auth_port"], existing["acct_port"]) == (
                    server.auth_port, server.acct_port)
            else:
                address = f"address ipv4 {host}"
                same_ports = existing is not None and existing["port"] == server.port
            if existing is not None and existing["name"] and same_ports and key is None:
                continue
            if key is None and not (existing is not None and existing["name"] and existing["key_configured"]):
                raise InvalidInputError(t("Für den neuen Server {host} ist ein Schlüssel erforderlich.", host=host))
            if existing is not None and not existing["name"]:
                lines.add(f"no {legacy} {host}")
            name = existing["name"] if existing is not None and existing["name"] else _server_name(prefix, host)
            lines.add(f"{block} {name}")
            lines.add(address)
            if key is not None:
                lines.add(f"key {REDACTED}", f"key {key}", key)
            if kind == "tacacs":
                lines.add(f"port {int(server.port)}")
            lines.add("exit")
        return list(desired)

    def _check_own_account(self, session: transport.SshSession, name: str) -> None:
        if name == (session.credentials or {}).get("username"):
            raise InvalidInputError(t("Das Konto, mit dem SwitchSteward sich anmeldet, kann hier nicht geändert werden."))

    def plan_device_user_set(
        self, session: transport.SshSession, name: str, password: str | None, privilege: str,
    ) -> ChangePlan:
        name = validate_username(name)
        self._check_own_account(session, name)
        level = {"admin": 15, "read_only": 1}.get(privilege)
        if level is None:
            raise InvalidInputError(t("Ungültiger Wert für {label}: {value}", label="Privileg", value=repr(privilege)))
        exists = any(user["name"] == name for user in dp.parse_users(self._sections(session)))
        if password is None:
            if not exists:
                raise InvalidInputError(t("Für einen neuen Benutzer ist ein Passwort erforderlich."))
            return cli_plan([f"username {name} privilege {level}"])
        password = validate_secret(password)
        algorithm = "algorithm-type scrypt " if self._mqc else ""
        prefix = f"username {name} privilege {level} {algorithm}secret "
        lines = _Lines()
        lines.add(prefix + REDACTED, prefix + password, password)
        return lines.plan()

    def plan_device_user_delete(self, session: transport.SshSession, name: str) -> ChangePlan:
        """``no username`` asks ``[confirm]`` on IOS-XE: exec steps through configuration mode."""
        name = validate_username(name)
        self._check_own_account(session, name)
        if not any(user["name"] == name for user in dp.parse_users(self._sections(session))):
            raise InvalidInputError(t("Benutzer {name} existiert auf dem Switch nicht.", name=name))
        steps = (
            CliCommand("configure terminal"),
            CliCommand(f"no username {name}", prompts=((r"\[confirm\]", ""),)),
            CliCommand("end"),
        )
        return ChangePlan(lines=tuple(step.command for step in steps), steps=steps)

    def plan_device_ssh(
        self, session: transport.SshSession, timeout_seconds: int | None, telnet_enabled: bool | None,
        web_enabled: bool | None,
    ) -> ChangePlan:
        lines = _Lines()
        if timeout_seconds is not None or telnet_enabled is not None:
            lines.add("line vty 0 15")
            if timeout_seconds is not None:
                seconds = int(timeout_seconds)
                if not 60 <= seconds <= 3600:
                    raise InvalidInputError(t("Ungültiger Wert für {label}: {value}", label="Timeout", value=seconds))
                lines.add(f"exec-timeout {seconds // 60} {seconds % 60}")
            if telnet_enabled is not None:
                lines.add("transport input ssh telnet" if telnet_enabled else "transport input ssh")
            lines.add("exit")
        if web_enabled is True:
            lines.add("ip http secure-server")
        elif web_enabled is False:
            lines.add("no ip http server")
            lines.add("no ip http secure-server")
        return lines.plan()

    # --- Layer 3 -------------------------------------------------------------------------

    def plan_svi_set(
        self, session: transport.SshSession, vlan: int, address: str, prefix_length: int, dhcp_relay: tuple[str, ...],
    ) -> ChangePlan:
        vlan = validate_vlan_id(vlan)
        address = validate_ipv4(address)
        if not 1 <= int(prefix_length) <= 32:
            raise InvalidInputError(t("Ungültiges IPv4-Netz: {value}", value=repr(f"{address}/{prefix_length}")))
        relays = list(dict.fromkeys(validate_ipv4(server) for server in dhcp_relay))
        current = next((svi for svi in dp.parse_l3(self._sections(session))["svis"] if svi["vlan"] == vlan), None)
        body: list[str] = []
        if current is None or (current["address"], current["prefix_length"]) != (address, int(prefix_length)):
            body.append(f"ip address {address} {_mask(prefix_length)}")
        existing = current["dhcp_relay"] if current else []
        body += [f"no ip helper-address {server}" for server in existing if server not in relays]
        body += [f"ip helper-address {server}" for server in relays if server not in existing]
        if current is None or not current["enabled"]:
            body.append("no shutdown")
        if not body:
            raise _no_change()
        return cli_plan([f"interface Vlan{vlan}", *body, "exit"])

    def plan_svi_delete(self, session: transport.SshSession, vlan: int) -> ChangePlan:
        vlan = validate_vlan_id(vlan)
        if not any(svi["vlan"] == vlan for svi in dp.parse_l3(self._sections(session))["svis"]):
            raise InvalidInputError(t("Das VLAN-Interface {vlan} existiert auf dem Switch nicht.", vlan=vlan))
        return cli_plan([f"no interface Vlan{vlan}"])

    def plan_gateway(self, session: transport.SshSession, gateway: str) -> ChangePlan:
        """``ip default-gateway`` without ``ip routing``, otherwise the default route."""
        gateway = validate_ipv4(gateway)
        l3 = dp.parse_l3(self._sections(session))
        if not l3["routing_enabled"]:
            if l3["default_gateway"] == gateway:
                raise _no_change()
            return cli_plan([f"ip default-gateway {gateway}"])
        hops = [route["next_hop"] for route in l3["routes"] if route["prefix_length"] == 0]
        lines = [f"no ip route 0.0.0.0 0.0.0.0 {hop}" for hop in hops if hop != gateway]
        if gateway not in hops:
            lines.append(f"ip route 0.0.0.0 0.0.0.0 {gateway}")
        if not lines:
            raise _no_change()
        return cli_plan(lines)

    def plan_route_add(
        self, session: transport.SshSession, prefix: str, prefix_length: int, next_hop: str, distance: int | None,
    ) -> ChangePlan:
        network = validate_ipv4_prefix(prefix, prefix_length)
        next_hop = validate_ipv4(next_hop)
        if distance is not None and not 1 <= int(distance) <= 255:
            raise InvalidInputError(t("Ungültiger Wert für {label}: {value}", label="Distanz", value=distance))
        l3 = dp.parse_l3(self._sections(session))
        if not l3["routing_enabled"]:
            raise InvalidInputError(t("Statische Routen erfordern ip routing; auf diesem Switch ist Routing nicht aktiv."))
        for route in l3["routes"]:
            if (route["prefix"], route["prefix_length"], route["next_hop"]) == (
                    str(network.network_address), network.prefixlen, next_hop) and (
                    distance is None or route["distance"] == int(distance)):
                raise _no_change()
        line = f"ip route {network.network_address} {network.netmask} {next_hop}"
        return cli_plan([line + (f" {int(distance)}" if distance is not None else "")])

    def plan_route_delete(
        self, session: transport.SshSession, prefix: str, prefix_length: int, next_hop: str,
    ) -> ChangePlan:
        network = validate_ipv4_prefix(prefix, prefix_length)
        next_hop = validate_ipv4(next_hop)
        routes = dp.parse_l3(self._sections(session))["routes"]
        if not any((route["prefix"], route["prefix_length"], route["next_hop"]) == (
                str(network.network_address), network.prefixlen, next_hop) for route in routes):
            raise InvalidInputError(t("Die Route existiert auf dem Switch nicht."))
        return cli_plan([f"no ip route {network.network_address} {network.netmask} {next_hop}"])

    # --- ACLs -----------------------------------------------------------------------------

    def _acl(self, session: transport.SshSession, name: str) -> dict:
        name = validate_acl_name(name)
        acl = next((acl for acl in self._access_lists(session) if acl["name"] == name), None)
        if acl is None:
            raise InvalidInputError(t("ACL {name} existiert auf dem Switch nicht.", name=name))
        return acl

    def plan_acl_create(self, session: transport.SshSession, name: str, acl_type: str) -> ChangePlan:
        name = validate_acl_name(name)
        acl_type = validate_choice(acl_type, ("standard", "extended"), "ACL-Typ")
        if any(acl["name"] == name for acl in self._access_lists(session)):
            raise InvalidInputError(t("ACL {name} existiert bereits.", name=name))
        return cli_plan([f"ip access-list {acl_type} {name}", "exit"])

    def plan_acl_delete(self, session: transport.SshSession, name: str) -> ChangePlan:
        acl = self._acl(session, name)
        bound = dp.parse_acl_bindings(self._sections(session)).get(acl["name"], [])
        if bound:
            interfaces = ", ".join(f"{binding['interface']} ({binding['direction']})" for binding in bound)
            raise InvalidInputError(t("Die ACL ist noch an {interfaces} gebunden.", interfaces=interfaces))
        return cli_plan([f"no ip access-list {acl['type']} {acl['name']}"])

    def plan_acl_entry_add(self, session: transport.SshSession, name: str, entry: AclEntry) -> ChangePlan:
        acl = self._acl(session, name)
        seq = int(entry.seq)
        if not 1 <= seq <= 2147483647:
            raise InvalidInputError(t("Ungültiger Wert für {label}: {value}", label="Seq", value=seq))
        if any(existing["seq"] == seq for existing in acl["entries"]):
            raise InvalidInputError(t("Der Eintrag {seq} existiert bereits.", seq=seq))
        action = validate_choice(entry.action, ("permit", "deny"), "Aktion")
        source = _acl_address(entry.src, entry.src_len)
        if acl["type"] == "standard":
            if entry.protocol != "ip" or entry.dst is not None or entry.dst_port_op is not None:
                raise InvalidInputError(t("Eine Standard-ACL prüft nur die Quelladresse."))
            rule = f"{seq} {action} {source}"
        else:
            protocol = validate_choice(entry.protocol, ("ip", "tcp", "udp", "icmp"), "Protokoll")
            rule = f"{seq} {action} {protocol} {source} {_acl_address(entry.dst, entry.dst_len)}"
            if entry.dst_port_op is not None:
                if protocol not in {"tcp", "udp"}:
                    raise InvalidInputError(t("Zielports gibt es nur für TCP und UDP."))
                if entry.dst_port is None or not 1 <= int(entry.dst_port) <= 65535:
                    raise InvalidInputError(t("Es fehlt der Zielport."))
                if entry.dst_port_op == "eq":
                    rule += f" eq {int(entry.dst_port)}"
                else:
                    end = entry.dst_port_end
                    if end is None or not int(entry.dst_port) <= int(end) <= 65535:
                        raise InvalidInputError(t("Das Ende des Portbereichs muss größer oder gleich dem Anfang sein."))
                    rule += f" range {int(entry.dst_port)} {int(end)}"
        return cli_plan([f"ip access-list {acl['type']} {acl['name']}", rule, "exit"])

    def plan_acl_entry_delete(self, session: transport.SshSession, name: str, seq: int) -> ChangePlan:
        acl = self._acl(session, name)
        if not any(entry["seq"] == int(seq) for entry in acl["entries"]):
            raise InvalidInputError(t("Der Eintrag {seq} existiert nicht.", seq=seq))
        return cli_plan([f"ip access-list {acl['type']} {acl['name']}", f"no {int(seq)}", "exit"])

    def _acl_interface(self, interface: str) -> str:
        interface = self.validate_interface(interface)
        vlan = re.fullmatch(r"(?i)vlan(\d+)", interface)
        if vlan:
            return f"Vlan{validate_vlan_id(vlan.group(1))}"
        if not self.has_switchport(interface):
            raise InvalidInputError(t("Das Interface {interface} kann keine ACL tragen.", interface=interface))
        return interface

    def _bound(self, session: transport.SshSession, name: str, interface: str, direction: str) -> bool:
        key = parsers.interface_key(interface)
        return any(
            parsers.interface_key(binding["interface"]) == key and binding["direction"] == direction
            for binding in dp.parse_acl_bindings(self._sections(session)).get(name, [])
        )

    def plan_acl_bind(self, session: transport.SshSession, name: str, interface: str, direction: str) -> ChangePlan:
        acl = self._acl(session, name)
        interface = self._acl_interface(interface)
        direction = validate_choice(direction, ("in", "out"), "Richtung")
        if self._bound(session, acl["name"], interface, direction):
            raise _no_change()
        return cli_plan([f"interface {interface}", f"ip access-group {acl['name']} {direction}", "exit"])

    def plan_acl_unbind(self, session: transport.SshSession, name: str, interface: str, direction: str) -> ChangePlan:
        name = validate_acl_name(name)
        interface = self._acl_interface(interface)
        direction = validate_choice(direction, ("in", "out"), "Richtung")
        if not self._bound(session, name, interface, direction):
            raise InvalidInputError(t("Die ACL {name} ist an {interface} nicht gebunden.", name=name, interface=interface))
        return cli_plan([f"interface {interface}", f"no ip access-group {name} {direction}", "exit"])

    # --- QoS ------------------------------------------------------------------------------

    def plan_qos_port(
        self, session: transport.SshSession, interface: str, trust: str | None, voice_preset: bool | None,
    ) -> ChangePlan:
        interface = self.validate_interface(interface)
        if not self.has_switchport(interface):
            raise InvalidInputError(t("Ungültiger Interface-Name: {interface}", interface=repr(interface)))
        if trust is not None:
            validate_choice(trust, ("none", "cos", "dscp"), "Trust")
        if trust is None and voice_preset is None:
            raise _no_change()
        sections = self._sections(session)
        key = parsers.interface_key(interface)
        body = next((lines for name, lines in dp.interface_bodies(sections).items()
                     if parsers.interface_key(name) == key), [])
        voice = {True: "auto qos voip cisco-phone", False: "no auto qos voip"}
        if not self._mqc:
            port = {"none": "no mls qos trust", "cos": "mls qos trust cos", "dscp": "mls qos trust dscp"}
            lines = [f"interface {interface}"]
            if trust is not None:
                lines.append(port[trust])
            if voice_preset is not None:
                lines.append(voice[voice_preset])
            lines.append("exit")
            enables = trust in {"cos", "dscp"} or voice_preset is True
            if enables and "mls qos" not in [header for header, _ in sections]:
                # With QoS off nothing is trusted or remarked; enabling it changes every port.
                return cli_plan(
                    ["mls qos", *lines], risk=t("QoS wird global aktiviert; nicht vertrauenswürdige Ports setzen DSCP auf 0."),
                )
            return cli_plan(lines)
        policy = next((match.group(1) for line in body
                       if (match := re.match(r"^service-policy input\s+(\S+)$", line))), None)
        policies = {
            "cos": (dp.TRUST_COS_POLICY, [
                "table-map SM-COS2COS", "default copy", "exit",
                f"policy-map {dp.TRUST_COS_POLICY}", "class class-default", "set cos cos table SM-COS2COS",
                "exit", "exit",
            ]),
            "none": (dp.UNTRUST_POLICY, [
                f"policy-map {dp.UNTRUST_POLICY}", "class class-default", "set dscp default", "exit", "exit",
            ]),
        }
        defined = {header for header, _ in sections}
        lines: list[str] = []
        port: list[str] = []
        if trust is not None:
            target = policies.get(trust, (None, []))[0]
            if policy in {dp.TRUST_COS_POLICY, dp.UNTRUST_POLICY} and policy != target:
                port.append(f"no service-policy input {policy}")
            if target is not None and policy != target:
                if f"policy-map {target}" not in defined:
                    lines += policies[trust][1]
                port.append(f"service-policy input {target}")
        if voice_preset is not None:
            port.append("auto qos voip cisco-phone" if voice_preset else "no auto qos voip cisco-phone")
        if not port:
            raise _no_change()
        return cli_plan([*lines, f"interface {interface}", *port, "exit"])

    # --- Firmware ---------------------------------------------------------------

    def read_firmware(self, session: transport.SshSession) -> dict:
        version = self._device_show(session, "show version")
        boot = dp.parse_boot(self._device_optional_show(session, "show boot") or "")
        files, free = dp.parse_dir(self._device_optional_show(session, "dir flash:") or "")
        return {
            "running_version": parsers.parse_show_version(version)["software_version"],
            "boot_images": boot,
            "next_boot": boot[0] if boot else None,
            "install_mode": dp.parse_install_mode(version),
            "free_bytes": free,
            "files": files,
        }

    @staticmethod
    def _image_file(image: FirmwareImage) -> str:
        if not _FILENAME_RE.fullmatch(image.filename or ""):
            raise InvalidInputError(t(
                "Ungültiger Dateiname: erlaubt sind 1–128 Zeichen A–Z, a–z, 0–9, Punkt, Unterstrich und Bindestrich "
                "(erstes Zeichen Buchstabe oder Ziffer)."
            ))
        return image.filename

    def plan_firmware_stage(
        self, session: transport.SshSession, image: FirmwareImage, transfer: TransferLocation, firmware: dict,
    ) -> ChangePlan:
        """``copy {url} flash:{file}`` + ``verify /md5`` (bundle and install mode)."""
        filename = self._image_file(image)
        free = firmware.get("free_bytes")
        if free is not None and free < image.size:
            raise InvalidInputError(t("Nicht genug freier Speicher auf dem Switch."))
        md5 = image.md5.lower()
        if not re.fullmatch(r"[0-9a-f]{32}", md5):
            raise InvalidInputError(t("Ungültiger Wert für {label}: {value}", label="MD5", value=repr(image.md5)))
        copy = CliCommand(
            f"copy {transfer.url} flash:{filename}", prompts=_COPY_PROMPTS, timeout=FIRMWARE_TIMEOUT_SECONDS,
            success=r"bytes copied|\[OK",
        )
        verify = CliCommand(f"verify /md5 flash:{filename} {md5}", timeout=FIRMWARE_TIMEOUT_SECONDS, success="Verified")
        return ChangePlan(
            lines=(f"copy {transfer.display_url} flash:{filename}", verify.command),
            steps=(copy, verify),
            secrets=_transfer_secrets(transfer),
            persistent=True,
        )

    def plan_firmware_activate(
        self, session: transport.SshSession, image: FirmwareImage, firmware: dict, reload_now: bool,
    ) -> ChangePlan:
        """Install mode: ``install add … activate commit`` reloads by itself; bundle: boot variable + save."""
        filename = self._image_file(image)
        if filename not in (firmware.get("files") or []):
            raise InvalidInputError(t("Das Image {file} liegt nicht im Flash des Switches; bitte zuerst übertragen.",
                                      file=filename))
        if firmware.get("install_mode"):
            if not reload_now:
                raise InvalidInputError(t(
                    "Im Install-Modus startet die Aktivierung den Switch neu; bitte „jetzt“ oder einen Zeitpunkt wählen."
                ))
            step = CliCommand(
                f"install add file flash:{filename} activate commit prompt-level none", prompts=_INSTALL_PROMPTS,
                timeout=FIRMWARE_TIMEOUT_SECONDS, expect_disconnect=True,
            )
            return ChangePlan(lines=(step.command,), steps=(step,), reloads=True)
        timeout = max(session.conn.read_timeout_override or 0, transport.SAVE_CONFIG_MIN_TIMEOUT_SECONDS)
        save = CliCommand("write memory", timeout=int(timeout), success=r"\[OK\]")
        boot = ChangePlan(
            lines=("no boot system", f"boot system flash:{filename}", save.command),
            steps=(CliLines(("no boot system", f"boot system flash:{filename}")), save),
            warnings=(t("Die aktuelle Konfiguration wird dabei gespeichert (write memory)."),),
            persistent=True,
        )
        return combine_plans(boot, self.plan_reload(session)) if reload_now else boot

    # --- Diagnostics ----------------------------------------------------------------------

    def read_counters(self, session: transport.SshSession, interface: str | None) -> list[dict]:
        if interface is not None:
            interface = self.validate_interface(interface)
            return dp.parse_counters(self._device_show(session, f"show interfaces {interface}"))
        rows = dp.parse_counters(self._device_show(session, "show interfaces"))
        return [row for row in rows if self.has_switchport(row["interface"])]

    def plan_counters_clear(self, session: transport.SshSession, interface: str) -> ChangePlan:
        interface = self.validate_interface(interface)
        step = CliCommand(f"clear counters {interface}", prompts=((r"\[confirm\]", ""),))
        return ChangePlan(lines=(step.command,), steps=(step,), persistent=True)

    def read_transceivers(self, session: transport.SshSession) -> list[dict]:
        return dp.parse_transceivers(self._device_show(session, "show interfaces transceiver", empty_ok=True))

    def read_log(self, session: transport.SshSession, lines: int = 500) -> list[str]:
        return dp.parse_log(self._device_show(session, "show logging"), int(lines))

    def read_environment(self, session: transport.SshSession) -> dict:
        return dp.parse_environment(self._device_show(session, "show env all"))

    def plan_cable_test(self, session: transport.SshSession, interface: str) -> ChangePlan:
        interface = self.validate_interface(interface)
        if not self.is_physical_interface(interface):
            raise InvalidInputError(t("Ungültiger Interface-Name: {interface}", interface=repr(interface)))
        step = CliCommand(f"test cable-diagnostics tdr interface {interface}", prompts=((r"\[confirm\]", ""),))
        return ChangePlan(lines=(step.command,), steps=(step,), persistent=True)

    def read_cable_test(self, session: transport.SshSession, interface: str) -> dict:
        interface = self.validate_interface(interface)
        command = f"show cable-diagnostics tdr interface {interface}"
        output = transport.send_show(session.conn, command)
        if isinstance(output, str) and "not supported" in output.lower() and parsers.extract_ios_errors(output):
            return {"status": "unsupported", "pairs": []}
        try:
            parsers.ensure_show_output(output, command)
        except SwitchConnectionError:
            if isinstance(output, str) and re.search(r"never (?:been )?(?:run|issued)", output, re.IGNORECASE):
                return {"status": "running", "pairs": []}
            raise
        return dp.parse_cable_test(output)
