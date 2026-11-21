"""Change plans: the steps a driver sends for one write, built before anything is sent.

A plan is built inside a device session (it may read the device first), shown to the
user as a preview (``lines``, secrets redacted) and executed unchanged on apply
(``steps``, real values; never leaves the server). Drivers build plans with the
``plan_*`` methods of ``SwitchDriver`` and run them with ``execute_plan``.

Also holds the typed change requests passed to the ``plan_*`` methods.
"""

from dataclasses import dataclass, field
from typing import Literal

REDACTED = "********"


# --- Steps ----------------------------------------------------------------------------


@dataclass(frozen=True)
class CliLines:
    """Configuration lines sent with ``cli.run_config_lines`` (line by line, stop at the first error)."""

    lines: tuple[str, ...]
    enter: bool = True
    exit: bool = True
    # e.g. "configure terminal revert timer 5" (Cisco confirmed change); None = Netmiko default.
    config_mode_command: str | None = None


@dataclass(frozen=True)
class CliCommand:
    """Exec-mode command sent with ``cli.run_exec``.

    ``prompts``: (regex, answer) pairs for interactive questions (answer "" = Enter).
    ``expect_disconnect``: EOF/timeout after the command counts as success (reload).
    ``success``: regex that must occur in the output, otherwise the step failed.
    """

    command: str
    prompts: tuple[tuple[str, str], ...] = ()
    timeout: int = 30
    expect_disconnect: bool = False
    success: str | None = None


@dataclass(frozen=True)
class Pause:
    seconds: int


@dataclass(frozen=True)
class RestCall:
    """One REST request (MikroTik); ``body`` is sent as JSON.

    ``expect_disconnect``: a dropped connection or timeout counts as success (reboot).
    """

    method: Literal["GET", "PUT", "PATCH", "POST", "DELETE"]
    path: str
    body: dict | None = field(default=None, hash=False, compare=True)
    expect_disconnect: bool = False


Step = CliLines | CliCommand | Pause | RestCall


@dataclass(frozen=True)
class ChangePlan:
    """``lines``: displayed, redacted commands; ``steps``: what is actually sent.

    ``risk``: German reason that requires an explicit confirmation (operators are refused).
    ``persistent``: the change is saved on the device by itself (no "unsaved" state).
    ``reloads``: the device restarts as part of the plan.
    ``message``: success message (German, already translated); None = generic text.
    ``config_mode_command``: only on rollback-arm plans: config-mode command the following
    change plan's ``CliLines`` must use (Cisco ``configure terminal revert timer N``).
    ``secrets``: every secret value contained in ``steps`` (passwords, keys, transfer token
    secrets). They never appear in ``lines``; ``execute_plan`` removes them from logs,
    failure messages and device output (``redact``). A plan carrying a secret MUST list it.
    """

    lines: tuple[str, ...]
    steps: tuple[Step, ...]
    warnings: tuple[str, ...] = ()
    risk: str | None = None
    persistent: bool = False
    reloads: bool = False
    message: str | None = None
    config_mode_command: str | None = None
    secrets: tuple[str, ...] = ()


def redact(text: str, secrets) -> str:
    """Replace every secret value (longest first) in ``text`` with ``REDACTED``."""
    if not text:
        return text
    for secret in sorted((value for value in secrets if value), key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    return text


def cli_plan(lines, **kwargs) -> ChangePlan:
    """Plan of one configuration block whose displayed lines equal the sent lines."""
    lines = tuple(lines)
    return ChangePlan(lines=lines, steps=(CliLines(lines),), **kwargs)


def combine_plans(*plans: ChangePlan, message: str | None = None) -> ChangePlan:
    """Concatenate plans (lines, steps, warnings, secrets); the first risk wins; flags are OR-ed."""
    plans = tuple(plan for plan in plans if plan is not None)
    risk = next((plan.risk for plan in plans if plan.risk), None)
    return ChangePlan(
        lines=tuple(line for plan in plans for line in plan.lines),
        steps=tuple(step for plan in plans for step in plan.steps),
        warnings=tuple(dict.fromkeys(warning for plan in plans for warning in plan.warnings)),
        risk=risk,
        persistent=any(plan.persistent for plan in plans),
        reloads=any(plan.reloads for plan in plans),
        message=message if message is not None else next((plan.message for plan in plans if plan.message), None),
        secrets=tuple(dict.fromkeys(secret for plan in plans for secret in plan.secrets)),
    )


# --- File transfer (restore, firmware) ------------------------------------------------


@dataclass(frozen=True)
class TransferLocation:
    """Where the switch downloads a file from SwitchSteward.

    ``url``/``password`` carry the real one-time credentials and only go into steps;
    ``display_url`` (credentials replaced by ``REDACTED``) goes into plan lines. In a
    preview the credentials are placeholders, so the displayed lines are identical.
    http: ``url`` = ``{base}/transfer/{token}/{filename}``, ``username``/``password`` empty.
    sftp: ``url`` = ``sftp://{username}@{host}[:{port}]/{filename}``.
    """

    method: Literal["http", "sftp"]
    url: str
    display_url: str
    host: str
    port: int
    username: str
    password: str
    filename: str


@dataclass(frozen=True)
class FirmwareImage:
    id: int
    filename: str
    size: int
    sha256: str
    md5: str


# --- Port security -----------------------------------------------------------


@dataclass(frozen=True)
class PortSecuritySettings:
    enabled: bool
    max_macs: int | None = None
    sticky: bool | None = None
    violation: Literal["protect", "restrict", "shutdown"] | None = None


@dataclass(frozen=True)
class Dot1xSettings:
    mode: Literal["off", "dot1x", "mab", "dot1x_mab"]
    host_mode: Literal["single", "multi_auth", "multi_host", "multi_domain"] | None = None
    guest_vlan: int | None = None  # 0 = remove
    auth_fail_vlan: int | None = None  # 0 = remove


@dataclass(frozen=True)
class StpGuardSettings:
    bpdu_guard: bool | None = None
    root_guard: bool | None = None
    loop_guard: bool | None = None


@dataclass(frozen=True)
class StormControlSettings:
    """Percent of link speed; None = unchanged, 0 = off."""

    broadcast: float | None = None
    multicast: float | None = None
    unknown_unicast: float | None = None
    action: Literal["drop", "shutdown"] | None = None


@dataclass(frozen=True)
class SecurityChange:
    """Per-port security change; ``None`` leaves a block unchanged."""

    port_security: PortSecuritySettings | None = None
    dot1x: Dot1xSettings | None = None
    stp_guard: StpGuardSettings | None = None
    storm_control: StormControlSettings | None = None
    dhcp_snooping_trust: bool | None = None
    arp_inspection_trust: bool | None = None
    ip_source_guard: bool | None = None


@dataclass(frozen=True)
class SecurityGlobalChange:
    dhcp_snooping_enabled: bool | None = None
    dhcp_snooping_vlans: tuple[int, ...] | None = None  # replaces the list
    arp_inspection_vlans: tuple[int, ...] | None = None  # replaces the list
    dot1x_enabled: bool | None = None


# --- Device settings ---------------------------------------------------------


@dataclass(frozen=True)
class IdentityChange:
    hostname: str | None = None
    banner: str | None = None  # "" removes
    snmp_location: str | None = None  # "" removes
    snmp_contact: str | None = None  # "" removes


@dataclass(frozen=True)
class SyslogTarget:
    host: str
    severity: int  # 0-7


@dataclass(frozen=True)
class ServicesChange:
    """Lists replace the configured lists (plan removes missing, adds new entries)."""

    ntp_servers: tuple[str, ...] | None = None
    timezone_name: str | None = None
    timezone_offset_minutes: int | None = None
    dns_servers: tuple[str, ...] | None = None
    domain_name: str | None = None  # "" removes
    syslog: tuple[SyslogTarget, ...] | None = None


@dataclass(frozen=True)
class SnmpUserChange:
    name: str
    auth: Literal["sha", "sha256"]
    auth_key: str
    priv: Literal["aes128"] | None
    priv_key: str | None
    access: Literal["ro", "rw"]


@dataclass(frozen=True)
class RadiusServer:
    host: str
    key: str | None = None  # None = keep the configured key
    auth_port: int = 1812
    acct_port: int = 1813


@dataclass(frozen=True)
class TacacsServer:
    host: str
    key: str | None = None
    port: int = 49


@dataclass(frozen=True)
class AaaChange:
    """Lists replace the configured servers; ``login_order`` always contains "local"."""

    radius: tuple[RadiusServer, ...] | None = None
    tacacs: tuple[TacacsServer, ...] | None = None
    login_order: tuple[Literal["local", "radius", "tacacs"], ...] | None = None


@dataclass(frozen=True)
class AclEntry:
    seq: int
    action: Literal["permit", "deny"]
    protocol: Literal["ip", "tcp", "udp", "icmp"]
    src: str
    src_len: int
    dst: str | None = None  # None = any
    dst_len: int | None = None
    dst_port_op: Literal["eq", "range"] | None = None
    dst_port: int | None = None
    dst_port_end: int | None = None
