"""Cisco VTP: ``show vtp status`` / ``show vtp password`` parsers and the configuration plan."""

import re
from collections.abc import Mapping

from ....i18n import t
from ...errors import SwitchConnectionError
from ...validation import validate_choice, validate_vtp_domain, validate_vtp_password
from .. import cli
from ..plans import REDACTED, ChangePlan, CliLines

VTP_MODES = ("server", "client", "transparent", "off")
# Device text (lowercase) -> (mode, is VTPv3 primary server).
_MODES = {
    "server": ("server", False),
    "primary server": ("server", True),
    "client": ("client", False),
    "transparent": ("transparent", False),
    "off": ("off", False),
}
_NO_PRIMARY_ID = "0000.0000.0000"


def _segments(output: str) -> tuple[dict[str, str], dict[str, str], dict[str, str], str]:
    """Global, VLAN and MST key/values (lowercase keys) plus the VLAN segment text.

    ``parse_key_values`` keeps the first occurrence of a key, and the VLAN and MST
    blocks repeat keys such as ``VTP Operating Mode``: parse each block on its own.
    Without a ``Feature VLAN:`` header (older IOS) the global block is the VLAN block.
    """
    parts = re.split(r"^\s*Feature (\w+):\s*$", output or "", flags=re.MULTILINE)
    blocks = {name.upper(): body for name, body in zip(parts[1::2], parts[2::2], strict=True)}
    vlan_text = blocks.get("VLAN", parts[0])

    def values(text: str) -> dict[str, str]:
        return {key.lower(): value for key, value in cli.parse_key_values(text).items()}

    return values(parts[0]), values(vlan_text), values(blocks.get("MST", "")), vlan_text


def _int(value: str | None) -> int | None:
    return int(value) if value is not None and value.strip().isdigit() else None


def _mode(value: str | None) -> tuple[str | None, bool]:
    return _MODES.get(re.sub(r"\s+", " ", (value or "").strip().lower()), (None, False))


def _version(values: Mapping[str, str]) -> int | None:
    running = _int(values.get("vtp version running"))
    if running is not None:
        return running
    text = values.get("vtp version") or ""
    match = re.search(r"running VTP(\d)", text, re.IGNORECASE)
    if match:
        return int(match.group(1))
    if text.strip().isdigit():
        return 2 if (values.get("vtp v2 mode") or "").strip().lower() == "enabled" else 1
    return None


def parse_vtp_status(output: str) -> dict:
    """``show vtp status`` facts; raises ``SwitchConnectionError`` when no operating mode is found."""
    global_values, vlan_values, mst_values, vlan_text = _segments(output)
    merged = {**global_values, **vlan_values}
    mode, primary = _mode(vlan_values.get("vtp operating mode"))
    if mode is None:
        raise SwitchConnectionError(
            t("Die Ausgabe von '{command}' hat ein unbekanntes Format.", command="show vtp status"),
        )
    version = _version(merged)
    pruning = merged.get("vtp pruning mode")
    md5 = re.search(r"MD5 digest\s*:\s*((?:0x[0-9A-Fa-f]{2}\s*)+)", vlan_text)
    modified = re.search(r"^\s*Configuration last modified by (.+?)\s*$", output, re.MULTILINE)
    primary_id = vlan_values.get("primary id") or None
    return {
        "version": version,
        "version_capable": merged.get("vtp version capable") or None,
        "domain": merged.get("vtp domain name") or None,
        "mode": mode,
        "primary_server": primary if version == 3 else None,
        "pruning": pruning.strip().lower() == "enabled" if pruning is not None else None,
        "device_id": merged.get("device id") or None,
        "revision": _int(vlan_values.get("configuration revision")),
        "primary_id": None if primary_id == _NO_PRIMARY_ID else primary_id,
        "primary_description": vlan_values.get("primary description") or None,
        "vlan_count": _int(vlan_values.get("number of existing vlans")),
        "max_vlans": _int(vlan_values.get("maximum vlans supported locally")),
        "md5_digest": re.sub(r"0x|\s", "", md5.group(1)).upper() if md5 else None,
        "last_modified": modified.group(1) if modified else None,
        "mst_mode": _mode(mst_values.get("vtp operating mode"))[0],
    }


def parse_vtp_password(output: str | None) -> bool | None:
    """Whether a VTP password is set. The output may contain the plaintext password:
    only this bool may leave the function."""
    if not output:
        return None
    if re.search(r"not configured", output, re.IGNORECASE):
        return False
    if re.search(r"\bis configured", output, re.IGNORECASE):
        return True
    if re.search(r"^\s*VTP Password\s*:\s*\S", output, re.IGNORECASE | re.MULTILINE):
        return True
    if re.search(r"^\s*VTP Password\s*:\s*$", output, re.IGNORECASE | re.MULTILINE):
        return False
    return None


def configure_plan(current: Mapping, change) -> ChangePlan:
    """Lines for the fields of ``change`` (a ``VtpChange``) that differ from ``current``.

    Order matters: version 3 needs the domain first, ``hidden`` needs version 3.
    """
    changed = change.changed(current)
    shown: list[str] = []
    sent: list[str] = []

    def add(line: str, display: str | None = None) -> None:
        sent.append(line)
        shown.append(display or line)

    if "domain" in changed:
        add(f"vtp domain {validate_vtp_domain(change.domain)}")
    if "version" in changed:
        add(f"vtp version {validate_choice(change.version, (1, 2, 3), 'VTP-Version')}")
    password = None
    if "password" in changed:
        password = validate_vtp_password(change.password)
        suffix = " hidden" if change.password_hidden else ""
        add(f"vtp password {password}{suffix}", f"vtp password {REDACTED}{suffix}")
    elif "clear_password" in changed:
        add("no vtp password")
    if "mode" in changed:
        add(f"vtp mode {validate_choice(change.mode, VTP_MODES, 'VTP-Modus')}")
    if "pruning" in changed:
        add("vtp pruning" if change.pruning else "no vtp pruning")
    if not sent:
        return ChangePlan(lines=(), steps=())
    return ChangePlan(
        lines=tuple(shown),
        steps=(CliLines(tuple(sent)),),
        secrets=(password,) if password else (),
        message=t("VTP-Einstellungen übernommen (noch nicht dauerhaft gespeichert)."),
    )
