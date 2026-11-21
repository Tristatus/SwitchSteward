"""Vendor-neutral validation of values that end up in device commands.

Every value interpolated into a device command must pass through one of these
functions first; a line break in a description would otherwise inject commands.
"""

import ipaddress
import re
from typing import Literal, Union

from ..i18n import t
from .errors import InvalidInputError

MAX_VLAN_LIST_LENGTH = 24576
_VLAN_LIST_RE = re.compile(r"^(all|none|[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*)$", re.IGNORECASE)

# Normalized trunk VLAN selection: "all", "none" or the sorted, unique VLAN IDs.
VlanSelection = Union[Literal["all", "none"], tuple[int, ...]]


def validate_vlan_id(vlan_id) -> int:
    if isinstance(vlan_id, bool) or not isinstance(vlan_id, (int, str)):
        raise InvalidInputError(t("Ungültige VLAN-ID: {value}", value=repr(vlan_id)))
    try:
        value = int(vlan_id)
    except (TypeError, ValueError):
        raise InvalidInputError(t("Ungültige VLAN-ID: {value}", value=repr(vlan_id))) from None
    if not 1 <= value <= 4094:
        raise InvalidInputError(t("VLAN-ID außerhalb des gültigen Bereichs 1-4094: {value}", value=value))
    return value


def parse_vlan_list(vlan_list: str) -> VlanSelection:
    """Parse ``all``, ``none`` or a list such as ``10,20,30-40`` into a VlanSelection."""
    if (
        not isinstance(vlan_list, str)
        or len(vlan_list) > MAX_VLAN_LIST_LENGTH
        or any(ord(char) < 32 or ord(char) == 127 for char in vlan_list)
    ):
        raise InvalidInputError(t("Die VLAN-Liste ist zu lang oder enthaelt ungueltige Zeichen."))
    value = re.sub(r" *([,-]) *", r"\1", vlan_list.strip())
    if not _VLAN_LIST_RE.fullmatch(value):
        raise InvalidInputError(
            t("Ungültige VLAN-Liste: {value} (erlaubt: 'all', 'none' oder z.B. '10,20,30-40')", value=repr(vlan_list))
        )
    if value.lower() in {"all", "none"}:
        return value.lower()
    vlans = set()
    for item in value.split(","):
        parts = [part.lstrip("0") or "0" for part in item.split("-")]
        if any(len(part) > 4 for part in parts):
            raise InvalidInputError(t("Ungültiger VLAN-Bereich: {value}", value=repr(item)))
        bounds = [int(part) for part in parts]
        if any(not 1 <= bound <= 4094 for bound in bounds) or (len(bounds) == 2 and bounds[0] > bounds[1]):
            raise InvalidInputError(t("Ungültiger VLAN-Bereich: {value}", value=repr(item)))
        vlans.update(range(bounds[0], bounds[-1] + 1))
    return tuple(sorted(vlans))


def vlan_ranges(selection: tuple[int, ...]) -> list[str]:
    """Compress sorted VLAN IDs into items such as ``10``, ``30-40``."""
    items = []
    start = previous = None
    for vlan in selection:
        if start is None:
            start = previous = vlan
        elif vlan == previous + 1:
            previous = vlan
        else:
            items.append(str(start) if start == previous else f"{start}-{previous}")
            start = previous = vlan
    if start is not None:
        items.append(str(start) if start == previous else f"{start}-{previous}")
    return items


def format_vlan_list(selection: VlanSelection) -> str:
    """Inverse of ``parse_vlan_list``: ``all``, ``none`` or ``10,20,30-40``."""
    if isinstance(selection, str):
        return selection
    return ",".join(vlan_ranges(selection))


def sanitize_description(value: str | None, max_length: int) -> str:
    """Reject control characters (command injection) and overlong descriptions."""
    text = value or ""
    if len(text) > max_length or any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise InvalidInputError(
            t("Die Description darf höchstens {max_length} Zeichen und keine Steuerzeichen enthalten.", max_length=max_length)
        )
    return text.strip()


def validate_choice(value: str, allowed, label: str) -> str:
    if value not in allowed:
        raise InvalidInputError(t("Ungültiger Wert für {label}: {value}", label=t(label), value=repr(value)))
    return value


# Device settings
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_DNS_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_ACL_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,31}$")


def validate_hostname(value: str) -> str:
    if not isinstance(value, str) or not _HOSTNAME_RE.fullmatch(value):
        raise InvalidInputError(t("Ungültiger Hostname: {value}", value=repr(value)))
    return value


def validate_banner(value: str) -> str:
    """Printable ASCII and line breaks, max. 1000 characters, no banner delimiters ``^ # "``."""
    if (
        not isinstance(value, str)
        or len(value) > 1000
        or any(not (char == "\n" or 32 <= ord(char) < 127) or char in '^#"' for char in value)
    ):
        raise InvalidInputError(
            t("Der Banner darf höchstens 1000 druckbare ASCII-Zeichen enthalten, aber keines von ^ # \".")
        )
    return value.replace("\r", "")


def validate_snmp_text(value: str) -> str:
    text = sanitize_description(value, 255)
    if '"' in text:
        raise InvalidInputError(t("Der Text darf keine Anführungszeichen enthalten."))
    return text


def validate_host(value: str) -> str:
    """IPv4 address or DNS name (max. 253 characters)."""
    if isinstance(value, str):
        try:
            return str(ipaddress.IPv4Address(value))
        except ValueError:
            pass
        if len(value) <= 253 and _DNS_NAME_RE.fullmatch(value) and not re.fullmatch(r"[0-9.]+", value):
            return value
    raise InvalidInputError(t("Ungültige Adresse: {value}", value=repr(value)))


def validate_ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except (ValueError, TypeError):
        raise InvalidInputError(t("Ungültige IPv4-Adresse: {value}", value=repr(value))) from None


def validate_ipv4_prefix(prefix: str, prefix_length: int) -> ipaddress.IPv4Network:
    """Network address plus length; host bits must be zero."""
    try:
        return ipaddress.IPv4Network(f"{prefix}/{int(prefix_length)}", strict=True)
    except (ValueError, TypeError):
        raise InvalidInputError(
            t("Ungültiges IPv4-Netz: {value}", value=repr(f"{prefix}/{prefix_length}"))
        ) from None


def validate_secret(value: str) -> str:
    """8–64 printable ASCII characters without blanks, ``"``, ``?`` and ``\\``. Never echo the value."""
    if (
        not isinstance(value, str)
        or not 8 <= len(value) <= 64
        or any(not 33 <= ord(char) < 127 or char in '"?\\' for char in value)
    ):
        raise InvalidInputError(
            t("Schlüssel und Passwörter brauchen 8-64 druckbare Zeichen ohne Leerzeichen, \", ? und \\.")
        )
    return value


def validate_vtp_password(value: str) -> str:
    """VTP password: the ``validate_secret`` rules and at most 32 characters."""
    value = validate_secret(value)
    if len(value) > 32:
        raise InvalidInputError(t("Das VTP-Passwort darf höchstens 32 Zeichen lang sein."))
    return value


def validate_vtp_domain(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", value):
        raise InvalidInputError(t(
            "Ungültiger VTP-Domänenname: 1–32 Zeichen, erlaubt sind Buchstaben, Ziffern, Punkt, Unterstrich "
            "und Bindestrich."
        ))
    return value


def validate_username(value: str) -> str:
    if not isinstance(value, str) or not _USERNAME_RE.fullmatch(value):
        raise InvalidInputError(t("Ungültiger Benutzername: {value}", value=repr(value)))
    return value


def validate_acl_name(value: str) -> str:
    if not isinstance(value, str) or not _ACL_NAME_RE.fullmatch(value) or value.isdigit():
        raise InvalidInputError(t("Ungültiger ACL-Name: {value}", value=repr(value)))
    return value
