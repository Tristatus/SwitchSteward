"""VTP domain overview: the VTP status of every switch with VTP support, grouped by domain, with problem hints."""

import contextvars
import logging
from concurrent.futures import ThreadPoolExecutor

from .. import database as db
from ..i18n import t
from . import features
from .coalescing import coalesced_read
from .drivers import get_driver

logger = logging.getLogger("switchsteward.switches.vtp_overview")

_MAX_WORKERS = 8
_SYNC_MODES = ("server", "client")
_MEMBER_FIELDS = (
    "mode", "primary_server", "version", "revision", "md5_digest", "primary_id", "primary_description",
    "device_id", "pruning", "password_configured", "domain",
)

NO_DOMAIN = "Switches im Modus Server/Client ohne VTP-Domäne: {names}."
MIXED_VERSIONS = "Unterschiedliche VTP-Versionen im Modus Server/Client: {details}."
OUT_OF_SYNC = "Die Server/Clients sind nicht synchron (Revision/MD5 unterschiedlich): {details}."
PARTIAL_PASSWORD = "VTP-Passwort nur auf einem Teil der Switches gesetzt: {names}."  # noqa: S105 - message, not a password
MIXED_PRIMARIES = "Die Switches melden unterschiedliche Primary Server: {ids}."
MULTIPLE_PRIMARIES = "Mehrere Switches sind Primary Server: {names}."
NO_ACTIVE_PRIMARY = (
    "Kein Switch ist aktuell Primary Server (zuletzt {name}); VLAN-Änderungen sind erst nach "
    "'Primary übernehmen' möglich."
)
UNMANAGED_PRIMARY = (
    "Der Primary Server {description} ({id}) wird nicht von SwitchSteward verwaltet; sein Status kann nicht "
    "geprüft werden."
)
NO_PRIMARY = "Die Domäne hat keinen Primary Server; VLAN-Änderungen sind erst nach 'Primary übernehmen' möglich."
NO_MANAGED_SERVER = (
    "Kein verwalteter VTP-Server in der Domäne; die Clients erhalten ihre VLANs von einem nicht verwalteten Switch."
)
MISSING_CREDENTIALS = "Für diesen Switch fehlen Zugangsdaten für die gewählte Quelle (global/eigen)."


def _names(members) -> str:
    return ", ".join(member["name"] for member in members)


def _issue(severity: str, message: str, **params) -> dict:
    return {"severity": severity, "message": t(message, **params)}


def analyze_domain(members: list[dict]) -> list[dict]:
    """Problem hints of one domain's members (``read_vtp`` facts plus ``name``), in rule order."""
    issues = []
    sync = [member for member in members if member["mode"] in _SYNC_MODES]
    if sync and all(member["domain"] is None for member in members):
        issues.append(_issue("warning", NO_DOMAIN, names=_names(sync)))
    if len({member["version"] for member in sync}) > 1:
        details = ", ".join(f"{member['name']} v{member['version']}" for member in sync)
        issues.append(_issue("warning", MIXED_VERSIONS, details=details))
    if len({(member["revision"], member["md5_digest"]) for member in sync}) > 1:
        details = ", ".join(f"{member['name']} r{member['revision']}" for member in sync)
        issues.append(_issue("warning", OUT_OF_SYNC, details=details))
    passwords = {member["password_configured"] for member in sync} - {None}
    if passwords == {True, False}:
        issues.append(_issue(
            "warning", PARTIAL_PASSWORD, names=_names(m for m in sync if m["password_configured"] is True),
        ))
    if sync and all(member["version"] == 3 for member in sync):
        primary_ids = list(dict.fromkeys(member["primary_id"] for member in sync if member["primary_id"]))
        primaries = [member for member in sync if member["primary_server"] is True]
        if len(primary_ids) > 1:
            issues.append(_issue("warning", MIXED_PRIMARIES, ids=", ".join(primary_ids)))
        if len(primaries) > 1:
            issues.append(_issue("warning", MULTIPLE_PRIMARIES, names=_names(primaries)))
        if not primaries and not primary_ids:
            issues.append(_issue("warning", NO_PRIMARY))
        elif not primaries and len(primary_ids) == 1:
            owner = next((member for member in members if member["device_id"] == primary_ids[0]), None)
            if owner is not None:
                issues.append(_issue("warning", NO_ACTIVE_PRIMARY, name=owner["name"]))
            else:
                description = next(
                    (member["primary_description"] for member in sync if member["primary_description"]), None,
                )
                issues.append(_issue("info", UNMANAGED_PRIMARY, description=description or "–", id=primary_ids[0]))
    elif sync and all(member["version"] in (1, 2) for member in sync):
        if not any(member["mode"] == "server" for member in sync):
            issues.append(_issue("info", NO_MANAGED_SERVER))
    return issues


def _read_member(switch: dict) -> tuple[str, dict]:
    """("member" | "skipped" | "unreadable" | "ignored", entry)."""
    driver = get_driver(switch.get("device_type"))
    if driver is None or not features.for_switch(driver, switch)["vtp"].supported:
        return "ignored", {}
    entry = {"switch_id": switch["id"], "name": switch["name"]}
    connection = db.get_switch_connection(switch["id"])
    if not connection or not connection["credentials"]:
        return "skipped", {**entry, "reason": t(MISSING_CREDENTIALS)}
    try:
        with driver.session(connection["switch"], connection["credentials"]) as session:
            status = driver.read_vtp(session)
    except Exception as exc:
        logger.warning("VTP status of switch %s could not be read: %s", switch.get("name"), exc)
        return "unreadable", {**entry, "reason": str(exc) or type(exc).__name__}
    return "member", {**entry, **{key: status.get(key) for key in _MEMBER_FIELDS}}


@coalesced_read
def overview() -> dict:
    switches = db.list_switches()
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = [pool.submit(contextvars.copy_context().run, _read_member, switch) for switch in switches]
        outcomes = [future.result() for future in futures]
    groups: dict[str | None, list[dict]] = {}
    skipped, unreadable = [], []
    for kind, entry in outcomes:
        if kind == "member":
            groups.setdefault(entry["domain"], []).append(entry)
        elif kind == "skipped":
            skipped.append(entry)
        elif kind == "unreadable":
            unreadable.append(entry)
    domains = []
    for domain in sorted(groups, key=lambda name: (name is None, name or "")):
        members = sorted(groups[domain], key=lambda member: member["name"])
        domains.append({"domain": domain, "members": members, "issues": analyze_domain(members)})
    return {"domains": domains, "skipped": skipped, "unreadable": unreadable}
