"""Backups of a switch (list, content, diff), running-vs-startup comparison and the rollback timer.

Diffs are unified diffs (``difflib``) of the normalized texts (volatile lines of the driver
removed), at most ``MAX_DIFF_LINES`` lines; each line keeps its ``+``/``-``/`` `` marker.
"""

import difflib
import re

from fastapi import HTTPException, status

from .. import backups
from ..audit import audited_write
from ..auth import Principal
from ..device_locks import write_lock
from ..i18n import t
from . import config_state, features
from .coalescing import invalidates_reads
from .drivers import get_driver
from .errors import ChangeConflict, InvalidInputError

MAX_DIFF_LINES = 5000
_FILENAME_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _not_found() -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, detail=t("Backup nicht gefunden."))


def _driver(switch: dict):
    return get_driver(switch.get("device_type"))


def _capabilities(switch: dict):
    return features.for_switch(_driver(switch), switch)


def list_backups(switch: dict) -> dict:
    rows = backups.list_backups(switch["id"])
    keys = ("id", "created_at", "trigger", "source", "size", "encrypted", "created_by")
    return {"backups": [{key: row[key] for key in keys} for row in rows], "warnings": []}


def backup_text(switch: dict, backup_id: int) -> tuple[dict, str]:
    backup = backups.get_backup(switch["id"], backup_id)
    if backup is None:
        raise _not_found()
    try:
        return backup, backups.read_text(backup_id)
    except LookupError:
        raise _not_found() from None
    except ValueError as exc:
        raise InvalidInputError(str(exc)) from None


def download_name(switch: dict, backup: dict) -> str:
    stamp = backup["created_at"].replace(" ", "T").replace(":", "") + "Z"
    name = _FILENAME_UNSAFE.sub("_", f"{switch['name']}-{stamp}").strip("._") or "backup"
    return f"{name}.cfg"


def diff_lines(old: str, new: str, patterns=(), *, old_label: str = "a", new_label: str = "b") -> dict:
    """``{lines: [{type: context|add|del|hunk, text}], truncated}`` between the normalized texts."""
    old_lines = backups.normalize(old, patterns).splitlines()
    new_lines = backups.normalize(new, patterns).splitlines()
    lines = []
    truncated = False
    for line in difflib.unified_diff(old_lines, new_lines, old_label, new_label, lineterm=""):
        if line.startswith(("---", "+++")) and not lines:
            continue
        if len(lines) >= MAX_DIFF_LINES:
            truncated = True
            break
        if line.startswith("@@"):
            kind = "hunk"
        elif line.startswith("+"):
            kind = "add"
        elif line.startswith("-"):
            kind = "del"
        else:
            kind = "context"
        lines.append({"type": kind, "text": line})
    return {"lines": lines, "truncated": truncated}


def _read_device(switch: dict, credentials: dict, source: str) -> str:
    driver = _driver(switch)
    capabilities = _capabilities(switch)
    features.require(capabilities, "config_compare" if source == "startup" else "config_backup")
    with driver.session(switch, credentials) as session:
        text = driver.read_startup_config(session) if source == "startup" else driver.read_running_config(session)
    return text or ""


def diff_backup(switch: dict, credentials: dict, backup_id: int, against: str) -> dict:
    """Backup ``backup_id`` against another backup (older → newer) or the device (backup → device)."""
    backup, text = backup_text(switch, backup_id)
    patterns = _driver(switch).volatile_config_patterns
    if against in ("running", "startup"):
        device = _read_device(switch, credentials, against)
        return diff_lines(text, device, patterns, old_label=f"backup-{backup_id}", new_label=against)
    if not against.isdigit():
        raise InvalidInputError(t("Ungültiger Vergleich: {value}", value=against))
    other, other_text = backup_text(switch, int(against))
    first, second = (other, backup) if (other["created_at"], other["id"]) <= (backup["created_at"], backup["id"]) \
        else (backup, other)
    texts = {backup["id"]: text, other["id"]: other_text}
    return diff_lines(
        texts[first["id"]], texts[second["id"]], patterns,
        old_label=f"backup-{first['id']}", new_label=f"backup-{second['id']}",
    )


def compare_device(switch: dict, credentials: dict, principal: Principal) -> dict:
    """Running vs. startup on the device; updates the app's save state from the result.

    ``diff`` only for admins (``None`` otherwise).
    """
    driver = _driver(switch)
    features.require(_capabilities(switch), "config_compare")
    with driver.session(switch, credentials) as session:
        running = driver.read_running_config(session)
        startup = driver.read_startup_config(session) or ""
    patterns = driver.volatile_config_patterns
    differs = backups.content_hash(running, patterns) != backups.content_hash(startup, patterns)
    if not differs:
        config_state.mark_saved(switch["id"])
    elif config_state.state(switch["id"])["status"] != "dirty":
        config_state.mark_dirty(switch["id"], "extern")
    diff = None
    if differs and principal.can_edit:
        diff = diff_lines(startup, running, patterns, old_label="startup", new_label="running")["lines"]
    return {"differs": differs, "diff": diff}


@invalidates_reads
def finish_rollback(switch: dict, credentials: dict, *, revert: bool) -> dict:
    """Confirm (keep) or revert the change protected by the armed rollback timer."""
    switch_id = switch["id"]
    with write_lock(
        "switch", switch_id, t("Für diesen Switch wird bereits eine Änderung ausgeführt."),
        t("Ein anderer Serverprozess bearbeitet diesen Switch."), lambda message: ChangeConflict("busy", message),
    ):
        pending = config_state.pending(switch_id)
        if pending is None or pending["expired"]:
            raise ChangeConflict("rollback_none", t("Für diesen Switch läuft kein automatisches Rollback."))
        driver = _driver(switch)
        features.require(_capabilities(switch), "config_rollback")
        action = "rollback-revert" if revert else "rollback-confirm"
        with driver.session(switch, credentials) as session:
            plan = driver.plan_rollback_revert(session) if revert else driver.plan_rollback_confirm(session)
            result = audited_write(
                action, target=switch["name"], detail=f"mechanism={pending['mechanism']} commands={len(plan.lines)}",
                operation=lambda: driver.execute_plan(session, plan),
            )
        if result["ok"]:
            config_state.clear(switch_id)
            if revert:
                config_state.mark_unknown(switch_id)
    message = result["message"]
    if result["ok"]:
        message = t("Änderung wurde zurückgesetzt.") if revert else t("Änderung wurde bestätigt.")
    return {"ok": result["ok"], "message": message}
