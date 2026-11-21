"""
SQLite-Datenzugriff für Switch-Inventar, Zugangsdaten und Audit-Log.

Bewusst ohne ORM gehalten (nur sqlite3), damit das Projekt schlank
und leicht nachvollziehbar bleibt. Bei Bedarf später leicht auf
SQLAlchemy migrierbar.
"""

import base64
import hashlib
import hmac
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from . import config
from .schema import initialize_schema

# Each revision-token type signs with its own domain-separated key.
_TOKEN_KEY_LABELS = {
    "scr1": b"switchsteward/switch-credential-revision/v1",
    "wcr1": b"switchsteward/wlan-credential-revision/v1",
    "wlcr1": b"switchsteward/wlan-controller-revision/v1",
}


def _derive_key(label: bytes) -> bytes:
    source = config.settings.session_secret_key or config.settings.secret_key
    if not source:
        raise RuntimeError("Für Revisions-Tokens ist ein Anwendungsschlüssel erforderlich.")
    return hmac.new(source.encode("utf-8"), label, hashlib.sha256).digest()


def _sign_token(prefix: str, values) -> str:
    message = json.dumps(list(values), separators=(",", ":"), ensure_ascii=True).encode("ascii")
    signature = hmac.new(_derive_key(_TOKEN_KEY_LABELS[prefix]), message, hashlib.sha256).digest()
    return f"{prefix}." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


_SWITCH_READ_SQL = """
    SELECT s.*, sc.username AS _device_username,
        sc.password_enc AS _device_password_enc,
        sc.enable_secret_enc AS _device_enable_secret_enc,
        gc.username AS _global_username, gc.password_enc AS _global_password_enc,
        gc.enable_secret_enc AS _global_enable_secret_enc
    FROM switches AS s
    LEFT JOIN switch_credentials AS sc ON sc.switch_id = s.id
    LEFT JOIN credentials AS gc ON gc.id = 1
"""
_WLAN_READ_SQL = """
    SELECT c.*, wc.username AS _device_username,
        wc.password_enc AS _device_password_enc,
        gc.username AS _global_username, gc.password_enc AS _global_password_enc
    FROM wlan_controllers AS c
    LEFT JOIN wlan_credentials AS wc ON wc.controller_id = c.id
    LEFT JOIN credentials AS gc ON gc.id = 1
"""


def database_path() -> Path:
    return config.settings.database_path


@contextmanager
def get_conn():
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=config.settings.sqlite_timeout_seconds)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        initialize_schema(conn)


# --- Switches -------------------------------------------------------------

_CREDENTIAL_FIELDS = frozenset({
    "credential_mode",
    *(f"_{source}_{field}" for source in ("device", "global")
      for field in ("username", "password_enc", "enable_secret_enc")),
})


def _without_credential_fields(values):
    """Copy of a joined row without secret SQL fields and the raw credential mode."""
    return {key: value for key, value in values.items() if key not in _CREDENTIAL_FIELDS}


def _credential_state(values):
    """Waehlt genau einen Zugangssatz; die Eingabe bleibt unveraendert."""

    mode = values["credential_mode"]
    sets = {}
    for source in ("device", "global"):
        username = values.get(f"_{source}_username")
        password_enc = values.get(f"_{source}_password_enc")
        credentials = {"username": username, "password_enc": password_enc}
        enable_key = f"_{source}_enable_secret_enc"
        if enable_key in values:
            credentials["enable_secret_enc"] = values[enable_key]
        sets[source] = credentials if username and password_enc else None
    override = sets["device"]
    selected = sets.get(mode)
    return {
        "mode": mode,
        "configured": selected is not None,
        "override_configured": override is not None,
        "global_configured": sets["global"] is not None,
        "credentials": selected,
        **({"username": override["username"]} if override else {}),
        "enable_secret_configured": bool(override and override.get("enable_secret_enc")),
    }


def _public_credential_status(state):
    return {
        "credentials_source": state["mode"],
        "credentials_configured": state["configured"],
        "credentials_override_configured": state["override_configured"],
    }


def _switch_revision_token(row):
    return _sign_token("scr1", (
        row["id"], row["ip"], row["port"], row["device_type"], row["credential_mode"], row["credential_revision"],
    ))


def _switch_dict(row):
    if not row:
        return None
    values = dict(row)
    state = _credential_state(values)
    values = _without_credential_fields(values)
    values.pop("credential_revision", None)
    return {**values, **_public_credential_status(state)}


def list_switches():
    with get_conn() as conn:
        return [_switch_dict(row) for row in conn.execute(_SWITCH_READ_SQL + " ORDER BY s.name")]


def get_switch(switch_id: int):
    with get_conn() as conn:
        row = conn.execute(_SWITCH_READ_SQL + " WHERE s.id = ?", (switch_id,)).fetchone()
        return _switch_dict(row)


def list_switches_in_group(group_id: int) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(_SWITCH_READ_SQL + " WHERE s.group_id = ? ORDER BY s.name", (group_id,))
        return [_switch_dict(row) for row in rows]


def switch_revision_token(switch_id: int) -> str | None:
    """Signed token of the switch's address, type and credential revision (None if the switch is gone)."""
    with get_conn() as conn:
        row = conn.execute(_SWITCH_READ_SQL + " WHERE s.id = ?", (switch_id,)).fetchone()
    return _switch_revision_token(row) if row else None


def create_switch(*, name, ip, device_type, model_id=None, site=None, port=22, notes=None, group_id=None):
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO switches (name, ip, device_type, model_id, site, port, notes, group_id) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (name, ip, device_type, model_id, site, port, notes, group_id),
        )
        return cur.lastrowid


def update_switch(switch_id, *, name, ip, device_type, model_id=None, site=None, port=22, notes=None, group_id=None):
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute("SELECT * FROM switches WHERE id = ?", (switch_id,)).fetchone()
        if not existing:
            return None
        connection_changed = any(
            existing[field] != value
            for field, value in (("ip", ip), ("port", port), ("device_type", device_type))
        )
        conn.execute(
            "UPDATE switches SET name=?, ip=?, device_type=?, model_id=?, site=?, port=?, notes=?, group_id=?, "
            "credential_revision=credential_revision+? WHERE id=?",
            (name, ip, device_type, model_id, site, port, notes, group_id, int(connection_changed), switch_id),
        )
        if existing["device_type"] != device_type:
            # A detected model belongs to the previous driver's catalog.
            conn.execute(
                "UPDATE switches SET detected_model=NULL, detected_model_id=NULL, detected_at=NULL WHERE id=?",
                (switch_id,),
            )
        credentials_cleared = False
        if connection_changed:
            credentials_cleared = bool(conn.execute(
                "DELETE FROM switch_credentials WHERE switch_id = ?", (switch_id,)
            ).rowcount)
        updated = conn.execute(_SWITCH_READ_SQL + " WHERE s.id = ?", (switch_id,)).fetchone()
        return {
            "status": "ok", "switch": _switch_dict(updated),
            "connection_changed": connection_changed, "credentials_cleared": credentials_cleared,
        }


def set_detected_model(switch_id: int, model_string: str | None, model_id: str | None) -> None:
    """Store the model reported by the device after a successful device-info read."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE switches SET detected_model=?, detected_model_id=?, detected_at=datetime('now') WHERE id=?",
            (model_string, model_id, switch_id),
        )


def delete_switch(switch_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM switches WHERE id=?", (switch_id,))


# --- Switch-Gruppen --------------------------------------------------------


def list_switch_groups():
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT g.*, COUNT(s.id) AS switch_count
            FROM switch_groups AS g
            LEFT JOIN switches AS s ON s.group_id = g.id
            GROUP BY g.id
            ORDER BY g.name COLLATE NOCASE
            """
        )
        return [dict(row) for row in rows]


def get_switch_group(group_id: int):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM switch_groups WHERE id = ?", (group_id,)).fetchone()
        return dict(row) if row else None


def create_switch_group(name: str):
    with get_conn() as conn:
        cur = conn.execute("INSERT INTO switch_groups (name) VALUES (?)", (name,))
        return cur.lastrowid


def update_switch_group(group_id: int, name: str):
    with get_conn() as conn:
        conn.execute("UPDATE switch_groups SET name = ? WHERE id = ?", (name, group_id))


def delete_switch_group(group_id: int):
    with get_conn() as conn:
        # ON DELETE SET NULL behaelt die enthaltenen Switches als ungruppiert.
        conn.execute("DELETE FROM switch_groups WHERE id = ?", (group_id,))


# --- Credentials (globaler Satz und vollstaendige Geraete-Overrides) -------


def set_credentials(username, password_enc, enable_secret_enc):
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """INSERT INTO credentials (id, username, password_enc, enable_secret_enc)
               VALUES (1, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET username=excluded.username,
                   password_enc=excluded.password_enc,
                   enable_secret_enc=excluded.enable_secret_enc""",
            (username, password_enc, enable_secret_enc),
        )
        # Dialoge mit globalem Zugang muessen auch bei einem globalen Wechsel
        # ihren vorher gelesenen Credentialstand erneut laden.
        conn.execute(
            "UPDATE switches SET credential_revision = credential_revision + 1 "
            "WHERE credential_mode = 'global'"
        )
        conn.execute(
            "UPDATE wlan_controllers SET credential_revision = credential_revision + 1 "
            "WHERE credential_mode = 'global'"
        )


def get_credentials():
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id = 1").fetchone()
        return dict(row) if row else None


def get_switch_credentials(switch_id: int):
    """Interner Zugriff auf den gespeicherten Override, ohne globalen Fallback."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM switch_credentials WHERE switch_id = ?", (switch_id,)
        ).fetchone()
        return dict(row) if row else None


def get_switch_credentials_metadata(switch_id: int):
    with get_conn() as conn:
        row = conn.execute(_SWITCH_READ_SQL + " WHERE s.id = ?", (switch_id,)).fetchone()
        if not row:
            return None
        revision_token = _switch_revision_token(row)
        state = _credential_state(dict(row))
        state.pop("credentials")
        return {**state, **_public_credential_status(state), "revision_token": revision_token}


def get_switch_connection(switch_id: int):
    """Liest Ziel und den ausgewaehlten Zugang in einem SQLite-Snapshot."""
    with get_conn() as conn:
        row = conn.execute(_SWITCH_READ_SQL + " WHERE s.id = ?", (switch_id,)).fetchone()
        if not row:
            return None
        state = _credential_state(dict(row))
        credentials = state["credentials"]
        if credentials:
            credentials = {"switch_id": switch_id, **credentials}
        return {"switch": _switch_dict(row), "credentials": credentials}


def set_switch_credentials_for_connection(
    switch_id: int,
    username=None,
    password_enc=None,
    enable_secret_enc=None,
    *,
    expected_ip: str,
    expected_port: int,
    expected_device_type: str,
    expected_revision_token: str,
    mode: str = "device",
    preserve_password: bool = False,
    preserve_enable_secret: bool = False,
):
    """CAS fuer einen vollstaendigen Zugangssatz und das gebundene SSH-Ziel."""
    if mode not in {"global", "device"}:
        raise ValueError("Unbekannter Zugangsdatenmodus")
    if mode == "device" and (not username or (not preserve_password and not password_enc)):
        raise ValueError("Benutzername und Passwort sind fuer eigene Zugangsdaten erforderlich")
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(_SWITCH_READ_SQL + " WHERE s.id = ?", (switch_id,)).fetchone()
        if not row:
            return {"status": "switch_not_found"}
        if not isinstance(expected_revision_token, str) or not hmac.compare_digest(
            _switch_revision_token(row), expected_revision_token
        ):
            return {"status": "revision_changed", "switch_name": row["name"]}
        if (row["ip"], row["port"], row["device_type"]) != (
            expected_ip, expected_port, expected_device_type
        ):
            return {"status": "connection_changed", "switch_name": row["name"]}
        if mode == "global":
            conn.execute("DELETE FROM switch_credentials WHERE switch_id = ?", (switch_id,))
        else:
            current = conn.execute(
                "SELECT * FROM switch_credentials WHERE switch_id = ?", (switch_id,)
            ).fetchone()
            if preserve_password:
                if not current or not current["password_enc"]:
                    return {"status": "credentials_missing", "switch_name": row["name"]}
                password_enc = current["password_enc"]
            if preserve_enable_secret:
                enable_secret_enc = current["enable_secret_enc"] if current else None
            conn.execute(
                """INSERT INTO switch_credentials
                    (switch_id, username, password_enc, enable_secret_enc) VALUES (?, ?, ?, ?)
                    ON CONFLICT(switch_id) DO UPDATE SET username=excluded.username,
                        password_enc=excluded.password_enc,
                        enable_secret_enc=excluded.enable_secret_enc""",
                (switch_id, username, password_enc, enable_secret_enc),
            )
        conn.execute(
            "UPDATE switches SET credential_mode = ?, credential_revision = credential_revision + 1 "
            "WHERE id = ?", (mode, switch_id),
        )
        updated = conn.execute(_SWITCH_READ_SQL + " WHERE s.id = ?", (switch_id,)).fetchone()
        return {
            "status": "ok", "switch_name": row["name"],
            "revision_token": _switch_revision_token(updated),
        }


# --- WLAN-Controller -------------------------------------------------------


def _wlan_revision_token(controller_id: int, revision: int) -> str:
    """Erzeugt einen opaken, controllerspezifischen Zustands-Token."""
    return _sign_token("wcr1", (controller_id, revision))


def _wlan_controller_revision_token(
    controller_id: int,
    controller_revision: int,
    credential_revision: int,
) -> str:
    """Bindet einen Controllerdialog opak an Controller- und Credentialstand."""
    return _sign_token("wlcr1", (controller_id, controller_revision, credential_revision))


def _wlan_controller_dict(row):
    if not row:
        return None
    values = dict(row)
    state = _credential_state(values)
    controller = _without_credential_fields(values)
    controller_revision = controller.pop("controller_revision", 0)
    credential_revision = controller.pop("credential_revision", 0)
    controller["revision_token"] = _wlan_controller_revision_token(
        controller["id"],
        controller_revision,
        credential_revision,
    )
    # Interne Revisionszaehler werden nie ueber die Controller-API exponiert.
    controller.update(_public_credential_status(state))
    return controller


def list_wlan_controllers():
    with get_conn() as conn:
        rows = conn.execute(
            _WLAN_READ_SQL + " ORDER BY c.name COLLATE NOCASE"
        )
        return [_wlan_controller_dict(row) for row in rows]


def get_wlan_controller(controller_id: int):
    with get_conn() as conn:
        row = conn.execute(
            _WLAN_READ_SQL + " WHERE c.id = ?",
            (controller_id,),
        ).fetchone()
        return _wlan_controller_dict(row)


def create_wlan_controller(
    name,
    host,
    platform="catalyst_9800",
    port=443,
    site=None,
    notes=None,
    transport="restconf",
):
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO wlan_controllers
                (name, host, platform, transport, port, site, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (name, host, platform, transport, port, site, notes),
        )
        return cur.lastrowid


def update_wlan_controller(
    controller_id,
    name,
    host,
    platform,
    port,
    site,
    notes,
    transport="restconf",
    *,
    expected_revision_token: str,
):
    with get_conn() as conn:
        # Transportziel und Credentials muessen als eine atomare Einheit
        # behandelt werden. Der sofortige Write-Lock verhindert, dass zwei
        # parallele Admin-Updates beide gegen einen veralteten Stand pruefen.
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            """
            SELECT name, host, platform, transport, port,
                   controller_revision, credential_revision
            FROM wlan_controllers
            WHERE id = ?
            """,
            (controller_id,),
        ).fetchone()
        if not existing:
            return None
        current_revision_token = _wlan_controller_revision_token(
            controller_id,
            existing["controller_revision"],
            existing["credential_revision"],
        )
        if not isinstance(expected_revision_token, str) or not hmac.compare_digest(
            current_revision_token,
            expected_revision_token,
        ):
            return {
                "status": "revision_changed",
                "controller_name": existing["name"],
            }
        connection_changed = (
            existing["host"] != host
            or existing["platform"] != platform
            or existing["transport"] != transport
            or existing["port"] != port
        )
        conn.execute(
            """
            UPDATE wlan_controllers
            SET name = ?, host = ?, platform = ?, transport = ?,
                port = ?, site = ?, notes = ?,
                controller_revision = controller_revision + 1,
                credential_revision = credential_revision + ?
            WHERE id = ?
            """,
            (
                name,
                host,
                platform,
                transport,
                port,
                site,
                notes,
                int(connection_changed),
                controller_id,
            ),
        )
        if connection_changed:
            # Alte Secrets duerfen niemals an ein neues Transportziel
            # weitergereicht werden. Scheitert Update oder Delete, rollt
            # get_conn die gesamte Transaktion zurueck.
            conn.execute(
                "DELETE FROM wlan_credentials WHERE controller_id = ?",
                (controller_id,),
            )
        updated = conn.execute(
            _WLAN_READ_SQL + " WHERE c.id = ?",
            (controller_id,),
        ).fetchone()
        return {
            "status": "ok",
            "controller": _wlan_controller_dict(updated),
            "connection_changed": connection_changed,
        }


def delete_wlan_controller(controller_id: int):
    with get_conn() as conn:
        conn.execute("DELETE FROM wlan_controllers WHERE id = ?", (controller_id,))


def set_wlan_credentials(controller_id: int, username, password_enc):
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            INSERT INTO wlan_credentials (controller_id, username, password_enc)
            VALUES (?, ?, ?)
            ON CONFLICT(controller_id) DO UPDATE SET
                username = excluded.username,
                password_enc = excluded.password_enc
            """,
            (controller_id, username, password_enc),
        )
        conn.execute(
            """
            UPDATE wlan_controllers
            SET credential_revision = credential_revision + 1,
                credential_mode = 'device'
            WHERE id = ?
            """,
            (controller_id,),
        )


def set_wlan_credentials_for_connection(
    controller_id: int,
    username: str,
    password_enc,
    *,
    expected_host: str,
    expected_port: int,
    expected_platform: str,
    expected_transport: str,
    expected_revision_token: str,
    expected_controller_revision_token: str,
    preserve_password: bool = False,
    mode: str = "device",
):
    """Speichert Credentials nur fuer das zuvor gelesene Transportziel.

    Der Write-Lock serialisiert diese Pruefung mit Controller-Updates. Aendert
    sich das Transportziel vor dem Upsert, wird das Secret nicht gespeichert.
    """

    if mode not in {"global", "device"}:
        raise ValueError("Unbekannter Zugangsdatenmodus")
    if mode == "device" and not username:
        raise ValueError("Benutzername ist fuer eigene WLAN-Zugangsdaten erforderlich")
    if mode == "device" and not preserve_password and not password_enc:
        raise ValueError("password_enc ist für neue WLAN-Zugangsdaten erforderlich")
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        controller = conn.execute(
            """
            SELECT name, host, port, platform, transport,
                   controller_revision, credential_revision
            FROM wlan_controllers
            WHERE id = ?
            """,
            (controller_id,),
        ).fetchone()
        if not controller:
            return {"status": "controller_not_found"}
        current_revision_token = _wlan_revision_token(
            controller_id,
            controller["credential_revision"],
        )
        current_controller_revision_token = _wlan_controller_revision_token(
            controller_id,
            controller["controller_revision"],
            controller["credential_revision"],
        )
        credential_revision_matches = isinstance(
            expected_revision_token,
            str,
        ) and hmac.compare_digest(current_revision_token, expected_revision_token)
        controller_revision_matches = isinstance(
            expected_controller_revision_token,
            str,
        ) and hmac.compare_digest(
            current_controller_revision_token,
            expected_controller_revision_token,
        )
        if not credential_revision_matches or not controller_revision_matches:
            return {
                "status": "revision_changed",
                "controller_name": controller["name"],
            }
        if (
            controller["host"] != expected_host
            or controller["port"] != expected_port
            or controller["platform"] != expected_platform
            or controller["transport"] != expected_transport
        ):
            return {
                "status": "connection_changed",
                "controller_name": controller["name"],
            }
        if mode == "global":
            conn.execute("DELETE FROM wlan_credentials WHERE controller_id = ?", (controller_id,))
        elif preserve_password:
            cur = conn.execute(
                "UPDATE wlan_credentials SET username = ? WHERE controller_id = ?",
                (username, controller_id),
            )
            if cur.rowcount == 0:
                return {
                    "status": "credentials_missing",
                    "controller_name": controller["name"],
                }
        else:
            conn.execute(
                """
                INSERT INTO wlan_credentials (controller_id, username, password_enc)
                VALUES (?, ?, ?)
                ON CONFLICT(controller_id) DO UPDATE SET
                    username = excluded.username,
                    password_enc = excluded.password_enc
                """,
                (controller_id, username, password_enc),
            )
        new_revision = controller["credential_revision"] + 1
        conn.execute(
            """
            UPDATE wlan_controllers
            SET credential_revision = ?, credential_mode = ?
            WHERE id = ?
            """,
            (new_revision, mode, controller_id),
        )
        return {
            "status": "ok",
            "controller_name": controller["name"],
            "revision_token": _wlan_revision_token(controller_id, new_revision),
            "controller_revision_token": _wlan_controller_revision_token(
                controller_id,
                controller["controller_revision"],
                new_revision,
            ),
        }


def get_wlan_credentials(controller_id: int):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM wlan_credentials WHERE controller_id = ?",
            (controller_id,),
        ).fetchone()
        return dict(row) if row else None


def get_wlan_credentials_metadata(controller_id: int):
    """Liest den exponierbaren Credential-Status samt opakem Revisionstoken."""

    with get_conn() as conn:
        row = conn.execute(
            _WLAN_READ_SQL + " WHERE c.id = ?",
            (controller_id,),
        ).fetchone()
        if not row:
            return None
        state = _credential_state(dict(row))
        state.pop("credentials")
        state.pop("enable_secret_configured")
        return {
            **state,
            **_public_credential_status(state),
            "revision_token": _wlan_revision_token(
                row["id"],
                row["credential_revision"],
            ),
            "controller_revision_token": _wlan_controller_revision_token(
                row["id"],
                row["controller_revision"],
                row["credential_revision"],
            ),
        }


def get_wlan_controller_connection(controller_id: int):
    """Liest Transportziel und Credentials aus demselben SQLite-Snapshot."""

    with get_conn() as conn:
        row = conn.execute(
            _WLAN_READ_SQL + " WHERE c.id = ?",
            (controller_id,),
        ).fetchone()
        if not row:
            return None
        state = _credential_state(dict(row))
        controller = _wlan_controller_dict(row)
        credentials = state["credentials"]
        if credentials:
            credentials = {"controller_id": controller_id, **credentials}
        return {
            "controller": controller,
            "credentials": credentials,
        }


# --- Audit log --------------------------------------------------------------


def insert_audit(conn, username, target, interface, action, detail, status, *,
                 auth_provider=None, client_ip=None, request_id=None):
    # The column keeps its historical name switch_name; it stores any audit target.
    conn.execute(
        "INSERT INTO audit_log (username, switch_name, interface, action, detail, status, "
        "auth_provider, client_ip, request_id) VALUES (?,?,?,?,?,?,?,?,?)",
        (username, target, interface, action, detail, status, auth_provider, client_ip, request_id),
    )


def add_audit(username, target, interface, action, detail, status, *,
              auth_provider=None, client_ip=None, request_id=None):
    with get_conn() as conn:
        insert_audit(
            conn, username, target, interface, action, detail, status,
            auth_provider=auth_provider, client_ip=client_ip, request_id=request_id,
        )


def list_audit(limit=None):
    limit = config.settings.audit_log_limit if limit is None else max(1, min(int(limit), 1000))
    with get_conn() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]
