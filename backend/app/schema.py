"""Gemeinsames Datenbankschema für Erstinstallation und normale Starts."""

import sqlite3

_ROLES_CHECK = "('admin', 'operator', 'viewer')"

# One statement per entry: executescript() would commit the caller's transaction.
_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS switch_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        created_at TEXT DEFAULT (datetime('now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS switches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        ip TEXT NOT NULL,
        device_type TEXT NOT NULL DEFAULT 'cisco_ios',
        site TEXT,
        port INTEGER NOT NULL DEFAULT 22,
        notes TEXT,
        group_id INTEGER REFERENCES switch_groups(id) ON DELETE SET NULL,
        credential_mode TEXT NOT NULL DEFAULT 'global'
            CHECK (credential_mode IN ('global', 'device')),
        credential_revision INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        model_id TEXT,
        detected_model TEXT,
        detected_model_id TEXT,
        detected_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        username TEXT NOT NULL,
        password_enc BLOB NOT NULL,
        enable_secret_enc BLOB
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS switch_credentials (
        switch_id INTEGER PRIMARY KEY REFERENCES switches(id) ON DELETE CASCADE,
        username TEXT NOT NULL,
        password_enc BLOB NOT NULL,
        enable_secret_enc BLOB
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS wlan_controllers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        host TEXT NOT NULL,
        platform TEXT NOT NULL DEFAULT 'catalyst_9800',
        transport TEXT NOT NULL DEFAULT 'restconf',
        controller_revision INTEGER NOT NULL DEFAULT 0,
        credential_revision INTEGER NOT NULL DEFAULT 0,
        port INTEGER NOT NULL DEFAULT 443,
        credential_mode TEXT NOT NULL DEFAULT 'global'
            CHECK (credential_mode IN ('global', 'device')),
        site TEXT,
        notes TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS wlan_credentials (
        controller_id INTEGER PRIMARY KEY
            REFERENCES wlan_controllers(id) ON DELETE CASCADE,
        username TEXT NOT NULL,
        password_enc BLOB NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT DEFAULT (datetime('now')),
        username TEXT,
        switch_name TEXT,
        interface TEXT,
        action TEXT,
        detail TEXT,
        status TEXT,
        auth_provider TEXT,
        client_ip TEXT,
        request_id TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS wlan_config_state (
        controller_id INTEGER PRIMARY KEY
            REFERENCES wlan_controllers(id) ON DELETE CASCADE,
        connection_fingerprint TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'unknown',
        last_change_id TEXT,
        last_saved_at TEXT,
        updated_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_switches_group_id ON switches(group_id)",
    f"""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider TEXT NOT NULL CHECK (provider IN ('local', 'ad', 'entra')),
        subject TEXT NOT NULL,
        username TEXT NOT NULL,
        display_name TEXT,
        email TEXT,
        password_hash TEXT,
        assigned_role TEXT CHECK (assigned_role IN {_ROLES_CHECK}),
        enabled INTEGER NOT NULL DEFAULT 1,
        last_role TEXT,
        last_login_at TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE (provider, subject)
    )
    """,
    f"""
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK (role IN {_ROLES_CHECK}),
        csrf_token TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
    f"""
    CREATE TABLE IF NOT EXISTS group_role_mappings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider TEXT NOT NULL CHECK (provider IN ('ad', 'entra')),
        group_id TEXT NOT NULL,
        label TEXT,
        role TEXT NOT NULL CHECK (role IN {_ROLES_CHECK}),
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE (provider, group_id COLLATE NOCASE)
    )
    """,
    "CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)",
    """
    CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        switch_id INTEGER REFERENCES switches(id) ON DELETE CASCADE,
        run_at TEXT NOT NULL,
        params TEXT NOT NULL DEFAULT '{}',
        status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'done', 'failed', 'cancelled')),
        result TEXT,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_jobs_status_run_at ON jobs(status, run_at)",
    """
    CREATE TABLE IF NOT EXISTS switch_config_state (
        switch_id INTEGER PRIMARY KEY REFERENCES switches(id) ON DELETE CASCADE,
        status TEXT NOT NULL CHECK (status IN ('untracked', 'dirty', 'saved', 'unknown')),
        last_change_at TEXT,
        last_change_by TEXT,
        last_saved_at TEXT,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS switch_rollbacks (
        switch_id INTEGER PRIMARY KEY REFERENCES switches(id) ON DELETE CASCADE,
        mechanism TEXT NOT NULL,
        armed_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        armed_by TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS config_backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL,
        trigger TEXT NOT NULL
            CHECK (trigger IN ('before-save', 'after-save', 'before-restore', 'before-change', 'after-change')),
        source TEXT NOT NULL CHECK (source IN ('startup', 'running')),
        path TEXT NOT NULL,
        encrypted INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        size INTEGER NOT NULL,
        created_by TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_config_backups_switch ON config_backups(switch_id, created_at)",
    """
    CREATE TABLE IF NOT EXISTS transfer_tokens (
        token_id TEXT PRIMARY KEY,
        secret_hash TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('backup', 'firmware')),
        ref_id INTEGER NOT NULL,
        switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
        filename TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        uses INTEGER NOT NULL DEFAULT 0,
        max_uses INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS port_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        description TEXT,
        settings TEXT NOT NULL,
        updated_by TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS firmware_images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL UNIQUE,
        size INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        md5 TEXT NOT NULL,
        platforms TEXT NOT NULL,
        uploaded_by TEXT NOT NULL,
        uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,
)

SCHEMA_VERSION = 1


def initialize_schema(conn: sqlite3.Connection) -> None:
    """Create all tables and indexes; safe to run on every start."""
    # executescript() commits an existing transaction and runs DDL piecemeal.
    # Keep schema creation in the caller's transaction and serialize first-time starts.
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    for statement in _SCHEMA_STATEMENTS:
        conn.execute(statement)
    # PRAGMA does not accept bound parameters; SCHEMA_VERSION is a trusted int constant.
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
