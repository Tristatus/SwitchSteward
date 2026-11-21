"""Emergency administration from the command line.

Usage (from ``backend/``): ``python -m app.manage create-admin --username NAME``,
``python -m app.manage decrypt-backup FILE`` (password-encrypted configuration backup → stdout).
"""

import argparse
import getpass
import sqlite3
import sys
from pathlib import Path

from . import audit, backup_crypto, config, database
from .auth import passwords, sessions, users
from .logging_setup import configure_logging

_ACTOR = "cli"


def _read_password() -> str:
    password = getpass.getpass("Passwort: ")
    passwords.validate_password(password)
    if getpass.getpass("Passwort wiederholen: ") != password:
        raise ValueError("Die Passwörter stimmen nicht überein.")
    return password


def create_admin(username: str) -> str:
    """Create a local administrator or restore an existing local account as enabled admin."""
    username = username.strip()
    if not users.USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Der Benutzername darf nur Buchstaben, Ziffern und . _ @ - enthalten (1–64 Zeichen).")
    # Creates the schema if needed, so the command also works before the first server start.
    database.init_db()
    password_hash = passwords.hash_password(_read_password())
    with database.get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = users.find_local_user(username, conn=conn)
        if existing is None:
            users.create_local_user(conn, username, password_hash, "admin")
            action, detail = "user-create", "provider=local role=admin source=cli"
        else:
            conn.execute(
                "UPDATE users SET password_hash = ?, assigned_role = 'admin', enabled = 1, updated_at = ? WHERE id = ?",
                (password_hash, sessions.timestamp(), existing.id),
            )
            revoked = sessions.revoke_user_sessions(existing.id, conn=conn)
            username = existing.username
            action = "user-update"
            detail = f"provider=local fields=assigned_role,enabled,password role=admin revoked_sessions={revoked} source=cli"
        audit.record(action, target=username, detail=detail, username=_ACTOR, auth_provider="local", connection=conn)
    return action


def decrypt_backup(path: str) -> str:
    """Plain text of a password-encrypted backup file (``*.cfg.smbk``)."""
    data = Path(path).read_bytes()
    if not backup_crypto.is_encrypted(data):
        raise ValueError("Die Datei ist kein verschlüsseltes Backup.")
    return backup_crypto.decrypt(data, getpass.getpass("Backup-Passwort: "))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.manage", description="SwitchSteward administration")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-admin", help="lokales Administratorkonto anlegen oder wiederherstellen")
    create.add_argument("--username", required=True)
    decrypt = commands.add_parser("decrypt-backup", help="verschlüsseltes Konfigurations-Backup entschlüsseln")
    decrypt.add_argument("file")
    args = parser.parse_args(argv)
    if args.command == "decrypt-backup":
        try:
            text = decrypt_backup(args.file)
        except (ValueError, OSError, EOFError, KeyboardInterrupt) as exc:
            print(f"Fehler: {exc}", file=sys.stderr)
            return 1
        sys.stdout.write(text)
        return 0
    try:
        # system.log and audit.log record the emergency access like any other change.
        configure_logging(config.settings)
        action = create_admin(args.username)
    except (ValueError, RuntimeError, OSError, sqlite3.Error, EOFError, KeyboardInterrupt) as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1
    message = "angelegt" if action == "user-create" else "aktualisiert"
    print(f"Lokales Administratorkonto {args.username.strip()} wurde {message}.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
