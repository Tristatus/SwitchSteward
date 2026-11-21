"""Erzeugt die zentrale JSON-Konfiguration aus config.example.json."""

import json
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet

BACKEND_DIR = Path(__file__).resolve().parent.parent


def _config_file() -> Path:
    path = Path(os.environ.get("SWITCHSTEWARD_CONFIG_FILE", "config.json")).expanduser()
    return (BACKEND_DIR / path).resolve() if not path.is_absolute() else path.resolve()


def ensure_config(config_file: Path | None = None) -> None:
    """Erzeugt nur fehlende Konfigurationen; bestehende Schlüssel bleiben erhalten."""
    config_file = config_file if config_file is not None else _config_file()
    if config_file.exists():
        return

    template_path = BACKEND_DIR / "config.example.json"
    data = json.loads(template_path.read_text(encoding="utf-8"))
    # Die Oberfläche gehört zum Release, auch wenn die Laufzeitkonfiguration
    # außerhalb des backend-Verzeichnisses angelegt wird.
    if config_file.parent != BACKEND_DIR:
        data["application"]["frontend_dir"] = str((BACKEND_DIR.parent / "frontend").resolve())

    if not data["secrets"]["encryption_key"]:
        database_path = Path(data["application"]["database_path"]).expanduser()
        if not database_path.is_absolute():
            database_path = config_file.parent / database_path
        if database_path.exists():
            raise RuntimeError(
                f"Konfiguration fehlt, aber eine Datenbank existiert bereits: {database_path}. "
                "Die zugehörige config.json bzw. den bisherigen Verschlüsselungsschlüssel "
                "aus einer Sicherung wiederherstellen. Es wird kein neuer Schlüssel erzeugt."
            )
        data["secrets"]["encryption_key"] = Fernet.generate_key().decode("ascii")
    if not data["secrets"]["session_key"]:
        data["secrets"]["session_key"] = secrets.token_urlsafe(32)

    config_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        # O_EXCL verhindert, dass ein paralleler Erststart Schlüssel überschreibt.
        descriptor = os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")

    print(f"JSON-Konfiguration wurde neu erzeugt: {config_file}")
    print("Die Erstinstallation wird beim Start im lokalen Webbrowser eingerichtet.")


def main() -> None:
    ensure_config()


if __name__ == "__main__":
    main()
