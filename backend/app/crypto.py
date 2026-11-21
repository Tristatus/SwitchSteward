"""
Symmetrische Verschlüsselung für die im Tool hinterlegten Switch-Zugangsdaten.

Der Schlüssel kommt AUSSCHLIESSLICH aus ``secrets.encryption_key`` der zentralen
JSON-Konfiguration und wird nie in der Datenbank oder im Code abgelegt. Ohne
gesetzten Key startet die App nicht - so wird verhindert, dass versehentlich mit
einem Default-Key oder unverschlüsselt gearbeitet wird.
"""

from cryptography.fernet import Fernet

from .config import settings

_KEY = settings.secret_key

if not _KEY:
    raise RuntimeError(
        "secrets.encryption_key ist in config.json nicht gesetzt. "
        "Erzeuge die Datei mit 'python -m app.bootstrap_config'."
    )

_fernet = Fernet(_KEY.encode() if isinstance(_KEY, str) else _KEY)


def encrypt(plaintext: str | None) -> bytes | None:
    if plaintext is None:
        return None
    return _fernet.encrypt(plaintext.encode())


def decrypt(ciphertext: bytes | None) -> str | None:
    if ciphertext is None:
        return None
    return _fernet.decrypt(ciphertext).decode()
