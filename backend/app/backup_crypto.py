"""Password encryption of configuration backup files.

File format: ``b"SMBK1\\n"`` + one JSON line with the scrypt parameters + ``b"\\n"`` + Fernet token.
The Fernet key is ``urlsafe_b64encode(scrypt(password, salt, n, r, p, length=32))``; the format
can be decrypted offline with ``python -m app.manage decrypt-backup FILE``.
"""

import base64
import json
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .i18n import t

MAGIC = b"SMBK1\n"
_N, _R, _P = 32768, 8, 1
_SALT_BYTES = 16


def _fernet(password: str, salt: bytes, n: int, r: int, p: int) -> Fernet:
    key = Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key))


def is_encrypted(data: bytes) -> bool:
    return data.startswith(MAGIC)


def encrypt(text: str, password: str) -> bytes:
    salt = os.urandom(_SALT_BYTES)
    header = {"kdf": "scrypt", "salt": base64.b64encode(salt).decode("ascii"), "n": _N, "r": _R, "p": _P}
    token = _fernet(password, salt, _N, _R, _P).encrypt(text.encode("utf-8"))
    return MAGIC + json.dumps(header, separators=(",", ":")).encode("ascii") + b"\n" + token


def _header(data: bytes) -> tuple[bytes, int, int, int, bytes]:
    invalid = ValueError(t("Die Datei ist kein gültiges verschlüsseltes Backup."))
    if not is_encrypted(data):
        raise invalid
    header_line, separator, token = data[len(MAGIC):].partition(b"\n")
    try:
        header = json.loads(header_line)
        salt = base64.b64decode(header["salt"], validate=True)
        n, r, p = (int(header[name]) for name in ("n", "r", "p"))
    except (ValueError, KeyError, TypeError):
        raise invalid from None
    # Bounded so a manipulated header cannot demand unbounded memory or time.
    valid = (
        separator and header.get("kdf") == "scrypt" and salt
        and 2 <= n <= 2**20 and n & (n - 1) == 0 and 1 <= r <= 32 and 1 <= p <= 16
    )
    if not valid:
        raise invalid
    return salt, n, r, p, token.strip()


def decrypt(data: bytes, password: str) -> str:
    salt, n, r, p, token = _header(data)
    try:
        return _fernet(password, salt, n, r, p).decrypt(token).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError):
        raise ValueError(t("Backup kann mit dem hinterlegten Passwort nicht entschlüsselt werden.")) from None
