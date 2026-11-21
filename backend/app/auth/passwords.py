"""scrypt password hashes for local accounts (stdlib only)."""

import base64
import hashlib
import hmac
import secrets
from functools import lru_cache

from ..i18n import t

_N = 2**15
_R = 8
_P = 1
_DKLEN = 32
_SALT_BYTES = 16
_MAXMEM = 64 * 1024 * 1024
MIN_LENGTH = 12
MAX_LENGTH = 1024


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _derive(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=_MAXMEM)


def hash_password(password: str) -> str:
    """Return ``scrypt$32768$8$1$<salt_b64>$<hash_b64>``."""
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = _derive(password, salt, _N, _R, _P, _DKLEN)
    return f"scrypt${_N}${_R}${_P}${_b64encode(salt)}${_b64encode(digest)}"


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    # Unknown users are verified against this hash so they cost the same time as real ones.
    return hash_password(secrets.token_urlsafe(16))


def _parse(encoded: str) -> tuple[int, int, int, bytes, bytes] | None:
    parts = encoded.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return None
    try:
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = base64.b64decode(parts[4], validate=True)
        digest = base64.b64decode(parts[5], validate=True)
    except ValueError:
        return None
    if n < 2 or n & (n - 1) or n > 2**20 or not 1 <= r <= 32 or not 1 <= p <= 16:
        return None
    if not salt or not 16 <= len(digest) <= 64:
        return None
    return n, r, p, salt, digest


def verify_password(password: str, encoded: str | None) -> bool:
    """Constant-time check; a missing or malformed hash still costs one scrypt run and fails."""
    parsed = _parse(encoded) if encoded else None
    if parsed is None:
        _, _, _, salt, digest = _parse(_dummy_hash())
        hmac.compare_digest(_derive(password, salt, _N, _R, _P, _DKLEN), digest)
        return False
    n, r, p, salt, digest = parsed
    try:
        candidate = _derive(password, salt, n, r, p, len(digest))
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(candidate, digest)


def validate_password(password: str) -> str:
    """Apply the password rules (12–1024 characters, no control characters); raise ``ValueError``."""
    if not isinstance(password, str) or not MIN_LENGTH <= len(password) <= MAX_LENGTH:
        raise ValueError(t("Das Passwort muss 12 bis 1024 Zeichen lang sein."))
    if any(ord(character) < 32 or ord(character) == 127 for character in password):
        raise ValueError(t("Das Passwort darf keine Steuerzeichen enthalten."))
    return password
