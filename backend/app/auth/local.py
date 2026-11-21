"""Local account sign-in."""

from . import passwords, users
from .users import User


class LocalAuthError(Exception):
    """Sign-in failed; ``reason`` is ``invalid_credentials`` or ``disabled`` (audit only, never shown)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def authenticate_local(username: str, password: str) -> User:
    user = users.find_local_user(username)
    # Unknown accounts still run one scrypt verification so response times do not reveal them.
    valid = passwords.verify_password(password, user.password_hash if user else None)
    if user is None or not valid:
        raise LocalAuthError("invalid_credentials")
    if not user.enabled:
        # Checked after the password: a disabled account looks exactly like a wrong password.
        raise LocalAuthError("disabled")
    return user
