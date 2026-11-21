"""Exceptions shared by the switch service layer and all drivers."""


class SwitchConnectionError(Exception):
    """The device could not be reached or returned unusable output (HTTP 502)."""


class InvalidInputError(Exception):
    """A value is not acceptable as a device parameter (HTTP 400)."""


class UnsupportedFeatureError(Exception):
    """The driver, model or port cannot provide a feature (HTTP 409 ``incompatible``).

    ``reason`` is a German message ID with optional format ``params``; it is
    translated when the response is built.
    """

    def __init__(self, feature: str, reason: str, **params):
        super().__init__(reason.format(**params) if params else reason)
        self.feature = feature
        self.reason = reason
        self.params = params


class ChangeConflict(Exception):
    """A change cannot run in the current state (HTTP 409 ``{"message", "code"}``).

    ``message`` is already translated; codes: ``preview_invalid``, ``preview_stale``,
    ``risk_confirmation_required``, ``rollback_pending``, ``incompatible``, ``busy``.
    """

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def append_warning(warnings: list[str], message: str) -> None:
    """Append a user-visible warning once."""
    if message not in warnings:
        warnings.append(message)
