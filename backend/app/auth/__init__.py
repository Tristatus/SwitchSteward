"""Authentication: local accounts, Active Directory and Microsoft Entra ID with server-side sessions.

Public API used by the route modules: ``Role``, ``Principal``, ``CurrentPrincipal``, ``AdminPrincipal``,
``OperatorPrincipal``, ``get_current_principal``, ``require_admin``, ``require_operator``, ``require_csrf`` and
``COOKIE_NAME``.
"""

import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from .. import request_context
from ..i18n import t
from .sessions import COOKIE_NAME, Principal, Role, read_session

__all__ = [
    "COOKIE_NAME",
    "AdminPrincipal",
    "CurrentPrincipal",
    "OperatorPrincipal",
    "Principal",
    "Role",
    "get_current_principal",
    "require_admin",
    "require_operator",
    "require_csrf",
]


def get_current_principal(request: Request) -> Principal:
    principal = read_session(request.cookies.get(COOKIE_NAME))
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=t("Nicht angemeldet"))
    request_context.set_principal(principal.username, principal.provider)
    return principal


def require_admin(principal: Annotated[Principal, Depends(get_current_principal)]) -> Principal:
    if principal.role is not Role.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=t("Administratorrechte erforderlich"))
    return principal


def require_operator(principal: Annotated[Principal, Depends(get_current_principal)]) -> Principal:
    if not principal.can_operate:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=t("Operator- oder Administratorrechte erforderlich")
        )
    return principal


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]
AdminPrincipal = Annotated[Principal, Depends(require_admin)]
OperatorPrincipal = Annotated[Principal, Depends(require_operator)]


def require_csrf(request: Request) -> Principal:
    principal = get_current_principal(request)
    supplied = request.headers.get("X-CSRF-Token", "")
    if not secrets.compare_digest(supplied.encode("utf-8"), principal.csrf_token.encode("utf-8")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=t("Ungültiger CSRF-Token"))
    return principal
