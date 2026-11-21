"""Role resolution for local and external accounts."""

from collections.abc import Iterable, Sequence

from .sessions import Role
from .settings import GroupMapping
from .users import User


def resolve_role(
    user: User | None,
    provider: str,
    matched_group_ids: Iterable[str],
    mappings: Sequence[GroupMapping],
    default_role: str,
) -> Role | None:
    """Precedence: disabled → none; assigned role; admin, operator, viewer mapping; default role; none."""
    if user is not None and not user.enabled:
        return None
    if user is not None and user.assigned_role:
        return Role(user.assigned_role)
    matched = {group_id.casefold() for group_id in matched_group_ids}
    provider_mappings = [mapping for mapping in mappings if mapping.provider == provider]
    for role in (Role.ADMIN, Role.OPERATOR, Role.VIEWER):
        if any(mapping.role == role.value and mapping.group_id.casefold() in matched for mapping in provider_mappings):
            return role
    if default_role == Role.VIEWER.value:
        return Role.VIEWER
    return None


def matched_mappings(matched_group_ids: Iterable[str], mappings: Sequence[GroupMapping]) -> list[GroupMapping]:
    matched = {group_id.casefold() for group_id in matched_group_ids}
    return [mapping for mapping in mappings if mapping.group_id.casefold() in matched]
