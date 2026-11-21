"""Active Directory bind authentication with secure LDAP defaults."""

import logging
import ssl
import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from ldap3 import BASE, FIRST, NONE, SUBTREE, Connection, Server, ServerPool, Tls
from ldap3.core.exceptions import LDAPBindError
from ldap3.core.results import RESULT_INVALID_CREDENTIALS, RESULT_SUCCESS
from ldap3.utils.conv import escape_filter_chars

from ..i18n import t
from .settings import AdSettings, GroupMapping, ad_ca_cert_path, check_ad_files, parse_server_url

logger = logging.getLogger("switchsteward.ldap")

_USER_ATTRIBUTES = ["userPrincipalName", "objectGUID", "displayName", "mail"]


class LdapConfigError(Exception):
    """The AD connection is missing or configured insecurely (HTTP 503)."""


class LdapAuthError(Exception):
    """The credentials are invalid (HTTP 401)."""


class DirectoryUnavailableError(Exception):
    """No domain controller answered or a directory lookup failed (HTTP 503)."""


@dataclass(frozen=True)
class AdIdentity:
    subject: str
    username: str
    display_name: str | None
    email: str | None
    matched_group_ids: frozenset[str]


@dataclass(frozen=True)
class _ResolvedUser:
    dn: str
    upn: str
    guid: str
    display_name: str | None
    email: str | None


def _validate(ad: AdSettings) -> None:
    if not ad.enabled:
        raise LdapConfigError(t("Active Directory ist deaktiviert."))
    try:
        # The model validated the URLs on save; the CA file may have disappeared since.
        check_ad_files(ad)
    except ValueError as exc:
        raise LdapConfigError(str(exc)) from None


def _build_tls(ad: AdSettings) -> Tls:
    validation = ssl.CERT_REQUIRED if ad.tls_validate else ssl.CERT_NONE
    ca_file = ad_ca_cert_path(ad)
    return Tls(validate=validation, ca_certs_file=str(ca_file) if ca_file else None, version=ssl.PROTOCOL_TLS_CLIENT)


def _build_server_pool(ad: AdSettings):
    tls = _build_tls(ad)
    servers = []
    for value in ad.servers:
        try:
            host, port, use_ssl = parse_server_url(value)
        except ValueError as exc:
            raise LdapConfigError(str(exc)) from None
        servers.append(
            Server(host, port=port, get_info=NONE, use_ssl=use_ssl, tls=tls, connect_timeout=ad.connect_timeout_seconds)
        )
    if not servers:
        raise LdapConfigError(t("Mindestens ein AD-Server muss konfiguriert sein."))
    # ldap3 interprets True as unlimited retries, even when every DC is offline.
    return servers[0] if len(servers) == 1 else ServerPool(servers, FIRST, active=1, exhaust=True)


def _search_entries(conn: Connection, **kwargs) -> list:
    """Return search entries while distinguishing an empty result from an LDAP error."""
    conn.search(**kwargs)
    result = getattr(conn, "result", None)
    if not isinstance(result, dict) or result.get("result") != RESULT_SUCCESS:
        raise DirectoryUnavailableError(t("AD-Verzeichnissuche fehlgeschlagen."))
    return list(conn.entries)


def _attribute_text(entry, name: str) -> str | None:
    value = getattr(getattr(entry, name, None), "value", None)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _object_guid(entry) -> str | None:
    raw_values = getattr(getattr(entry, "objectGUID", None), "raw_values", None) or []
    raw = raw_values[0] if raw_values else None
    if not isinstance(raw, bytes) or len(raw) != 16:
        return None
    return str(uuid.UUID(bytes_le=raw))


def _search_user(conn: Connection, ad: AdSettings, attribute: str, value: str) -> list:
    search_filter = "(&(objectCategory=person)(objectClass=user)({}={}))".format(
        attribute, escape_filter_chars(value)
    )
    return _search_entries(
        conn, search_base=ad.base_dn, search_filter=search_filter, search_scope=SUBTREE,
        attributes=_USER_ATTRIBUTES, size_limit=2,
    )


def _resolve_user(conn: Connection, ad: AdSettings, upn: str, sam_account_name: str | None = None) -> _ResolvedUser:
    """Resolve a login UPN to exactly one user in the configured directory tree."""
    entries = _search_user(conn, ad, "userPrincipalName", upn)
    if not entries and sam_account_name:
        # AD also accepts sAMAccountName@DNS-domain as an implicit UPN for
        # legacy accounts without userPrincipalName. The caller only enables
        # this fallback for the configured domain, and the exact-DN rebind
        # still proves that the supplied password belongs to this object.
        entries = _search_user(conn, ad, "sAMAccountName", sam_account_name)
    if not entries:
        # A successful bind from a trusted domain must not inherit the role of a
        # same-named account in the configured domain.
        raise LdapAuthError("Anmeldung fehlgeschlagen.")
    if len(entries) != 1:
        raise LdapConfigError(t("AD-Benutzeridentität ist nicht eindeutig."))

    entry = entries[0]
    user_dn = getattr(entry, "entry_dn", None)
    canonical_upn = _attribute_text(entry, "userPrincipalName") or upn
    guid = _object_guid(entry)
    if not isinstance(user_dn, str) or not user_dn.strip() or not canonical_upn.strip() or guid is None:
        raise LdapConfigError(t("AD-Benutzeridentität konnte nicht aufgelöst werden."))
    return _ResolvedUser(
        dn=user_dn, upn=canonical_upn, guid=guid,
        display_name=_attribute_text(entry, "displayName"), email=_attribute_text(entry, "mail"),
    )


def _is_member_of_group(conn: Connection, user_dn: str, group_dn: str) -> bool:
    # LDAP_MATCHING_RULE_IN_CHAIN resolves nested memberships on the DC.
    search_filter = "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={}))".format(
        escape_filter_chars(group_dn)
    )
    entries = _search_entries(
        conn, search_base=user_dn, search_filter=search_filter, search_scope=BASE, attributes=[], size_limit=1,
    )
    return bool(entries)


def _matched_groups(conn: Connection, user_dn: str, mappings: Sequence[GroupMapping]) -> frozenset[str]:
    # Higher roles first keeps the lookup order deterministic; every mapped DN is checked.
    ordered = sorted(
        (mapping for mapping in mappings if mapping.provider == "ad"),
        key=lambda m: {"admin": 0, "operator": 1, "viewer": 2}[m.role],
    )
    return frozenset(
        mapping.group_id for mapping in ordered if _is_member_of_group(conn, user_dn, mapping.group_id)
    )


def _is_configured_domain_upn(ad: AdSettings, upn: str) -> bool:
    local_part, separator, domain = upn.rpartition("@")
    return bool(local_part and separator and domain.casefold() == ad.domain.casefold())


def authenticate(ad: AdSettings, mappings: Sequence[GroupMapping], username: str, password: str) -> AdIdentity:
    """Bind, resolve the exact account below the base DN and return its identity and mapped groups."""
    _validate(ad)
    username = (username or "").strip()
    if not username or not password or any(ord(char) < 32 for char in username):
        raise LdapAuthError("Anmeldung fehlgeschlagen.")

    upn = username if "@" in username else f"{username}@{ad.domain}"
    sam_account_name = upn.rpartition("@")[0] if _is_configured_domain_upn(ad, upn) else None
    try:
        conn = Connection(
            _build_server_pool(ad),
            user=upn,
            password=password,
            auto_bind=False,
            auto_referrals=False,
            receive_timeout=ad.receive_timeout_seconds,
        )
    except LdapConfigError:
        raise
    except LDAPBindError as exc:
        logger.warning("AD bind failed for %s (%s)", upn, type(exc).__name__)
        raise LdapAuthError("Anmeldung fehlgeschlagen.") from None
    except Exception as exc:
        logger.warning("AD connection failed (%s)", type(exc).__name__)
        raise DirectoryUnavailableError(t("AD-Anmeldedienst ist nicht erreichbar.")) from None

    try:
        # auto_bind raises the same LDAPBindError for invalid credentials and
        # server-side outages. Inspect the result to preserve retry budgets.
        if not conn.bind():
            if isinstance(conn.result, dict) and conn.result.get("result") == RESULT_INVALID_CREDENTIALS:
                raise LdapAuthError("Anmeldung fehlgeschlagen.")
            raise DirectoryUnavailableError(t("AD-Anmeldedienst hat die Bind-Anfrage nicht verarbeitet."))
        logger.info("AD bind succeeded on %s for %s", getattr(getattr(conn, "server", None), "host", "-"), upn)
        user = _resolve_user(conn, ad, upn, sam_account_name)
        if not conn.rebind(user=user.dn, password=password):
            if isinstance(conn.result, dict) and conn.result.get("result") == RESULT_INVALID_CREDENTIALS:
                raise LdapAuthError("Anmeldung fehlgeschlagen.")
            raise DirectoryUnavailableError(t("AD-Anmeldedienst hat die erneute Bind-Anfrage nicht verarbeitet."))
        groups = _matched_groups(conn, user.dn, mappings)
        return AdIdentity(
            subject=user.guid, username=user.upn, display_name=user.display_name, email=user.email,
            matched_group_ids=groups,
        )
    except LdapAuthError:
        logger.warning("AD authentication failed for %s", upn)
        raise
    except (LdapConfigError, DirectoryUnavailableError) as exc:
        logger.error("AD lookup failed for %s: %s", upn, exc)
        raise
    except Exception as exc:
        logger.error("AD lookup failed for %s (%s)", upn, type(exc).__name__)
        raise DirectoryUnavailableError(t("AD-Gruppenprüfung fehlgeschlagen.")) from None
    finally:
        try:
            conn.unbind()
        except Exception as exc:
            logger.warning("AD disconnect failed (%s)", type(exc).__name__)
