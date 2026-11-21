"""Microsoft Entra ID sign-in: OAuth 2.0 authorization code flow with PKCE plus OpenID Connect.

Synchronous on purpose: the routes are plain ``def`` endpoints running in the threadpool.
Tests replace ``_transport`` with an ``httpx.MockTransport``.
"""

import base64
import hashlib
import hmac
import logging
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from threading import Lock
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .. import config, crypto
from . import settings as auth_settings
from .settings import EntraSettings

logger = logging.getLogger("switchsteward.entra")

_transport: httpx.BaseTransport | None = None

CLOUDS = {
    "global": ("https://login.microsoftonline.com", "https://graph.microsoft.com"),
    "usgov": ("https://login.microsoftonline.us", "https://graph.microsoft.us"),
    "china": ("https://login.partner.microsoftonline.cn", "https://microsoftgraph.chinacloudapi.cn"),
}
SCOPES = "openid profile email User.Read"
TX_COOKIE = "switchsteward_oidc"
TX_MAX_AGE = 600
CALLBACK_PATH = auth_settings.ENTRA_CALLBACK_PATH
CLOCK_SKEW_SECONDS = 120
HTTP_TIMEOUT_SECONDS = 10
_DISCOVERY_TTL = 24 * 3600
_JWKS_TTL = 24 * 3600
_JWKS_FORCED_REFRESH_INTERVAL = 300
_CHECK_MEMBER_GROUPS_BATCH = 20

_lock = Lock()
_discovery_cache: dict[str, tuple[float, dict[str, Any]]] = {}


@dataclass
class _KeySet:
    keys: dict[str, tuple[jwt.PyJWK, str | None]] = field(default_factory=dict)
    fetched_at: float = float("-inf")
    attempted_at: float = float("-inf")


_jwks_cache: dict[str, _KeySet] = {}


class EntraAuthError(Exception):
    """Sign-in failed; ``code`` is one of ``state``, ``denied``, ``token``, ``unavailable``."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


@dataclass(frozen=True)
class EntraIdentity:
    subject: str
    username: str
    display_name: str | None
    email: str | None
    group_ids: frozenset[str]


def clear_caches() -> None:
    with _lock:
        _discovery_cache.clear()
        _jwks_cache.clear()


def _client() -> httpx.Client:
    # trust_env keeps HTTPS_PROXY support for installations behind a proxy.
    return httpx.Client(timeout=HTTP_TIMEOUT_SECONDS, transport=_transport)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _metadata_url(entra: EntraSettings) -> str:
    authority = CLOUDS[entra.cloud][0]
    return f"{authority}/{entra.tenant_id}/v2.0/.well-known/openid-configuration"


def _fetch_discovery(entra: EntraSettings) -> dict[str, Any]:
    try:
        with _client() as client:
            response = client.get(_metadata_url(entra))
            response.raise_for_status()
            meta = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise EntraAuthError("unavailable", f"discovery failed ({type(exc).__name__})") from None
    if not isinstance(meta, dict):
        raise EntraAuthError("unavailable", "discovery document is not an object")
    issuer = meta.get("issuer")
    if not isinstance(issuer, str) or not issuer.endswith(f"/{entra.tenant_id}/v2.0"):
        raise EntraAuthError("unavailable", "unexpected issuer in discovery document")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not isinstance(meta.get(key), str) or not meta[key].startswith("https://"):
            raise EntraAuthError("unavailable", f"discovery document lacks {key}")
    return meta


def discovery(entra: EntraSettings) -> dict[str, Any]:
    """Tenant-specific OpenID configuration, cached for 24 hours."""
    url = _metadata_url(entra)
    now = time.monotonic()
    with _lock:
        cached = _discovery_cache.get(url)
        if cached and now - cached[0] < _DISCOVERY_TTL:
            return cached[1]
        try:
            meta = _fetch_discovery(entra)
        except EntraAuthError:
            if cached:
                logger.warning("Entra discovery refresh failed; keeping the cached document")
                return cached[1]
            raise
        _discovery_cache[url] = (now, meta)
        logger.info("Entra discovery document loaded from %s", url)
        return meta


def _refresh_keys(jwks_uri: str, key_set: _KeySet, now: float) -> None:
    key_set.attempted_at = now
    try:
        with _client() as client:
            response = client.get(jwks_uri)
            response.raise_for_status()
            entries = response.json().get("keys", [])
        keys: dict[str, tuple[jwt.PyJWK, str | None]] = {}
        for entry in entries:
            if entry.get("kty") == "RSA" and entry.get("use", "sig") == "sig" and isinstance(entry.get("kid"), str):
                keys[entry["kid"]] = (jwt.PyJWK(entry, algorithm="RS256"), entry.get("issuer"))
    except (httpx.HTTPError, ValueError, AttributeError, jwt.PyJWTError) as exc:
        logger.warning("JWKS refresh failed, keeping %d cached keys (%s)", len(key_set.keys), type(exc).__name__)
        return
    if keys:
        key_set.keys = keys
        key_set.fetched_at = now
        logger.info("Entra JWKS loaded from %s (%d signing keys)", jwks_uri, len(keys))


def _signing_key(jwks_uri: str, kid: str) -> tuple[jwt.PyJWK, str | None]:
    now = time.monotonic()
    with _lock:
        key_set = _jwks_cache.setdefault(jwks_uri, _KeySet())
        expired = now - key_set.fetched_at > _JWKS_TTL
        # An unknown kid forces a refresh (key rollover), but at most every five minutes.
        unknown = kid not in key_set.keys and now - key_set.attempted_at >= _JWKS_FORCED_REFRESH_INTERVAL
        if expired or unknown:
            _refresh_keys(jwks_uri, key_set, now)
        if kid in key_set.keys:
            return key_set.keys[kid]
        if not key_set.keys:
            raise EntraAuthError("unavailable", "no signing keys available")
    raise EntraAuthError("token", "id_token signed with an unknown key")


def _serializer() -> URLSafeTimedSerializer:
    source = config.settings.session_secret_key or config.settings.secret_key
    if not source or len(source.encode("utf-8")) < 32:
        raise RuntimeError("Der Session-Schlüssel muss gesetzt und mindestens 32 Byte lang sein.")
    key = hmac.new(source.encode("utf-8"), b"switchsteward/oidc-transaction/v1", hashlib.sha256).digest()
    return URLSafeTimedSerializer(key, salt="switchsteward-oidc-v1")


def begin_login(entra: EntraSettings, redirect_uri: str) -> tuple[str, str]:
    """Return ``(authorize_url, signed_transaction_cookie)``."""
    meta = discovery(entra)
    verifier = _b64url(secrets.token_bytes(32))
    transaction = {
        "state": secrets.token_urlsafe(32),
        "nonce": secrets.token_urlsafe(32),
        "verifier": verifier,
    }
    params = {
        "client_id": entra.client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": SCOPES,
        "state": transaction["state"],
        "nonce": transaction["nonce"],
        "code_challenge": _b64url(hashlib.sha256(verifier.encode("ascii")).digest()),
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    return f"{meta['authorization_endpoint']}?{urlencode(params)}", _serializer().dumps(transaction)


def _load_transaction(tx_cookie: str | None) -> dict[str, str]:
    if not tx_cookie:
        raise EntraAuthError("state", "missing transaction cookie")
    try:
        transaction = _serializer().loads(tx_cookie, max_age=TX_MAX_AGE)
    except SignatureExpired:
        raise EntraAuthError("state", "transaction expired") from None
    except BadSignature:
        raise EntraAuthError("state", "invalid transaction cookie") from None
    if not isinstance(transaction, dict) or not all(
        isinstance(transaction.get(key), str) and transaction[key] for key in ("state", "nonce", "verifier")
    ):
        raise EntraAuthError("state", "malformed transaction")
    return transaction


def _client_secret(entra: EntraSettings) -> str:
    if not entra.client_secret_enc:
        raise EntraAuthError("token", "no client secret configured")
    return crypto.decrypt(entra.client_secret_enc.encode("ascii"))


def _redeem(entra: EntraSettings, meta: dict[str, Any], redirect_uri: str, code: str, verifier: str) -> dict:
    try:
        with _client() as client:
            response = client.post(
                meta["token_endpoint"],
                data={
                    "client_id": entra.client_id,
                    "client_secret": _client_secret(entra),
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "code_verifier": verifier,
                    "scope": SCOPES,
                },
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise EntraAuthError("unavailable", f"token endpoint unreachable ({type(exc).__name__})") from None
    try:
        body = response.json()
    except ValueError:
        raise EntraAuthError("token", f"token endpoint HTTP {response.status_code} without JSON") from None
    if response.status_code != 200 or not isinstance(body, dict) or "error" in body:
        error = body.get("error") if isinstance(body, dict) else None
        # error_description carries AADSTS codes and correlation ids: logged, never shown.
        description = str(body.get("error_description", ""))[:400] if isinstance(body, dict) else ""
        raise EntraAuthError("token", f"token error {error}: {description}")
    if not isinstance(body.get("id_token"), str):
        raise EntraAuthError("token", "token response lacks id_token")
    return body


def _validate_id_token(entra: EntraSettings, meta: dict[str, Any], id_token: str, nonce: str) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError:
        raise EntraAuthError("token", "malformed id_token") from None
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise EntraAuthError("token", "unexpected id_token header")
    key, key_issuer = _signing_key(meta["jwks_uri"], header["kid"])
    try:
        claims = jwt.decode(
            id_token,
            key=key.key,
            algorithms=["RS256"],
            audience=entra.client_id,
            issuer=meta["issuer"],
            leeway=CLOCK_SKEW_SECONDS,
            options={"require": ["exp", "iat", "iss", "aud", "nonce", "tid", "oid"]},
        )
    except jwt.PyJWTError as exc:
        raise EntraAuthError("token", f"id_token rejected ({type(exc).__name__})") from None
    if not secrets.compare_digest(str(claims["nonce"]).encode("utf-8"), nonce.encode("utf-8")):
        raise EntraAuthError("token", "nonce mismatch")
    if str(claims["tid"]).casefold() != entra.tenant_id.casefold():
        raise EntraAuthError("token", "wrong tenant")
    if claims.get("ver") != "2.0":
        raise EntraAuthError("token", "expected a v2.0 id_token")
    if not isinstance(claims.get("oid"), str) or not claims["oid"]:
        raise EntraAuthError("token", "id_token lacks oid")
    if isinstance(key_issuer, str) and key_issuer.replace("{tenantid}", str(claims["tid"])) != claims["iss"]:
        raise EntraAuthError("token", "signing key is not valid for this issuer")
    return claims


def _has_overage(claims: Mapping[str, Any]) -> bool:
    claim_names = claims.get("_claim_names")
    return (isinstance(claim_names, dict) and "groups" in claim_names) or claims.get("hasgroups") is True


def _check_member_groups(entra: EntraSettings, access_token: str, group_ids: list[str]) -> set[str]:
    graph = CLOUDS[entra.cloud][1]
    found: set[str] = set()
    try:
        with _client() as client:
            for index in range(0, len(group_ids), _CHECK_MEMBER_GROUPS_BATCH):
                response = client.post(
                    f"{graph}/v1.0/me/checkMemberGroups",
                    json={"groupIds": group_ids[index:index + _CHECK_MEMBER_GROUPS_BATCH]},
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if response.status_code != 200:
                    raise EntraAuthError("unavailable", f"checkMemberGroups HTTP {response.status_code}")
                values = response.json().get("value", [])
                found.update(str(value).lower() for value in values)
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        raise EntraAuthError("unavailable", f"checkMemberGroups failed ({type(exc).__name__})") from None
    return found


def _group_ids(entra: EntraSettings, claims: Mapping[str, Any], access_token: str | None) -> frozenset[str]:
    groups = claims.get("groups")
    if isinstance(groups, list):
        return frozenset(str(group).lower() for group in groups)
    if not _has_overage(claims):
        return frozenset()
    # Overage: ask Graph only about mapped groups; the _claim_sources endpoint is never called.
    mapped = sorted({mapping.group_id.lower() for mapping in auth_settings.list_mappings("entra")})
    if not mapped:
        return frozenset()
    if not access_token:
        raise EntraAuthError("token", "group overage without access token")
    return frozenset(_check_member_groups(entra, access_token, mapped))


def complete_login(
    entra: EntraSettings, redirect_uri: str, params: Mapping[str, str], tx_cookie: str | None,
) -> EntraIdentity:
    """Validate the callback and return the signed-in identity with its group object IDs."""
    transaction = _load_transaction(tx_cookie)
    state = params.get("state") or ""
    if not secrets.compare_digest(state.encode("utf-8"), transaction["state"].encode("utf-8")):
        raise EntraAuthError("state", "state mismatch")
    if params.get("error"):
        raise EntraAuthError("denied", f"{params.get('error')}: {str(params.get('error_description', ''))[:300]}")
    code = params.get("code")
    if not code:
        raise EntraAuthError("token", "callback without code")
    meta = discovery(entra)
    tokens = _redeem(entra, meta, redirect_uri, code, transaction["verifier"])
    claims = _validate_id_token(entra, meta, tokens["id_token"], transaction["nonce"])
    access_token = tokens.get("access_token") if isinstance(tokens.get("access_token"), str) else None
    group_ids = _group_ids(entra, claims, access_token)
    tenant = str(claims["tid"]).lower()
    oid = str(claims["oid"]).lower()
    username = next(
        (str(claims[name]) for name in ("preferred_username", "upn", "email") if isinstance(claims.get(name), str)
         and claims[name].strip()),
        oid,
    )
    display_name = claims.get("name") if isinstance(claims.get("name"), str) else None
    email = claims.get("email") if isinstance(claims.get("email"), str) else None
    return EntraIdentity(
        subject=f"{tenant}:{oid}", username=username, display_name=display_name, email=email, group_ids=group_ids,
    )


def check_configuration(entra: EntraSettings) -> dict[str, Any]:
    """Load the tenant's discovery document (bypassing the cache) for the admin check."""
    meta = _fetch_discovery(entra)
    with _lock:
        _discovery_cache[_metadata_url(entra)] = (time.monotonic(), meta)
    return meta
