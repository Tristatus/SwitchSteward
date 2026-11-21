"""Device settings read route: ``GET /api/switches/{id}/device-config``.

Writes go through the change framework (``ops/device.py``).
"""

from fastapi import APIRouter

from ..auth import CurrentPrincipal
from . import features, service
from .coalescing import coalesced_read
from .operations import SECRET_FIELDS
from .routes import _get_switch_and_creds

router = APIRouter(prefix="/api", tags=["switches"])

# Response block -> feature that must be supported for the block to be reported.
BLOCK_FEATURES = (
    ("identity", "device_identity"),
    ("services", "device_services"),
    ("snmp", "device_snmp"),
    ("aaa", "device_aaa"),
    ("users", "device_users"),
    ("ssh", "device_ssh"),
    ("l3", "device_l3"),
    ("acls", "acl"),
    ("qos", "qos"),
)


def _without_secrets(value):
    """Defense in depth: drivers never report secrets, but a stray key must not reach the browser."""
    if isinstance(value, dict):
        return {key: _without_secrets(item) for key, item in value.items() if key not in SECRET_FIELDS}
    if isinstance(value, list):
        return [_without_secrets(item) for item in value]
    return value


@coalesced_read
def get_device_config(switch: dict, credentials: dict) -> dict:
    driver = service.driver_for(switch)
    capabilities = features.for_switch(driver, switch)
    if not any(capabilities[feature].supported for _block, feature in BLOCK_FEATURES):
        features.require(capabilities, "device_identity")
    with driver.session(switch, credentials) as session:
        config = driver.read_device_config(session) or {}
        warnings = list(session.warnings)
    result = {
        block: _without_secrets(config.get(block)) if capabilities[feature].supported else None
        for block, feature in BLOCK_FEATURES
    }
    result["warnings"] = warnings
    return result


@router.get("/switches/{switch_id}/device-config")
def api_device_config(switch_id: int, _: CurrentPrincipal):
    switch, creds = _get_switch_and_creds(switch_id)
    return get_device_config(switch, creds)
