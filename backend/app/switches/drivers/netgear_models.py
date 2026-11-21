"""Netgear fully managed model catalog, matched against the model string the switch reports.

The model string is the marketing name from ``show version`` ("System Description" or
"Machine Model", e.g. ``M4250-26G4F-PoE+``). The PoE classification follows Netgear's
product naming and is not validated against hardware; see docs/switch-drivers.md:

- ``UP90`` or ``-UP`` (e.g. ``M4350-24X8F8V-UP90``) -> 802.3af/at/bt Type 4 (90 W)
- ``PoE++`` without UP -> 802.3af/at/bt Type 3
- ``PoE+`` -> 802.3af/at
- otherwise no PoE
"""

import re

from ..catalog import Catalog, ModelProfile

_AF, _AT, _BT3, _BT4 = "802.3af", "802.3at", "802.3bt-type3", "802.3bt-type4"

# (family, PoE variants exist); M7100 is a 10G aggregation line without PoE models.
_FAMILIES = (
    ("M4250", True),
    ("M4300", True),
    ("M4350", True),
    ("M5300", True),
    ("M7100", False),
)

# (id suffix, label suffix, lookahead after the family name, PoE standards); first match wins.
_POE_VARIANTS = (
    ("up", " PoE++ UP (90 W)", r"(?=.*(?:UP90|-UP\b))", (_AF, _AT, _BT4)),
    ("poe-plus-plus", " PoE++", r"(?=.*PoE\+\+)", (_AF, _AT, _BT3)),
    ("poe-plus", " PoE+", r"(?=.*PoE\+)", (_AF, _AT)),
)


def _profile(model_id: str, label: str, pattern: str, poe_standards: tuple[str, ...]) -> ModelProfile:
    return ModelProfile(
        id=model_id,
        vendor="Netgear",
        label=label,
        match=re.compile(pattern, re.IGNORECASE),
        poe_standards=poe_standards,
    )


def _models() -> tuple[ModelProfile, ...]:
    models = []
    for family, poe_family in _FAMILIES:
        base = rf"\b{family}\b"
        if poe_family:
            for suffix, label_suffix, lookahead, standards in _POE_VARIANTS:
                models.append(_profile(f"{family.lower()}-{suffix}", family + label_suffix, base + lookahead, standards))
        models.append(_profile(family.lower(), family, base, ()))
    return tuple(models)


NETGEAR_CATALOG = Catalog(_models())
