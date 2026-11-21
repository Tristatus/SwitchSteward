"""MikroTik RouterOS model catalog, matched against ``board-name`` / routerboard ``model``.

PoE follows the vendor naming only: ``-<ports>P-`` (e.g. ``CRS328-24P-4S+``) means
802.3af/at PoE-out; to be verified against the hardware documentation.
"""

import re

from ..catalog import Catalog, ModelProfile

_POE_AT = ("802.3af", "802.3at")
_NOTES = "PoE-Zuordnung aus der Herstellerbenennung (-xxP-) abgeleitet; nicht an Hardware verifiziert."


def _family(series: str, label: str) -> tuple[ModelProfile, ModelProfile]:
    return (
        ModelProfile(
            id=f"mikrotik-{series.lower()}-poe",
            vendor="MikroTik",
            label=f"MikroTik {label} mit PoE",
            match=re.compile(rf"^{series}\d*-\d+P-", re.IGNORECASE),
            poe_standards=_POE_AT,
            notes=_NOTES,
        ),
        ModelProfile(
            id=f"mikrotik-{series.lower()}",
            vendor="MikroTik",
            label=f"MikroTik {label}",
            match=re.compile(rf"^{series}\d*-", re.IGNORECASE),
            poe_standards=(),
            notes=_NOTES,
        ),
    )


MIKROTIK_CATALOG = Catalog(
    models=(
        *_family("CRS1", "CRS1xx"),
        *_family("CRS2", "CRS2xx"),
        *_family("CRS3", "CRS3xx"),
        *_family("CRS5", "CRS5xx"),
    )
)
