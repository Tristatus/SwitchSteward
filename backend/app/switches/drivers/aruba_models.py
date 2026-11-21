"""Aruba model catalogs (AOS-CX and AOS-S), matched against the model string the switch reports.

The PoE classification follows Aruba's product naming (``CL4``/``Class 4``/``PoE``, ``CL6``/``Class 6``)
and is not validated against hardware; see docs/switch-drivers.md.
"""

import re

from ..catalog import Catalog, ModelProfile

_AF, _AT, _BT3 = "802.3af", "802.3at", "802.3bt-type3"

# ---------------------------------------------------------------------------
# AOS-CX: "Product Name" from ``show system``, e.g. "JL659A 6300M 48SR5 CL6 PoE 4SFP56 Swch".
# ---------------------------------------------------------------------------

_AOSCX_CLASS6 = r"(?=.*\b(?:CL6|Class 6)\b)"
_AOSCX_POE = r"(?=.*\b(?:CL4|Class 4|PoE)\b)"
_AOSCX_CHASSIS_NOTE = "PoE hängt von den eingesetzten Line-Cards ab."

# (id, label, family pattern, PoE-capable family); PoE families get Class-6 / PoE / non-PoE variants.
_AOSCX_FAMILIES = (
    ("6000", "CX 6000", r"6000", True),
    ("6100", "CX 6100", r"6100", True),
    ("6200f", "CX 6200F", r"6200F", True),
    ("6300m", "CX 6300M", r"6300M", True),
    ("6300f", "CX 6300F", r"6300F", True),
    ("8100", "CX 8100", r"8100", False),
    ("8320", "CX 8320", r"8320", False),
    ("8325", "CX 8325", r"8325", False),
    ("8360", "CX 8360", r"8360", False),
)


def _aoscx_profile(model_id: str, label: str, pattern: str, poe_standards, notes: str | None = None) -> ModelProfile:
    return ModelProfile(
        id=f"aoscx-{model_id}",
        vendor="Aruba",
        label=label,
        match=re.compile(pattern, re.IGNORECASE),
        poe_standards=poe_standards,
        notes=notes,
    )


def _aoscx_models() -> tuple[ModelProfile, ...]:
    models = []
    for model_id, label, family, poe_family in _AOSCX_FAMILIES:
        base = rf"\b{family}\b"
        if poe_family:
            models.append(_aoscx_profile(f"{model_id}-cl6", f"{label} Class 6 PoE", _AOSCX_CLASS6 + base,
                                         (_AF, _AT, _BT3)))
            models.append(_aoscx_profile(f"{model_id}-poe", f"{label} PoE", _AOSCX_POE + base, (_AF, _AT)))
        models.append(_aoscx_profile(model_id, label, base, ()))
    # Modular 6400 chassis (6405/6410): PoE depends on the line cards, so the model does not restrict it.
    models.append(_aoscx_profile("6400", "CX 6400", r"\b64(?:00|05|10)\b", None, _AOSCX_CHASSIS_NOTE))
    return tuple(models)


AOSCX_CATALOG = Catalog(_aoscx_models())

# ---------------------------------------------------------------------------
# AOS-S: maintained by the AOS-S driver (AOSS_CATALOG).
# ---------------------------------------------------------------------------
# Chassis line from ``show modules``, e.g. "2930F-24G-PoE+-4SFP+ JL255A" or "5406Rzl2 J9850A".

_AOSS_CLASS6 = r"(?=.*(?:\bPoE[ -]?Class ?6\b|\bClass ?6\b))"
_AOSS_POE_PLUS = r"(?=.*\bPoE(?:\+|P\b))"
_AOSS_POE = r"(?=.*\bPoE\b)"
_AOSS_CHASSIS_NOTE = "PoE hängt von den eingesetzten Modulen ab."

# (id, label, family pattern, family has Class-6 models)
_AOSS_FAMILIES = (
    ("2530", "Aruba 2530", r"2530", False),
    ("2540", "Aruba 2540", r"2540", False),
    ("2930f", "Aruba 2930F", r"2930F", False),
    ("2930m", "Aruba 2930M", r"2930M", True),
    ("3810m", "Aruba 3810M", r"3810M?", True),
)


def _aoss_profile(model_id: str, label: str, pattern: str, poe_standards, notes: str | None = None) -> ModelProfile:
    return ModelProfile(
        id=f"aoss-{model_id}",
        vendor="Aruba",
        label=label,
        match=re.compile(pattern, re.IGNORECASE),
        poe_standards=poe_standards,
        notes=notes,
    )


def _aoss_models() -> tuple[ModelProfile, ...]:
    models = []
    for model_id, label, family, class6 in _AOSS_FAMILIES:
        base = rf"\b{family}\b"
        if class6:
            models.append(_aoss_profile(f"{model_id}-cl6", f"{label} PoE Class 6", _AOSS_CLASS6 + base,
                                        (_AF, _AT, _BT3)))
        models.append(_aoss_profile(f"{model_id}-poep", f"{label} PoE+", _AOSS_POE_PLUS + base, (_AF, _AT)))
        models.append(_aoss_profile(f"{model_id}-poe", f"{label} PoE", _AOSS_POE + base, (_AF,)))
        models.append(_aoss_profile(model_id, label, base, ()))
    # Modular 5400R chassis (5406R/5412R): PoE depends on the modules, so the model does not restrict it.
    models.append(_aoss_profile("5400r", "Aruba 5400R", r"\b54(?:00|06|12)R", None, _AOSS_CHASSIS_NOTE))
    return tuple(models)


AOSS_CATALOG = Catalog(_aoss_models())
