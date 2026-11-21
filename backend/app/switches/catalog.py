"""Model catalog types: per-driver hardware profiles matched against the reported model string."""

import re
from dataclasses import dataclass

# PoE standard IDs used by catalogs, features and the configure-interface API.
POE_STANDARDS = ("802.3af", "802.3at", "802.3bt-type3", "802.3bt-type4", "cisco-upoe")


@dataclass(frozen=True)
class ModelProfile:
    id: str
    vendor: str
    label: str
    match: re.Pattern
    # () = no PoE; None = PoE depends on modules/ports and is not restricted by the model.
    poe_standards: tuple[str, ...] | None
    poe_ports: str | None = None
    speeds: tuple[str, ...] | None = None
    notes: str | None = None


@dataclass(frozen=True)
class Catalog:
    models: tuple[ModelProfile, ...] = ()

    def __post_init__(self):
        ids = [profile.id for profile in self.models]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate model id in catalog")

    def match(self, model_string: str | None) -> ModelProfile | None:
        """First profile whose pattern is found in the reported model string."""
        text = (model_string or "").strip()
        if not text:
            return None
        return next((profile for profile in self.models if profile.match.search(text)), None)

    def get(self, model_id: str | None) -> ModelProfile | None:
        return next((profile for profile in self.models if profile.id == model_id), None)
