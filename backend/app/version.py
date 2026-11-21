"""Die installierte Release-Version hat genau eine Quelle: VERSION im Projekt."""

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_VERSION_PATTERN = re.compile(
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)


def validate_version(value: str) -> str:
    value = value.strip()
    if len(value) > 100 or not _VERSION_PATTERN.fullmatch(value):
        raise ValueError("VERSION muss eine Versionsnummer wie 1.2.3 enthalten.")
    return value


def get_version(root: Path = PROJECT_ROOT) -> str:
    try:
        return validate_version((root / "VERSION").read_text(encoding="utf-8").strip())
    except (OSError, UnicodeError, ValueError):
        return "unbekannt"
