#!/usr/bin/env python3
"""Build the SwitchSteward release archives.

Writes dist/switchsteward.zip and dist/switchsteward.tar.gz with the single root folder
``switchsteward/``. The file list comes from backend/app/release_manifest.py, which is loaded
by path, so the build needs only the Python standard library. The archives contain regular
files only, with fixed timestamps; they are the packages the web updater accepts.
"""

import gzip
import importlib.util
import io
import stat
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = "switchsteward"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
TAR_TIMESTAMP = 315532800  # 1980-01-01T00:00:00Z
EXECUTABLE = "backend/start.sh"


def _manifest():
    path = ROOT / "backend" / "app" / "release_manifest.py"
    spec = importlib.util.spec_from_file_location("release_manifest", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def release_files() -> list[str]:
    manifest = _manifest()
    names = set(
        manifest.DOC_FILES + manifest.BACKEND_FILES + manifest.REQUIRED_FRONTEND_FILES + manifest.REQUIRED_MODULES
    )
    for folder, pattern in (("frontend", manifest.FRONTEND_PATTERN), ("docs", manifest.DOC_PATTERN)):
        for path in (ROOT / folder).iterdir():
            name = f"{folder}/{path.name}"
            if path.is_file() and pattern.fullmatch(name):
                names.add(name)
    for path in (ROOT / "backend" / "app").rglob("*.py"):
        parts = path.relative_to(ROOT).parts
        if "__pycache__" not in parts and not any(part.startswith(".") for part in parts):
            names.add("/".join(parts))
    missing = sorted(name for name in names if not (ROOT / name).is_file())
    if missing:
        raise SystemExit("Missing release files: " + ", ".join(missing))
    return sorted(names)


def _read(name: str) -> bytes:
    data = (ROOT / name).read_bytes()
    return data.replace(b"\r\n", b"\n") if name == EXECUTABLE else data


def _mode(name: str) -> int:
    return 0o755 if name == EXECUTABLE else 0o644


def build(dist: Path) -> list[Path]:
    files = [(name, _read(name)) for name in release_files()]
    dist.mkdir(parents=True, exist_ok=True)
    zip_path = dist / f"{NAME}.zip"
    tar_path = dist / f"{NAME}.tar.gz"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in files:
            info = zipfile.ZipInfo(f"{NAME}/{name}", date_time=ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # Unix: keeps the mode bits in external_attr
            info.external_attr = (stat.S_IFREG | _mode(name)) << 16
            archive.writestr(info, data)
    with tar_path.open("wb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name, data in files:
                    info = tarfile.TarInfo(f"{NAME}/{name}")
                    info.size = len(data)
                    info.mode = _mode(name)
                    info.mtime = TAR_TIMESTAMP
                    archive.addfile(info, io.BytesIO(data))
    return [zip_path, tar_path]


def main() -> None:
    for path in build(ROOT / "dist"):
        print(path.relative_to(ROOT).as_posix())


if __name__ == "__main__":
    main()
