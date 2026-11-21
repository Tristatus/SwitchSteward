"""Validierte Release-Archive und wiederherstellbare Updates des lokalen Servers.

Nur der Launcher app.run darf eine Installation beginnen: Er beendet erst alle
Anfragen, tauscht danach Dateien aus und startet einen frischen Python-Prozess.
Konfiguration, Datenbanken, Zertifikate und die bisherige venv bleiben bestehen.
"""

import gzip
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import traceback
import uuid
import zipfile
import zlib
from contextlib import closing, contextmanager
from pathlib import Path, PurePosixPath
from typing import Callable

from .i18n import t
from .release_manifest import (
    BACKEND_FILES,
    DOC_FILES,
    DOC_PATTERN,
    FRONTEND_PATTERN,
    REQUIRED_FRONTEND_FILES,
    REQUIRED_MODULES,
)
from .version import PROJECT_ROOT, get_version, validate_version

logger = logging.getLogger("switchsteward.updates")
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_UNPACKED_BYTES = 200 * 1024 * 1024
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_FILES = 2000
_FIXED_FILES = frozenset(DOC_FILES + BACKEND_FILES + REQUIRED_FRONTEND_FILES)
_REQUIRED_FILES = _FIXED_FILES | frozenset(REQUIRED_MODULES)
_ID_PATTERN = re.compile(r"[a-f0-9]{32}")
_PROBE = """
import asyncio
from app.main import app

async def check():
    async with app.router.lifespan_context(app):
        pass

asyncio.run(check())
"""


def _is_path_key(key: str) -> bool:
    """Config keys holding filesystem paths (relative ones resolve against the config file)."""
    return key.endswith(("_file", "_dir")) or key in {"database_path", "directory"}


def _localized_result(result):
    """Installation results are stored with the German message ID (written outside any request)."""
    if isinstance(result, dict) and isinstance(result.get("message"), str):
        return {**result, "message": t(result["message"])}
    return result


class UpdateError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _allowed_file(name: str) -> bool:
    path = PurePosixPath(name)
    if name in _FIXED_FILES or FRONTEND_PATTERN.fullmatch(name) or DOC_PATTERN.fullmatch(name):
        return True
    return (
        name.startswith("backend/app/") and path.suffix == ".py"
        and all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", part) for part in path.parts)
        and "__pycache__" not in path.parts
    )


def _archive_path(name: str) -> str:
    parts = name.split("/")
    if (not name or "\\" in name or "\x00" in name or ":" in name
            or any(part in {"", ".", ".."} or part.endswith((" ", ".")) for part in parts)
            or parts[0] != "switchsteward" or len(parts) < 2):
        raise UpdateError(t("Ungültiger Archivpfad. Bitte das gebaute SwitchSteward Release-Archiv verwenden."))
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    if any(part.split(".")[0].upper() in reserved for part in parts):
        raise UpdateError(t("Das Archiv enthält einen reservierten Dateipfad."))
    relative = "/".join(parts[1:])
    if not _allowed_file(relative):
        raise UpdateError(t("Nicht erlaubte Release-Datei: {path}", path=relative[:150]))
    return relative


def _write_json(path: Path, value: dict) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".switchsteward-state-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


class _LimitedTarReader:
    """Count all decompressed bytes, including otherwise unbounded PAX metadata."""

    def __init__(self, stream):
        self.stream = stream
        self.remaining = MAX_UNPACKED_BYTES + MAX_FILES * 2048

    def read(self, size: int) -> bytes:
        if size < 0 or size > self.remaining:
            raise UpdateError(t("Das entpackte tar-Archiv überschreitet die Größenbegrenzung."), 413)
        data = self.stream.read(size)
        self.remaining -= len(data)
        return data


def _atomic_copy(source: Path, target: Path) -> None:
    # Temporary siblings keep rename atomic on the same filesystem, including
    # run.py and this recovery module. A crash never leaves a truncated module.
    descriptor, temporary_name = tempfile.mkstemp(prefix=".switchsteward-update-", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
        shutil.copystat(source, temporary)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


class UpdateManager:
    def __init__(self, root: Path = PROJECT_ROOT):
        self.root = root.resolve()
        self.directory = self.root / ".updates"
        self._mutex = threading.Lock()
        self._shutdown: Callable[[], None] | None = None

    def register_shutdown(self, callback: Callable[[], None] | None) -> None:
        self._shutdown = callback

    def _safe_path(self, relative: str) -> Path:
        path = self.root / relative
        for ancestor in (path, *path.parents):
            if ancestor == self.root:
                break
            # is_junction is only available on newer Python versions; resolve
            # additionally prevents Windows junctions escaping the installation.
            if ancestor.is_symlink() or getattr(ancestor, "is_junction", lambda: False)():
                raise UpdateError(t("Updates sind bei verlinkten Anwendungsdateien nicht möglich."), 409)
        if not path.resolve().is_relative_to(self.root):
            raise UpdateError(t("Ein Update-Pfad liegt außerhalb der Installation."), 409)
        return path

    def _remove_tree(self, path: Path) -> None:
        expected = self._safe_path(path.relative_to(self.root).as_posix())
        if expected == self.directory or not expected.resolve().is_relative_to(self.directory.resolve()):
            raise UpdateError(t("Ungültiges Update-Arbeitsverzeichnis."))
        if expected.exists():
            shutil.rmtree(expected)

    @contextmanager
    def _locked(self):
        if not self._mutex.acquire(blocking=False):
            raise UpdateError(t("Ein Update wird bereits verarbeitet."), 409)
        handle = None
        acquired = False
        try:
            lock_path = self._safe_path(".updates/lock")
            self.directory.mkdir(mode=0o700, exist_ok=True)
            handle = lock_path.open("a+b")
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                if not lock_path.stat().st_size:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise UpdateError(t("Ein Update wird bereits verarbeitet."), 409) from exc
            else:
                import fcntl

                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    raise UpdateError(t("Ein Update wird bereits verarbeitet."), 409) from exc
            acquired = True
            yield
        finally:
            if handle is not None:
                if acquired:
                    handle.seek(0)
                    if os.name == "nt":
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                handle.close()
            self._mutex.release()

    def _state(self) -> dict:
        path = self._safe_path(".updates/state.json")
        if not path.exists():
            return {}
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(state, dict):
                raise ValueError
            return state
        except (OSError, UnicodeError, ValueError) as exc:
            raise UpdateError(t("Der Update-Status ist beschädigt. Das Verzeichnis .updates prüfen."), 409) from exc

    def _save(self, state: dict) -> None:
        _write_json(self._safe_path(".updates/state.json"), state)

    def status(self) -> dict:
        state = self._state()
        candidate = state.get("candidate")
        return {
            "current_version": get_version(self.root),
            "update_supported": self._shutdown is not None,
            "max_upload_bytes": MAX_UPLOAD_BYTES,
            "pending": candidate if state.get("phase") in {"staged", "requested"} else None,
            "last_result": _localized_result(state.get("last_result")),
        }

    def unaudited_result(self) -> dict | None:
        """Last installation result that has not yet been written to the audit trail."""
        state = self._state()
        result = state.get("last_result")
        if not isinstance(result, dict) or state.get("result_audited") == result.get("update_id"):
            return None
        return result

    def mark_result_audited(self, update_id: str) -> None:
        with self._locked():
            state = self._state()
            state["result_audited"] = update_id
            self._save(state)

    def _extract(self, archive_path: Path, destination: Path) -> list[str]:
        names: dict[str, str] = {}
        total = 0

        def extract(name, size, reader):
            nonlocal total
            relative = _archive_path(name)
            key = relative.casefold()
            if key in names:
                raise UpdateError(t("Das Archiv enthält doppelte Dateipfade."))
            if len(names) >= MAX_FILES or size < 0 or size > MAX_FILE_BYTES or total + size > MAX_UNPACKED_BYTES:
                raise UpdateError(t("Das entpackte Release überschreitet die Größenbegrenzung."), 413)
            names[key] = relative
            total += size
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with reader() as source, target.open("wb") as output:
                written = 0
                while chunk := source.read(128 * 1024):
                    written += len(chunk)
                    if written > size:
                        raise UpdateError(t("Ungültige Dateigröße im Archiv."))
                    output.write(chunk)
                if written != size:
                    raise UpdateError(t("Das Release-Archiv ist unvollständig."))
            target.chmod(0o755 if relative == "backend/start.sh" else 0o644)

        try:
            if zipfile.is_zipfile(archive_path):
                # Bound central-directory entry allocation before ZipFile builds
                # its in-memory list. ZIP64/multipart are unnecessary below 50 MiB.
                with archive_path.open("rb") as stream:
                    stream.seek(max(0, archive_path.stat().st_size - 65557))
                    trailer = stream.read()
                offset = trailer.rfind(b"PK\x05\x06")
                if offset < 0 or len(trailer) - offset < 22:
                    raise UpdateError(t("Ungültiges ZIP-Verzeichnis."))
                _, disk, directory_disk, count, total_count, directory_bytes, _, _ = struct.unpack_from(
                    "<4s4H2LH", trailer, offset,
                )
                # ZipFile parses the entire central directory and does not use
                # the declared count as its stopping condition. Bound both.
                if (disk or directory_disk or count != total_count or total_count > MAX_FILES
                        or directory_bytes > MAX_FILES * 1024):
                    raise UpdateError(t("Das ZIP-Archiv enthält zu viele Dateien oder verwendet ein nicht unterstütztes Format."), 413)
                with zipfile.ZipFile(archive_path) as archive:
                    for entry in archive.infolist():
                        mode = entry.external_attr >> 16
                        if entry.is_dir() or stat.S_IFMT(mode) not in {0, stat.S_IFREG} or entry.flag_bits & 1:
                            raise UpdateError(t("Das Release darf nur reguläre, unverschlüsselte Dateien enthalten."))
                        extract(entry.filename, entry.file_size, lambda entry=entry: archive.open(entry))
            else:
                with gzip.open(archive_path, "rb") as compressed, tarfile.open(
                    fileobj=_LimitedTarReader(compressed), mode="r|",
                ) as archive:
                    for entry in archive:
                        if not entry.isfile() or entry.issparse():
                            raise UpdateError(t("Das Release darf keine Links oder Spezialdateien enthalten."))
                        extract(entry.name, entry.size, lambda entry=entry: archive.extractfile(entry))
        except (zipfile.BadZipFile, tarfile.TarError, gzip.BadGzipFile, zlib.error,
                EOFError, UnicodeError, ValueError, RuntimeError) as exc:
            if isinstance(exc, UpdateError):
                raise
            raise UpdateError(t("Ungültiges oder beschädigtes ZIP-/tar.gz-Release-Archiv.")) from exc
        files = sorted(names.values())
        missing = _REQUIRED_FILES - set(files)
        if missing:
            raise UpdateError(t("Unvollständiges Release: {files}", files=", ".join(sorted(missing))))
        for name in files:
            if name.endswith(".py"):
                try:
                    compile((destination / name).read_bytes(), name, "exec")
                except (SyntaxError, ValueError) as exc:
                    raise UpdateError(
                        t("Python-Datei ist mit dieser Python-Version nicht kompatibel: {name}", name=name)
                    ) from exc
        return files

    def stage_archive(self, archive_path: Path) -> dict:
        if self._shutdown is None:
            raise UpdateError(t("Web-Updates benötigen einen Start über backend/start.sh, start.ps1 oder python -m app.run."), 409)
        if not 0 < archive_path.stat().st_size <= MAX_UPLOAD_BYTES:
            raise UpdateError(t("Das Release-Archiv darf maximal 50 MiB groß sein."), 413)
        with self._locked():
            state = self._state()
            if state.get("phase") in {"requested", "applying", "validating"}:
                raise UpdateError(t("Eine Installation läuft bereits."), 409)
            update_id = uuid.uuid4().hex
            if shutil.disk_usage(self.root).free < MAX_UNPACKED_BYTES + MAX_UPLOAD_BYTES:
                raise UpdateError(t("Für ein Update werden mindestens 250 MiB freier Speicher benötigt."), 409)
            staging = self._safe_path(f".updates/staging/{update_id}")
            staging.mkdir(parents=True, mode=0o700)
            try:
                files = self._extract(archive_path, staging)
                try:
                    version = validate_version((staging / "VERSION").read_text(encoding="utf-8"))
                except (ValueError, UnicodeError) as exc:
                    raise UpdateError(t("Das Release enthält keine gültige VERSION.")) from exc
                current = get_version(self.root)
                if version == current:
                    raise UpdateError(t("Diese Version ist bereits installiert."), 409)
                self._check_runtime_paths(set(files))
                with archive_path.open("rb") as stream:
                    digest = hashlib.sha256()
                    while chunk := stream.read(128 * 1024):
                        digest.update(chunk)
                candidate = {"update_id": update_id, "version": version, "current_version": current,
                             "sha256": digest.hexdigest(), "files": len(files)}
                previous = state.get("candidate", {}).get("update_id")
                self._save({"phase": "staged", "candidate": candidate, "files": files,
                            "hashes": {name: hashlib.sha256((staging / name).read_bytes()).hexdigest() for name in files},
                            "last_result": state.get("last_result")})
                if previous and _ID_PATTERN.fullmatch(previous):
                    try:
                        self._remove_tree(self.directory / "staging" / previous)
                    except OSError:
                        logger.warning("Altes Update-Arbeitsverzeichnis konnte nicht entfernt werden", exc_info=True)
                return candidate
            except BaseException:
                self._remove_tree(staging)
                raise

    def request_install(self, update_id: str) -> dict:
        if self._shutdown is None:
            raise UpdateError(t("Der Server unterstützt keinen automatischen Neustart; bitte app.run verwenden."), 409)
        with self._locked():
            state = self._state()
            candidate = state.get("candidate", {})
            if state.get("phase") != "staged" or candidate.get("update_id") != update_id:
                raise UpdateError(t("Dieses Release ist nicht mehr zur Installation vorgemerkt. Erneut hochladen."), 409)
            self._verify_staging(state)
            state["phase"] = "requested"
            self._save(state)
            return candidate

    def begin_restart(self) -> None:
        if self._shutdown is not None and self._state().get("phase") == "requested":
            self._shutdown()

    def cancel_install(self, update_id: str) -> None:
        with self._locked():
            state = self._state()
            if state.get("phase") == "requested" and state.get("candidate", {}).get("update_id") == update_id:
                state["phase"] = "staged"
                self._save(state)

    def _verify_staging(self, state: dict) -> Path:
        update_id = state.get("candidate", {}).get("update_id", "")
        if not isinstance(update_id, str) or not _ID_PATTERN.fullmatch(update_id):
            raise UpdateError(t("Ungültige Update-ID."), 409)
        staging = self._safe_path(f".updates/staging/{update_id}")
        for name in state.get("files", []):
            if not _allowed_file(name):
                raise UpdateError(t("Ungültige Update-Dateiliste."), 409)
            source = self._safe_path(f".updates/staging/{update_id}/{name}")
            self._safe_path(name)
            if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != state["hashes"].get(name):
                raise UpdateError(t("Die vorgemerkten Release-Dateien wurden verändert. Erneut hochladen."), 409)
        return staging

    def _config_path(self) -> Path:
        path = Path(os.environ.get("SWITCHSTEWARD_CONFIG_FILE", "config.json")).expanduser()
        return (path if path.is_absolute() else self.root / "backend" / path).resolve()

    def _check_runtime_paths(self, managed: set[str]) -> None:
        config_path = self._config_path()
        data = json.loads(config_path.read_text(encoding="utf-8"))
        protected = {config_path}

        def collect(node):
            for key, value in node.items():
                if isinstance(value, dict):
                    collect(value)
                elif value and _is_path_key(key):
                    path = Path(value).expanduser()
                    protected.add((path if path.is_absolute() else config_path.parent / path).resolve())

        collect(data)
        frontend = Path(data["application"]["frontend_dir"]).expanduser()
        frontend = (frontend if frontend.is_absolute() else config_path.parent / frontend).resolve()
        if frontend != self.root / "frontend":
            raise UpdateError(t("Web-Updates benötigen das frontend-Verzeichnis dieser Installation; die Konfiguration verweist auf ein anderes Verzeichnis."), 409)
        targets = {self._safe_path(name).resolve() for name in managed}
        if (targets & protected or any(path.is_relative_to(self.directory) for path in protected)
                or any(path.is_relative_to(self.root / "backend/app") and "__pycache__" in path.parts
                       for path in protected)):
            raise UpdateError(t("Eine konfigurierte Laufzeitdatei liegt in einem vom Update verwalteten Pfad. Speicherort vor dem Update ändern."), 409)

    def _clear_bytecode(self) -> None:
        for path in (self.root / "backend/app").rglob("__pycache__"):
            checked = self._safe_path(path.relative_to(self.root).as_posix())
            if checked.is_dir():
                shutil.rmtree(checked)

    def selected_python(self) -> str:
        path = self._safe_path(".updates/python.json")
        if not path.exists():
            return sys.executable
        data = json.loads(path.read_text(encoding="utf-8"))
        python = self._safe_path(data["python"])
        if not python.is_file() or not python.is_relative_to(self.directory / "environments"):
            raise UpdateError(t("Die virtuelle Update-Umgebung fehlt; .updates/python.json prüfen."), 409)
        return str(python)

    def _dependencies(self, staging: Path, update_id: str) -> str:
        requirements = staging / "backend/requirements.txt"
        if requirements.read_bytes() == (self.root / "backend/requirements.txt").read_bytes():
            return self.selected_python()
        environment = self._safe_path(f".updates/environments/{update_id}")
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        # A new environment makes even a partially failed pip install harmless
        # to the running/previous release. Keep its final path (venvs cannot move).
        self._run([sys.executable, "-m", "venv", "--copies", str(environment)], timeout=180)
        self._run([str(python), "-m", "pip", "install", "--disable-pip-version-check", "-r", str(requirements)],
                  timeout=600)
        return str(python)

    def _run(self, command: list[str], *, timeout: int, env: dict | None = None) -> None:
        with (self.directory / "update.log").open("ab") as output:
            result = subprocess.run(  # noqa: S603 - administrator supplied release, no shell
                command, cwd=self.root / "backend", env=env, stdout=output, stderr=subprocess.STDOUT,
                timeout=timeout, check=False,
            )
        if result.returncode:
            raise UpdateError(t("Abhängigkeiten oder Startprüfung fehlgeschlagen; Details stehen in .updates/update.log."), 500)

    def _validate_install(self, python: str) -> None:
        # Exercise the real application lifespan with a consistent SQLite copy.
        # Schema changes during this probe must never touch the live database.
        config_path = self._config_path()
        data = json.loads(config_path.read_text(encoding="utf-8"))

        def absolute_paths(node):
            for key, value in node.items():
                if isinstance(value, dict):
                    absolute_paths(value)
                elif value and _is_path_key(key):
                    path = Path(value).expanduser()
                    node[key] = str(path if path.is_absolute() else config_path.parent / path)

        absolute_paths(data)
        with tempfile.TemporaryDirectory(prefix="probe-", dir=self.directory) as temporary:
            probe_dir = Path(temporary)
            probe_dir.chmod(0o700)
            database = Path(data["application"]["database_path"])
            if database.exists():
                with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as source:
                    with closing(sqlite3.connect(probe_dir / "database.db")) as target:
                        source.backup(target)
            data["application"]["database_path"] = str(probe_dir / "database.db")
            # Keep probe logs out of the production log directory.
            data.setdefault("logging", {})["directory"] = str(probe_dir / "logs")
            probe_config = probe_dir / "config.json"
            _write_json(probe_config, data)
            probe_config.chmod(0o600)
            env = dict(os.environ, SWITCHSTEWARD_CONFIG_FILE=str(probe_config))
            env.pop("PYTHONPATH", None)
            self._run([python, "-c", _PROBE], timeout=120, env=env)

    def _restore(self, state: dict) -> None:
        update_id = state["candidate"]["update_id"]
        if not _ID_PATTERN.fullmatch(update_id):
            raise UpdateError(t("Ungültige Wiederherstellungs-ID."))
        for name, existed in state.get("originals", {}).items():
            if not _allowed_file(name) and name != ".updates/python.json":
                raise UpdateError(t("Ungültige Wiederherstellungsdatei."))
            target = self._safe_path(name)
            if existed:
                source = self._safe_path(f".updates/backups/{update_id}/{name}")
                if not source.is_file():
                    raise UpdateError(t("Die Update-Sicherung ist unvollständig. Manuelle Wiederherstellung erforderlich."), 500)
                target.parent.mkdir(parents=True, exist_ok=True)
                _atomic_copy(source, target)
            else:
                target.unlink(missing_ok=True)

    def _result(self, state: dict, success: bool, message: str) -> None:
        result = {
            "status": "success" if success else "error", "message": message,
            "version": state["candidate"]["version"], "update_id": state["candidate"]["update_id"],
        }
        changed = {**state, "phase": "done" if success else "failed", "last_result": result}
        self._save(changed)
        state.update(changed)

    def apply_pending(self) -> bool:
        """After server shutdown: install, or restore the complete previous code."""
        if self._state().get("phase") != "requested":
            return False
        with self._locked():
            state = self._state()
            logger.info("Applying update %s", state.get("candidate", {}).get("version"))
            try:
                log_path = self._safe_path(".updates/update.log")
                if log_path.exists() and log_path.stat().st_size > 5 * 1024 * 1024:
                    log_path.write_bytes(b"")
                staging = self._verify_staging(state)
                update_id = state["candidate"]["update_id"]
                python = self._dependencies(staging, update_id)
                managed = set(state["files"])
                managed.update(
                    path.relative_to(self.root).as_posix()
                    for path in (self.root / "backend/app").rglob("*.py")
                    if "__pycache__" not in path.parts
                    and _allowed_file(path.relative_to(self.root).as_posix())
                )
                managed.add(".updates/python.json")
                self._check_runtime_paths(managed)
                state["originals"] = {}
                for name in sorted(managed):
                    source = self._safe_path(name)
                    state["originals"][name] = source.is_file()
                    if source.exists():
                        if not source.is_file():
                            raise UpdateError(t("Eine Anwendungsdatei ist kein regulärer Dateipfad."), 409)
                        target = self._safe_path(f".updates/backups/{update_id}/{name}")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        _atomic_copy(source, target)
                state["phase"] = "applying"
                self._save(state)
                # VERSION changes last, so it never announces a partial copy.
                for name in sorted(managed - {"VERSION", ".updates/python.json"}) + ["VERSION"]:
                    target = self._safe_path(name)
                    if name in state["files"]:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        _atomic_copy(staging / name, target)
                    else:
                        target.unlink(missing_ok=True)
                if Path(python).is_relative_to(self.directory / "environments"):
                    _write_json(self._safe_path(".updates/python.json"),
                                {"python": Path(python).relative_to(self.root).as_posix()})
                state["phase"] = "validating"
                self._save(state)
                self._clear_bytecode()
                self._validate_install(python)
                self._result(state, True, t("Release installiert und Startprüfung erfolgreich. Server wird neu gestartet."))
                logger.info("Update %s installed and validated", state["candidate"]["version"])
            except Exception:
                logger.exception("Release-Installation fehlgeschlagen")
                try:
                    with (self.directory / "update.log").open("a", encoding="utf-8") as log:
                        traceback.print_exc(file=log)
                except OSError:
                    logger.error("Update-Protokoll konnte nicht geschrieben werden")
                if state.get("phase") in {"applying", "validating"}:
                    self._restore(state)
                    self._clear_bytecode()
                self._result(state, False, t("Update fehlgeschlagen; bisherige Version wurde beibehalten. Details: .updates/update.log."))
            return True

    def recover_interrupted(self) -> bool:
        """Called once by app.run before importing the possibly replaced app."""
        state = self._state()
        if state.get("phase") in {"applying", "validating"}:
            with self._locked():
                logger.warning("Interrupted update detected; restoring the previous version")
                self._restore(state)
                self._clear_bytecode()
                self._result(state, False, t("Unterbrochenes Update: bisherige Version wurde wiederhergestellt."))
            return True
        return False


update_manager = UpdateManager()


if __name__ == "__main__":
    # The start scripts call this before pip/bootstrap, using only the stdlib.
    # Subsequent commands run in fresh interpreters after any recovery.
    update_manager.recover_interrupted()
    print(update_manager.selected_python())
