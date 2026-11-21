"""Single source of truth for the files a SwitchSteward release contains.

Pure data module: it must not import anything from ``app`` because the release
build script loads it directly from its file path.
"""

import re

DOC_FILES = ("VERSION", "README.md", "CHANGELOG.md", "SECURITY.md", "LICENSE")
BACKEND_FILES = (
    "backend/config.example.json",
    "backend/requirements.txt",
    "backend/start.ps1",
    "backend/start.sh",
)
REQUIRED_FRONTEND_FILES = tuple(
    f"frontend/{name}"
    for name in (
        "index.html", "app.css", "theme.js", "i18n.js", "i18n.en.js", "core.js", "switches.js",
        "wlan.css", "wlan.js", "admin.js", "main.js", "setup.html", "setup.css", "setup.js",
    )
)
REQUIRED_MODULES = (
    "backend/app/__init__.py",
    "backend/app/application.py",
    "backend/app/bootstrap_config.py",
    "backend/app/config.py",
    "backend/app/main.py",
    "backend/app/run.py",
    "backend/app/runtime_files.py",
    "backend/app/setup.py",
    "backend/app/updates.py",
    "backend/app/version.py",
)
FRONTEND_PATTERN = re.compile(r"^frontend/[a-z0-9][a-z0-9.-]*\.(html|css|js)$")
DOC_PATTERN = re.compile(r"^docs/[a-z0-9][a-z0-9.-]*\.md$")
