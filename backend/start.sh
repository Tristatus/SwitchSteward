#!/usr/bin/env bash
# Start-Skript fuer Linux/Mac. Richtet beim ersten Aufruf venv + config.json automatisch
# ein und startet danach die App. Bei jedem weiteren Aufruf reicht "./start.sh".
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
venv_python="./venv/bin/python"
version_check='import sys; sys.exit(0 if (3, 10) <= sys.version_info[:2] < (4, 0) else 1)'

if [ ! -x "$venv_python" ]; then
    if ! command -v python3 >/dev/null 2>&1 || ! python3 -c "$version_check"; then
        echo "Python 3.10 oder neuer (Python 3) wird benoetigt. Bitte Python installieren und erneut starten." >&2
        exit 1
    fi
    echo "Erstelle virtuelle Umgebung ..."
    python3 -m venv venv
fi

if ! "$venv_python" -c "$version_check"; then
    echo "Die virtuelle Umgebung benoetigt Python 3.10 oder neuer (Python 3). Bitte backend/venv mit einer passenden Python-Version neu erstellen." >&2
    exit 1
fi

# Stellt ein unterbrochenes Update wieder her, bevor pip oder Anwendungscode
# geladen wird. Nach einem Web-Update kann eine eigene venv aktiv sein.
venv_python="$("$venv_python" -m app.updates)"

echo "Installiere/aktualisiere Abhaengigkeiten ..."
"$venv_python" -m pip install -q -r requirements.txt

"$venv_python" -m app.bootstrap_config

echo ""
echo "Zum Beenden: Strg+C"
echo ""
echo "Servereinstellungen werden aus der Konfigurationsdatei geladen."
exec "$venv_python" -m app.run
