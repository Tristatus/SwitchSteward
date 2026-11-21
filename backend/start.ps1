# Start-Skript fuer Windows/PowerShell.
# Richtet beim ersten Aufruf venv + config.json automatisch ein und startet danach die App.
# Bei jedem weiteren Aufruf reicht ein Doppelklick bzw. ".\start.ps1".

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$VenvPython = Join-Path $PSScriptRoot "venv\Scripts\python.exe"
$VersionCheck = "import sys; sys.exit(0 if (3, 10) <= sys.version_info[:2] < (4, 0) else 1)"

if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    $PythonCommand = $null
    $PythonArguments = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 -c $VersionCheck
        if ($LASTEXITCODE -eq 0) {
            $PythonCommand = "py"
            $PythonArguments = @("-3")
        }
    }
    if (-not $PythonCommand -and (Get-Command python -ErrorAction SilentlyContinue)) {
        & python -c $VersionCheck
        if ($LASTEXITCODE -eq 0) {
            $PythonCommand = "python"
        }
    }
    if (-not $PythonCommand) {
        throw "Python 3.10 oder neuer (Python 3) wird benoetigt. Bitte Python installieren und erneut starten."
    }

    Write-Host "Erstelle virtuelle Umgebung ..."
    & $PythonCommand @PythonArguments -m venv venv
    if ($LASTEXITCODE -ne 0) {
        throw "Die virtuelle Umgebung konnte nicht erstellt werden (Exitcode $LASTEXITCODE)."
    }
}

& $VenvPython -c $VersionCheck
if ($LASTEXITCODE -ne 0) {
    throw "Die virtuelle Umgebung benoetigt Python 3.10 oder neuer (Python 3). Bitte backend/venv mit einer passenden Python-Version neu erstellen."
}

# Wiederherstellung vor pip/bootstrap; Web-Updates koennen eine eigene venv nutzen.
$SelectedPython = & $VenvPython -m app.updates
if ($LASTEXITCODE -ne 0) {
    throw "Ein unterbrochenes Update konnte nicht wiederhergestellt werden. Bitte .updates pruefen."
}
$VenvPython = ([string]$SelectedPython).Trim()

Write-Host "Installiere/aktualisiere Abhaengigkeiten ..."
& $VenvPython -m pip install -q -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    throw "Die Abhaengigkeiten konnten nicht installiert werden (Exitcode $LASTEXITCODE)."
}

& $VenvPython -m app.bootstrap_config
if ($LASTEXITCODE -ne 0) {
    throw "Die Erstkonfiguration ist fehlgeschlagen (Exitcode $LASTEXITCODE)."
}

Write-Host ""
# Ab hier: normale Logausgaben von uvicorn (auf stderr) sollen NICHT als
# PowerShell-Fehler gewertet werden, deshalb ErrorActionPreference lockern.
$ErrorActionPreference = "Continue"

Write-Host "Servereinstellungen werden aus der Konfigurationsdatei geladen."
Write-Host "Zum Beenden: Strg+C"
Write-Host ""
& $VenvPython -m app.run
exit $LASTEXITCODE
