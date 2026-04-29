# AETERNA v0.3.0 "Oculus" — War Room launcher (Windows PowerShell).
#
# Guard-rails (per SPRINT-v0.3.0 §6 Risk #1 — "operator accidentally
# exposes the dashboard beyond loopback"):
#
#   --server.address=127.0.0.1      Bind loopback only. Override with
#                                   -PublicBind to bind 0.0.0.0 AFTER
#                                   a 3-second warning.
#   --server.fileWatcherType=none   Disable hot-reload. A file change
#                                   in the middle of an incident shift
#                                   must not restart the dashboard.
#   --server.runOnSave=false        Same, for the other half of the
#                                   Streamlit watcher.
#   --server.headless=true          Don't auto-open a browser; the
#                                   operator picks when to click the URL.
#   --browser.gatherUsageStats=false Anthropic-OPS contract — the War
#                                   Room must not phone home.
#
# Usage (Windows PowerShell 5.1 — default on Windows 10/11):
#   powershell -ExecutionPolicy Bypass -File operations\war_room\launch.ps1
#   powershell -ExecutionPolicy Bypass -File operations\war_room\launch.ps1 -Port 8502
#   powershell -ExecutionPolicy Bypass -File operations\war_room\launch.ps1 -PublicBind  # ⚠️ LAN-visible
#
# Usage (PowerShell 7+ — if `pwsh` is on PATH):
#   pwsh operations/war_room/launch.ps1
#
# The `-ExecutionPolicy Bypass` flag avoids Windows' default "running
# scripts is disabled on this system" block for this one invocation
# without modifying machine-wide policy.
#
# On first run, install deps with:
#   pip install -r operations/war_room/requirements.txt

[CmdletBinding()]
param(
    [int]$Port = 8501,
    [switch]$PublicBind,
    [string]$AdminTarget = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Bind choice — loopback unless the operator explicitly asked for LAN.
$BindAddress = "127.0.0.1"
if ($PublicBind) {
    # ASCII-only on purpose. Windows PowerShell 5.1 (the default shell on
    # Windows 10/11) parses .ps1 files as the system codepage unless a
    # UTF-8 BOM is present, and mangles Unicode box-drawing characters
    # into syntax errors. ASCII keeps the launcher portable.
    Write-Host "+------------------------------------------------------------+" -ForegroundColor Red
    Write-Host "|  WARNING -- BINDING WAR ROOM ON 0.0.0.0                    |" -ForegroundColor Red
    Write-Host "|  The dashboard will be visible to every host on this LAN.  |" -ForegroundColor Red
    Write-Host "|  The Admin surface is READ-ONLY, but the operator view is  |" -ForegroundColor Red
    Write-Host "|  sensitive. Put a reverse proxy with auth in front of it,  |" -ForegroundColor Red
    Write-Host "|  OR abort now (Ctrl+C) within 3 seconds.                   |" -ForegroundColor Red
    Write-Host "+------------------------------------------------------------+" -ForegroundColor Red
    Start-Sleep -Seconds 3
    $BindAddress = "0.0.0.0"
}

# Propagate operator-chosen Admin target into the Streamlit env so the
# sidebar defaults correctly.
if ($AdminTarget) {
    $env:SANTUARIO_ADMIN_TARGET = $AdminTarget
}

Write-Host "AETERNA War Room -- starting on http://${BindAddress}:${Port}" -ForegroundColor Cyan

# Run from the war_room dir so `streamlit run app.py` finds the app and
# the sibling `client.py` / `admin_pb2*.py` modules without an extra
# PYTHONPATH dance.
Push-Location $ScriptDir
try {
    # Prefer a Windows-native venv (`.venv\Scripts\python.exe`). A venv
    # created from inside WSL looks similar on disk but has a POSIX
    # layout (`.venv/bin/python` → python3 symlink) that Windows cannot
    # exec. On mixed-host setups we must NOT follow the POSIX layout,
    # or Windows shows the "open with..." app picker because it treats
    # the symlink target as an unknown file type.
    #
    # Resolution order on Windows:
    #   1. .venv\Scripts\python.exe         (Windows venv)
    #   2. py.exe                           (Python Launcher for Windows)
    #   3. python.exe on PATH               (last-resort — often the
    #                                        Store alias, may pop the app
    #                                        picker; we check before use)
    #
    # If none of those resolve to an actual executable, abort with a
    # useful error instead of letting Streamlit's child process flap.
    $VenvPython = Join-Path $ScriptDir ".venv\Scripts\python.exe"
    $PythonExe = $null

    if (Test-Path $VenvPython) {
        $PythonExe = $VenvPython
    }
    elseif (Get-Command py -ErrorAction SilentlyContinue) {
        # `py -3` dispatches to the newest Python 3.x installed via the
        # official Windows installer. Use -3 explicitly to avoid accidentally
        # booting a Python 2.x that's still hanging around on old boxes.
        $PythonExe = "py"
        $PyLauncherArgs = @("-3")
    }
    elseif ((Get-Command python -ErrorAction SilentlyContinue) -and `
            ((Get-Command python).Source -notlike "*WindowsApps*")) {
        # Plain `python` on PATH — but ONLY if it's not the Microsoft
        # Store execution alias under %LOCALAPPDATA%\Microsoft\WindowsApps\,
        # which is the stub that triggers the "open with..." dialog.
        $PythonExe = "python"
    }
    else {
        Write-Host ""
        Write-Host "ERROR: no usable Python interpreter found." -ForegroundColor Red
        Write-Host ""
        Write-Host "The War Room needs a Windows-native Python to drive the Streamlit" -ForegroundColor Yellow
        Write-Host "server. Bootstrap one with:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  1) Install Python 3.12 from https://www.python.org/downloads/windows/" -ForegroundColor Yellow
        Write-Host "     (tick 'Add python.exe to PATH' during install)" -ForegroundColor Yellow
        Write-Host "  2) python -m venv operations\war_room\.venv" -ForegroundColor Yellow
        Write-Host "  3) operations\war_room\.venv\Scripts\pip install -r operations\war_room\requirements.txt" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "A venv created from inside WSL has a POSIX layout that Windows" -ForegroundColor Yellow
        Write-Host "cannot execute. Keep the two worlds separate: run the WSL venv" -ForegroundColor Yellow
        Write-Host "with launch.sh, and the Windows venv with launch.ps1." -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }

    # Build the final argv. `py -3` takes the module spec as positional
    # arguments after the launcher switch; everything else forwards
    # `-m streamlit run app.py ...` directly.
    $StreamlitArgs = @(
        "-m", "streamlit", "run", "app.py",
        "--server.address=$BindAddress",
        "--server.port=$Port",
        "--server.fileWatcherType=none",
        "--server.runOnSave=false",
        "--server.headless=true",
        "--browser.gatherUsageStats=false"
    )
    if ($PyLauncherArgs) {
        & $PythonExe @PyLauncherArgs @StreamlitArgs
    }
    else {
        & $PythonExe @StreamlitArgs
    }

}
finally {
    Pop-Location
}
