# AETERNA v0.3.0 "Oculus" -- Telegram operator bot launcher (Windows PowerShell).
#
# Sibling of operations/war_room/launch.ps1; same Python resolution order
# (local .venv -> py.exe launcher -> python.exe on PATH, skipping the
# Microsoft Store execution alias).
#
# Usage (Windows PowerShell 5.1 -- default on Windows 10/11):
#   powershell -ExecutionPolicy Bypass -File operations\telegram_bot\launch.ps1
#
# Usage (PowerShell 7+ -- if pwsh is on PATH):
#   pwsh operations/telegram_bot/launch.ps1
#
# Provisioning (one-time): see operations\telegram_bot\README.md.
#
# On first run, install deps with (Windows-native venv only):
#   python -m venv operations\telegram_bot\.venv
#   operations\telegram_bot\.venv\Scripts\pip install -r `
#       operations\telegram_bot\requirements.txt

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot  = Resolve-Path (Join-Path $ScriptDir "..\..")

Push-Location $RepoRoot
try {
    $VenvPython = Join-Path $ScriptDir ".venv\Scripts\python.exe"
    $PythonExe  = $null
    $PyLauncherArgs = $null

    if (Test-Path $VenvPython) {
        $PythonExe = $VenvPython
    }
    elseif (Get-Command py -ErrorAction SilentlyContinue) {
        $PythonExe = "py"
        $PyLauncherArgs = @("-3")
    }
    elseif ((Get-Command python -ErrorAction SilentlyContinue) -and `
            ((Get-Command python).Source -notlike "*WindowsApps*")) {
        $PythonExe = "python"
    }
    else {
        Write-Host ""
        Write-Host "ERROR: no usable Python interpreter found." -ForegroundColor Red
        Write-Host ""
        Write-Host "Bootstrap one with:" -ForegroundColor Yellow
        Write-Host "  1) winget install Python.Python.3.12" -ForegroundColor Yellow
        Write-Host "  2) python -m venv operations\telegram_bot\.venv" -ForegroundColor Yellow
        Write-Host "  3) operations\telegram_bot\.venv\Scripts\pip install -r operations\telegram_bot\requirements.txt" -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }

    Write-Host "AETERNA Telegram bot -- launching from $RepoRoot" -ForegroundColor Cyan

    $BotArgs = @("-m", "operations.telegram_bot.bot") + $args
    if ($PyLauncherArgs) {
        & $PythonExe @PyLauncherArgs @BotArgs
    }
    else {
        & $PythonExe @BotArgs
    }
}
finally {
    Pop-Location
}
