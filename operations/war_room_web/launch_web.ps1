# AETERNA v0.3.0 "Oculus" — Web HUD Dashboard Launcher (Windows PowerShell).
# 
# Usage:
#   powershell -ExecutionPolicy Bypass -File operations\war_room_web\launch_web.ps1
#

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Resolve Python from the existing war_room virtual environment (which contains numpy, grpcio, and protobuf)
$VenvPython = Join-Path $ScriptDir "..\war_room\.venv\Scripts\python.exe"
$PythonExe = $null

if (Test-Path $VenvPython) {
    $PythonExe = $VenvPython
}
elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $PythonExe = "py"
    $PyArgs = @("-3")
}
elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $PythonExe = "python"
}
else {
    Write-Host "ERROR: No usable Python interpreter found. Please make sure Python is installed and operations\war_room\.venv is configured." -ForegroundColor Red
    exit 1
}

# Start backend Python API server on port 8000
Write-Host ""
Write-Host ">>> Starting AETERNA Backend API Server on http://127.0.0.1:8000..." -ForegroundColor Cyan
if ($PyArgs) {
    $BackendProc = Start-Process -FilePath $PythonExe -ArgumentList @("-3", "server.py") -NoNewWindow -PassThru -WorkingDirectory $ScriptDir
}
else {
    $BackendProc = Start-Process -FilePath $PythonExe -ArgumentList "server.py" -NoNewWindow -PassThru -WorkingDirectory $ScriptDir
}

# Give the backend server a second to start
Start-Sleep -Seconds 1

# Start frontend dev server
Write-Host ">>> Starting Vite/React Frontend Server..." -ForegroundColor Cyan
Push-Location (Join-Path $ScriptDir "frontend")
try {
    # This runs npm run dev in the foreground, allowing stdout log stream and standard Ctrl+C termination
    npm run dev
}
finally {
    # Cleanup background Python process on exit
    Write-Host ""
    Write-Host ">>> Stopping API Backend (PID $($BackendProc.Id))..." -ForegroundColor Yellow
    try {
        Stop-Process -Id $BackendProc.Id -Force -ErrorAction SilentlyContinue
    }
    catch {}
    Pop-Location
    Write-Host ">>> AETERNA Web Dashboard stopped." -ForegroundColor Green
}
