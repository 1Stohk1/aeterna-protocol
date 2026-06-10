# Stop any running aeternad instances
Get-Process -Name "aeternad" -ErrorAction SilentlyContinue | Stop-Process -Force

# Setup home folders
$UserDir = [System.Environment]::GetFolderPath('UserProfile')
$Home1 = Join-Path $UserDir ".aeternad_prometheus-1"
$Home2 = Join-Path $UserDir ".aeternad_prometheus-2"

# Clean old state if requested or automatically
if (Test-Path $Home1) { Remove-Item -Recurse -Force $Home1 }
if (Test-Path $Home2) { Remove-Item -Recurse -Force $Home2 }

# Check binary
$BinaryPath = Join-Path $PSScriptRoot "..\aeternad.exe"
if (!(Test-Path $BinaryPath)) {
    Write-Host "aeternad.exe not found in chain directory. Building..."
    Push-Location $PSScriptRoot\..
    & "C:\Program Files\Go\bin\go.exe" build -o aeternad.exe ./cmd/aeternad/
    Pop-Location
}

# Initialize nodes
Write-Host "Initializing Node 1 (prometheus-1)..."
& $BinaryPath init --moniker prometheus-1 --home $Home1

Write-Host "Initializing Node 2 (prometheus-2)..."
& $BinaryPath init --moniker prometheus-2 --home $Home2

# Inject custom genesis containing pre-minted SBTs
Write-Host "Injecting pre-minted SBT genesis configuration..."
Copy-Item (Join-Path $PSScriptRoot "genesis.json") (Join-Path $Home1 "config\genesis.json") -Force
Copy-Item (Join-Path $PSScriptRoot "genesis.json") (Join-Path $Home2 "config\genesis.json") -Force

# Start nodes in background with redirected output logs and --home flag
Write-Host "Starting Node 1 on RPC :26657, REST :1317..."
Start-Process -FilePath $BinaryPath -ArgumentList "start --rpc-addr 127.0.0.1:26657 --rest-addr 127.0.0.1:1317 --moniker prometheus-1 --home $Home1" -WindowStyle Hidden -RedirectStandardOutput (Join-Path $Home1 "aeternad.log") -RedirectStandardError (Join-Path $Home1 "aeternad_err.log")

Write-Host "Starting Node 2 on RPC :26658, REST :1318..."
Start-Process -FilePath $BinaryPath -ArgumentList "start --rpc-addr 127.0.0.1:26658 --rest-addr 127.0.0.1:1318 --moniker prometheus-2 --home $Home2" -WindowStyle Hidden -RedirectStandardOutput (Join-Path $Home2 "aeternad.log") -RedirectStandardError (Join-Path $Home2 "aeternad_err.log")

Write-Host "Local 2-node devnet launched successfully:"
Write-Host "  - Node 1 (prometheus-1): http://127.0.0.1:1317 (REST) / http://127.0.0.1:26657 (RPC) with home $Home1"
Write-Host "  - Node 2 (prometheus-2): http://127.0.0.1:1318 (REST) / http://127.0.0.1:26658 (RPC) with home $Home2"
