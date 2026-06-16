# Production Deployment Script for AETERNA AppChain (CometBFT & Cosmovisor)
# Orchestrates a 2-node local consensus cluster.

# Stop any running aeternad or cosmovisor instances
Write-Host "Stopping any running aeternad and cosmovisor instances..." -ForegroundColor Cyan
Get-Process -Name "aeternad" -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name "cosmovisor" -ErrorAction SilentlyContinue | Stop-Process -Force

# Setup home folders
$UserDir = [System.Environment]::GetFolderPath('UserProfile')
$Home1 = Join-Path $UserDir ".aeternad_prometheus-1"
$Home2 = Join-Path $UserDir ".aeternad_prometheus-2"

# Clean old state
Write-Host "Cleaning up old state in home directories..." -ForegroundColor Cyan
if (Test-Path $Home1) { Remove-Item -Recurse -Force $Home1 }
if (Test-Path $Home2) { Remove-Item -Recurse -Force $Home2 }

# 1. Compile aeternad.exe
Write-Host "Compiling aeternad.exe..." -ForegroundColor Cyan
Push-Location $PSScriptRoot\..
& go build -o aeternad.exe ./cmd/aeternad/
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error compiling aeternad.exe" -ForegroundColor Red
    Pop-Location
    Exit 1
}
Pop-Location

# 2. Check and locate cosmovisor.exe
$CosmovisorPath = Join-Path $PSScriptRoot "..\cosmovisor.exe"
if (!(Test-Path $CosmovisorPath)) {
    $GoBinCosmovisor = Join-Path $UserDir "go\bin\cosmovisor.exe"
    if (Test-Path $GoBinCosmovisor) {
        Write-Host "Found cosmovisor.exe in Go bin directory. Copying..." -ForegroundColor Cyan
        Copy-Item $GoBinCosmovisor $CosmovisorPath -Force
    } else {
        Write-Host "cosmovisor.exe not found. Installing..." -ForegroundColor Cyan
        Push-Location $PSScriptRoot\..
        & go install cosmossdk.io/tools/cosmovisor/cmd/cosmovisor@v1.5.0
        Pop-Location
        
        # Check if python is available to copy it (since PowerShell path expansion might virtualize go/bin)
        Write-Host "Copying installed cosmovisor.exe using python..." -ForegroundColor Cyan
        python -c "import shutil; shutil.copy(r'$GoBinCosmovisor', r'$CosmovisorPath')"
        if (!(Test-Path $CosmovisorPath)) {
            Write-Host "Failed to locate/install cosmovisor.exe" -ForegroundColor Red
            Exit 1
        }
    }
}

# 3. Setup Cosmovisor directories for Node 1 and Node 2
Write-Host "Setting up Cosmovisor directories..." -ForegroundColor Cyan
$DaemonBin1 = Join-Path $Home1 "cosmovisor\genesis\bin"
$DaemonBin2 = Join-Path $Home2 "cosmovisor\genesis\bin"

New-Item -ItemType Directory -Force -Path $DaemonBin1 | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Home1 "cosmovisor\upgrades") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Home1 "backup") | Out-Null

New-Item -ItemType Directory -Force -Path $DaemonBin2 | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Home2 "cosmovisor\upgrades") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Home2 "backup") | Out-Null

# Copy binary to Cosmovisor folders
Copy-Item (Join-Path $PSScriptRoot "..\aeternad.exe") (Join-Path $DaemonBin1 "aeternad.exe") -Force
Copy-Item (Join-Path $PSScriptRoot "..\aeternad.exe") (Join-Path $DaemonBin2 "aeternad.exe") -Force

# Create directory junctions for cosmovisor\current pointing to cosmovisor\genesis
Write-Host "Creating directory junctions for current..." -ForegroundColor Cyan
if (Test-Path (Join-Path $Home1 "cosmovisor\current")) { [System.IO.Directory]::Delete((Join-Path $Home1 "cosmovisor\current"), $false) }
if (Test-Path (Join-Path $Home2 "cosmovisor\current")) { [System.IO.Directory]::Delete((Join-Path $Home2 "cosmovisor\current"), $false) }
cmd.exe /c "mklink /j `"$Home1\cosmovisor\current`" `"$Home1\cosmovisor\genesis`""
cmd.exe /c "mklink /j `"$Home2\cosmovisor\current`" `"$Home2\cosmovisor\genesis`""

# 4. Initialize nodes to generate config and validator keys
Write-Host "Initializing Node 1 (prometheus-1)..." -ForegroundColor Cyan
& (Join-Path $DaemonBin1 "aeternad.exe") init --moniker prometheus-1 --home $Home1

Write-Host "Initializing Node 2 (prometheus-2)..." -ForegroundColor Cyan
& (Join-Path $DaemonBin2 "aeternad.exe") init --moniker prometheus-2 --home $Home2

# 5. Generate unified genesis.json
Write-Host "Merging validator keys and generating unified genesis.json..." -ForegroundColor Cyan
$GenesisTemplate = Join-Path $PSScriptRoot "genesis.json"
& python (Join-Path $PSScriptRoot "generate_genesis.py") $Home1 $Home2 $GenesisTemplate
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error generating genesis.json" -ForegroundColor Red
    Exit 1
}

# 6. Read Node IDs using show-node-id command
Write-Host "Reading Node IDs..." -ForegroundColor Cyan
$NodeId1 = & (Join-Path $DaemonBin1 "aeternad.exe") show-node-id --home $Home1
$NodeId2 = & (Join-Path $DaemonBin2 "aeternad.exe") show-node-id --home $Home2

Write-Host "  - Node 1 ID: $NodeId1" -ForegroundColor Gray
Write-Host "  - Node 2 ID: $NodeId2" -ForegroundColor Gray

# 7. Start both nodes under Cosmovisor in the background
Write-Host "Starting Node 1 under Cosmovisor in background..." -ForegroundColor Cyan
$env:DAEMON_NAME = "aeternad.exe"
$env:DAEMON_HOME = $Home1
$env:DAEMON_ALLOW_START_KEY_MIGRATION = "true"
$env:DAEMON_DATA_BACKUP_DIR = "$Home1\backup"

Start-Process -FilePath $CosmovisorPath -ArgumentList "run", "start", "--rpc-addr", "127.0.0.1:26657", "--rest-addr", "127.0.0.1:1317", "--p2p-addr", "tcp://0.0.0.0:26656", "--peers", "${NodeId2}@127.0.0.1:26659", "--moniker", "prometheus-1", "--home", "$Home1" -RedirectStandardOutput "$Home1\cosmovisor_out.log" -RedirectStandardError "$Home1\cosmovisor.log" -NoNewWindow

Write-Host "Starting Node 2 under Cosmovisor in background..." -ForegroundColor Cyan
$env:DAEMON_NAME = "aeternad.exe"
$env:DAEMON_HOME = $Home2
$env:DAEMON_ALLOW_START_KEY_MIGRATION = "true"
$env:DAEMON_DATA_BACKUP_DIR = "$Home2\backup"

Start-Process -FilePath $CosmovisorPath -ArgumentList "run", "start", "--rpc-addr", "127.0.0.1:26658", "--rest-addr", "127.0.0.1:1318", "--p2p-addr", "tcp://0.0.0.0:26659", "--peers", "${NodeId1}@127.0.0.1:26656", "--moniker", "prometheus-2", "--home", "$Home2" -RedirectStandardOutput "$Home2\cosmovisor_out.log" -RedirectStandardError "$Home2\cosmovisor.log" -NoNewWindow

Write-Host ""
Write-Host "AETERNA production nodes successfully launched under Cosmovisor!" -ForegroundColor Green
Write-Host "  - Node 1: REST http://127.0.0.1:1317 | RPC http://127.0.0.1:26657 | Logs: $Home1\cosmovisor.log"
Write-Host "  - Node 2: REST http://127.0.0.1:1318 | RPC http://127.0.0.1:26658 | Logs: $Home2\cosmovisor.log"
Write-Host ""

Write-Host "Keeping script alive and tailing Node 1 logs..." -ForegroundColor Cyan
Start-Sleep -Seconds 2
Get-Content (Join-Path $Home1 "cosmovisor.log") -Wait -Tail 100
