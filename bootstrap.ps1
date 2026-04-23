# bootstrap.ps1
param([switch]$InstallDeps)

Write-Host ">>> Inizializzazione AETERNA v0.0.1 (Windows Edition)..." -ForegroundColor Cyan

if ($InstallDeps) {
    Write-Host "[*] Installazione dipendenze Python..." -ForegroundColor Yellow
    pip install -r core/requirements.txt
    
    Write-Host "[*] Installazione dipendenze Julia..." -ForegroundColor Yellow
    julia --project=scientific -e 'using Pkg; Pkg.instantiate()'
}

Write-Host "[+] Avvio Motore Scientifico (Julia) in background..." -ForegroundColor Magenta
# Lancia Julia come processo separato tenendo traccia del suo ID
$juliaProcess = Start-Process -FilePath "julia" -ArgumentList "--project=scientific", "scientific/zmq_server.jl" -PassThru -NoNewWindow

# Attesa per il bind del socket ZeroMQ
Start-Sleep -Seconds 5

Write-Host "[+] Avvio Sentinel (Python)..." -ForegroundColor Green
try {
    # Avvia il Core
    python -m core.sentinel --config aeterna.toml
} finally {
    # Al termine (es. premendo Ctrl+C), abbattiamo il motore Julia in modo pulito
    Write-Host "`n[!] Chiusura del sistema. Terminazione Motore Julia (PID: $($juliaProcess.Id))..." -ForegroundColor Red
    Stop-Process -Id $juliaProcess.Id -Force
    Write-Host "[OK] Sistema arrestato." -ForegroundColor Green
}