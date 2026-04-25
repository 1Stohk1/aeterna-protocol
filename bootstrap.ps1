# =============================================================================
# AETERNA -- bootstrap.ps1 (Windows orchestrator, v2 "Tripod")
# =============================================================================
#
# Starts the three-headed Prometheus stack in the right order and tears it
# down in reverse. Each head has an independent failure mode, and the v1
# launcher (just Start-Process + Start-Sleep) was too fragile to absorb them:
#
#   1. santuario-signer  (Rust, gRPC :SantuarioPort)     -- source of truth
#   2. scientific engine (Julia, ZMQ REP :ZmqPort)       -- compute back end
#   3. sentinel          (Python, in foreground)         -- policy brain
#
# The three must come up in that order because:
#   * Sentinel.__init__ does a blocking gRPC handshake against the signer and
#     raises SantuarioUnavailable if nobody answers on :SantuarioPort.
#   * Sentinel opens a ZMQ REQ channel to the Julia engine right after, so
#     Julia must be bound on :ZmqPort before the Sentinel finishes init.
#
# Teardown must be reverse-order (LIFO):
#   * Sentinel exits first (Ctrl-C from foreground).
#   * Julia is killed next.
#   * Signer is killed last -- if we kill it first the Sentinel sees a gRPC
#     failure storm on its way out and the audit log gets noisy for nothing.
#
# Zombie-process guard: every Start-Process handle we spawn is tracked in a
# list, and the finally-block iterates that list in reverse. This is what
# prevents the "WSAEADDRINUSE / 10048" errors that haunted the v1 launcher.
#
# PATH-poisoning guard: we never trust bare `python` or `pip` from PATH.
#   * Python resolution order (same as war_room/launch.ps1 and
#     telegram_bot/launch.ps1): local .venv -> py.exe -3 -> first non-
#     WindowsApps python.exe on PATH.
#   * Pip is always `python -m pip`, never the `pip.exe` wrapper -- because
#     that wrapper stores a hard-coded python path at install time and
#     breaks when the distro is moved (ComfyUI portable is a common
#     culprit on this host).
#
# Parameters -- operator ergonomics for multi-instance dev
# -------------------------------------------------------------------------
#   -Config            aeterna.toml path passed to Sentinel (-config).
#   -SantuarioPort     TCP port for the signer's gRPC Admin surface.
#                      Also exported as $env:SANTUARIO_PORT so the
#                      Sentinel's SantuarioClient finds the same target.
#   -ZmqPort           TCP port for the Julia ZMQ REP socket. Exported as
#                      $env:AETERNA_ZMQ_ENDPOINT = tcp://*:$ZmqPort so
#                      zmq_server.jl picks it up without editing code.
#                      NOTE: the Sentinel reads the client-side endpoint
#                      from aeterna.toml ([sentinel.zmq.endpoint]), so if
#                      you override ZmqPort you should also point -Config
#                      at a toml with a matching client endpoint. The
#                      script does NOT rewrite the toml behind your back.
#   -InstallDeps       Run pip install + Julia precompile pipeline before
#                      launch. Idempotent when the env is already
#                      consistent, so safe to always pass on first boot
#                      after a pull.
#   -RegenJuliaManifest  Delete scientific\Manifest.toml and let Pkg
#                      re-resolve from scratch against the *current*
#                      Julia version. Use when you see "Unsatisfiable
#                      requirements" -- typically Statistics pinned to
#                      1.10.0 (Julia 1.10 stdlib) but you're now on 1.11+.
#                      Implies -InstallDeps for the Julia leg.
#   -SkipSigner        Don't launch santuario-signer -- useful when you're
#                      running the signer under `cargo run` in another
#                      pane for faster rebuild cycles. You still get
#                      sentinel + julia from here.
#   -SkipJulia         Don't launch the scientific engine -- for pure
#                      signer<->sentinel smoke tests.
#   -SkipSentinel      Don't launch Sentinel -- for bringing up just the
#                      two back-end daemons (e.g. while iterating on the
#                      War Room streamlit or the Telegram bot).
#   -SignerProfile     release (default) | debug -- selects both the cargo
#                      build profile AND the target subdir we spawn from
#                      (target\release vs target\debug). Debug rebuilds are
#                      ~15x faster but the runtime is noticeably slower;
#                      fine for dev.
#   -SignerReadyTimeoutSec  How long to wait for the signer's TCP socket
#                      to accept connections AFTER spawn. The cold cargo
#                      build happens synchronously before this timer starts,
#                      so the budget here only covers the binary's startup
#                      (Dilithium key gen, gRPC bind). Default 120s is
#                      generous; a warm signer is usually ready in <1s.
#   -ZmqReadyTimeoutSec How long to wait for Julia. Default 90s; Julia
#                      precompile on first boot after an update is slow.
#
# Examples
# -------------------------------------------------------------------------
#   .\bootstrap.ps1
#       Default Prometheus-1 on :50051 / :5555 with aeterna.toml.
#
#   .\bootstrap.ps1 -InstallDeps
#       First-boot-after-pull sweep: reinstalls Python deps, re-resolves
#       the Julia Manifest against the currently-installed Julia version,
#       then boots normally.
#
#   .\bootstrap.ps1 -RegenJuliaManifest -InstallDeps
#       Use after a Julia major-version bump (e.g. 1.10 -> 1.12). Wipes
#       the lockfile, regenerates from Project.toml, then proceeds.
#
#   .\bootstrap.ps1 -Config aeterna.prometheus-0.toml `
#                   -SantuarioPort 50052 -ZmqPort 5556
#       Run a second instance in parallel on different ports.
#
#   .\bootstrap.ps1 -SkipSigner
#       I already have `cargo run` running in another shell; just bring
#       up Julia and Sentinel.
# =============================================================================

[CmdletBinding()]
param(
    [string]   $Config              = "aeterna.toml",
    [int]      $SantuarioPort       = 50051,
    [int]      $ZmqPort             = 5555,
    [switch]   $InstallDeps,
    [switch]   $RegenJuliaManifest,
    [switch]   $SkipSigner,
    [switch]   $SkipJulia,
    [switch]   $SkipSentinel,
    [ValidateSet("release", "debug")]
    [string]   $SignerProfile       = "release",
    [int]      $SignerReadyTimeoutSec = 120,
    [int]      $ZmqReadyTimeoutSec    = 90
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Repo root -- anchor all relative paths to the script's own directory so the
# script works regardless of where it's invoked from (cd-in, double-click,
# task scheduler, etc.).
# ---------------------------------------------------------------------------
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot

$Banner = @"
>>> AETERNA bootstrap v2 "Tripod" (Windows Edition)
    repo                : $RepoRoot
    config              : $Config
    santuario port      : $SantuarioPort
    zmq port            : $ZmqPort
    signer profile      : $SignerProfile
    install deps        : $($InstallDeps.IsPresent)
    regen julia manifest: $($RegenJuliaManifest.IsPresent)
    skip signer/julia/sentinel : $($SkipSigner.IsPresent) / $($SkipJulia.IsPresent) / $($SkipSentinel.IsPresent)
"@
Write-Host $Banner -ForegroundColor Cyan


# ---------------------------------------------------------------------------
# Python resolution -- same order as war_room/launch.ps1 and
# telegram_bot/launch.ps1. See the comment-block at the top of the file
# for why bare `python` is unsafe on Windows 11.
#
# Returns a hashtable @{ Exe = "...exe"; PreArgs = @("-3", ...) } so the
# caller can splat both parts into the call operator uniformly, regardless
# of whether the resolver picked a direct .exe (PreArgs empty) or py.exe
# (PreArgs = "-3"). This avoids the trap of quoting "py.exe -3" as a
# single token -- PowerShell would then try to run a command literally
# named "py.exe -3" and fail.
# ---------------------------------------------------------------------------
function Resolve-Python {
    $venvPy = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    if (Test-Path $venvPy) {
        Write-Host "[py] using repo venv: $venvPy" -ForegroundColor DarkGray
        return @{ Exe = $venvPy; PreArgs = @() }
    }

    $pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        Write-Host "[py] using Python Launcher: $($pyLauncher.Source) -3" -ForegroundColor DarkGray
        return @{ Exe = $pyLauncher.Source; PreArgs = @("-3") }
    }

    # Last resort: any `python.exe` on PATH that isn't the Windows Store
    # stub under %LOCALAPPDATA%\Microsoft\WindowsApps\. That stub opens the
    # "Seleziona un'app" dialog and crashes the whole chain.
    $candidates = Get-Command python.exe -All -ErrorAction SilentlyContinue |
                  Where-Object { $_.Source -notmatch "WindowsApps" }
    if ($candidates) {
        $chosen = $candidates[0].Source
        Write-Host "[py] using PATH python: $chosen" -ForegroundColor DarkGray
        return @{ Exe = $chosen; PreArgs = @() }
    }

    throw @"
[FATAL] No usable Python found. Resolution order:
  1. $RepoRoot\.venv\Scripts\python.exe
  2. py.exe -3 (Python Launcher for Windows)
  3. a non-WindowsApps python.exe on PATH
Install one of:
  winget install Python.Python.3.12
  # or create the local venv: python -m venv .venv
"@
}

$Python    = Resolve-Python
$PyExe     = $Python.Exe
$PyPreArgs = $Python.PreArgs


# ---------------------------------------------------------------------------
# Optional manifest reset for the Julia env. Runs BEFORE the dep-install
# block so a fresh resolve sees an empty Manifest and rebuilds against
# the currently-installed Julia.
# ---------------------------------------------------------------------------
if ($RegenJuliaManifest) {
    $manifestPath = Join-Path $RepoRoot "scientific\Manifest.toml"
    if (Test-Path $manifestPath) {
        Write-Host "[*] -RegenJuliaManifest: removing $manifestPath" -ForegroundColor Yellow
        Remove-Item $manifestPath -Force
    } else {
        Write-Host "[i] -RegenJuliaManifest: no Manifest.toml present (already clean)" -ForegroundColor DarkGray
    }
    # Force the install path even if the operator forgot -InstallDeps --
    # without it the freshly-deleted manifest stays empty and the launch
    # fails immediately on the first `using ZMQ`.
    if (-not $InstallDeps) {
        Write-Host "[i] implying -InstallDeps for Julia re-resolution" -ForegroundColor DarkGray
        $InstallDeps = $true
    }
}


# ---------------------------------------------------------------------------
# Dep install (optional -- gated by -InstallDeps).
#
# Why `python -m pip` instead of `pip`: on this host the `pip.exe` wrapper
# first in PATH was a ComfyUI-portable leftover with a hard-coded interpreter
# path that no longer existed on disk ("Fatal error in launcher: Unable to
# create process using ..."). Invoking pip as a module of the resolved Python
# bypasses the launcher stub entirely.
#
# Julia: when the Manifest exists we do the full resolve->update->precompile
# triad (self-healing for compat drift). When the Manifest was just nuked
# by -RegenJuliaManifest, Pkg.instantiate() does the right thing -- it
# re-resolves from Project.toml and installs from scratch. Both paths end
# in precompile() so the first boot afterwards is fast.
# ---------------------------------------------------------------------------
if ($InstallDeps) {
    Write-Host "[*] Installing Python deps via python -m pip ..." -ForegroundColor Yellow
    & $PyExe @PyPreArgs -m pip install --upgrade pip
    & $PyExe @PyPreArgs -m pip install -r (Join-Path $RepoRoot "core\requirements.txt")
    if ($LASTEXITCODE -ne 0) {
        throw "pip install failed (exit $LASTEXITCODE) -- check PATH for a hijacked pip.exe or an incomplete Python install."
    }

    Write-Host "[*] Re-resolving Julia env (handles version drift) ..." -ForegroundColor Yellow
    julia --project=scientific -e 'using Pkg; Pkg.resolve(); Pkg.instantiate(); Pkg.precompile()'
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Julia precompile returned $LASTEXITCODE. Some optional packages may have failed (DifferentialEquations etc.) -- the server still starts if ZMQ/JSON3 compiled. Continuing."
    }
}


# ---------------------------------------------------------------------------
# Child-process bookkeeping -- populated as we spawn, drained LIFO in finally.
# Each entry is a hashtable so we get a nicer shutdown log than "PID 1234".
# ---------------------------------------------------------------------------
$Children = [System.Collections.Generic.List[object]]::new()

function Start-Child {
    param(
        [string]   $Label,
        [string]   $FilePath,

        # [AllowEmptyCollection()] is needed because the santuario-signer takes
        # no CLI args -- we configure it via $env:SANTUARIO_PORT. Without this
        # attribute, PS 5.1's strict param binder rejects @() at THIS call site
        # before we even get a chance to forward it to Start-Process. Default
        # value is also @() so omitting -ArgumentList works.
        [AllowEmptyCollection()]
        [string[]] $ArgumentList = @(),

        [hashtable]$ExtraEnv = @{}
    )

    # Merge env so the child inherits the current process env plus any
    # per-child overrides. We don't want ExtraEnv to leak into the parent.
    $savedEnv = @{}
    foreach ($k in $ExtraEnv.Keys) {
        $savedEnv[$k] = [System.Environment]::GetEnvironmentVariable($k, "Process")
        [System.Environment]::SetEnvironmentVariable($k, $ExtraEnv[$k], "Process")
    }
    try {
        # Splat conditionally: Start-Process -ArgumentList @() ALSO trips the
        # "null or empty" validator (separate codepath from Start-Child's own
        # binder), so the empty-args case must omit the parameter entirely.
        $startArgs = @{
            FilePath    = $FilePath
            PassThru    = $true
            NoNewWindow = $true
        }
        if ($ArgumentList -and $ArgumentList.Count -gt 0) {
            $startArgs.ArgumentList = $ArgumentList
        }
        $proc = Start-Process @startArgs
    } finally {
        # Restore parent env immediately -- child has already forked its view.
        foreach ($k in $savedEnv.Keys) {
            [System.Environment]::SetEnvironmentVariable($k, $savedEnv[$k], "Process")
        }
    }
    $Children.Add([pscustomobject]@{
        Label   = $Label
        Process = $proc
    }) | Out-Null
    Write-Host ("[+] spawned {0} (PID {1})" -f $Label, $proc.Id) -ForegroundColor Magenta
    return $proc
}

function Wait-TcpReady {
    param(
        [string] $Host_     = "127.0.0.1",
        [int]    $Port,
        [int]    $TimeoutSec,
        [string] $Label
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $warned = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $task = $c.ConnectAsync($Host_, $Port)
            if ($task.Wait(500)) {
                $c.Close()
                Write-Host ("[OK] {0} ready on {1}:{2}" -f $Label, $Host_, $Port) -ForegroundColor Green
                return $true
            }
            $c.Close()
        } catch {
            # Connection refused is expected while the daemon is still booting.
        }
        if (-not $warned) {
            Write-Host ("[..] waiting for {0} on {1}:{2} ..." -f $Label, $Host_, $Port) -ForegroundColor DarkGray
            $warned = $true
        }
        Start-Sleep -Milliseconds 400
    }
    # NOTE: ${Host_} / ${Port} need brace-delimiters here. Bare $Host_:$Port
    # makes PS 5.1 read "$Host_:" as a drive-provider prefix (like $env:NAME)
    # and bail with "Riferimento a variabile non valido".
    throw "[FATAL] $Label did not bind ${Host_}:${Port} within ${TimeoutSec}s"
}


# ---------------------------------------------------------------------------
# Env exports that the children depend on. These stay set on the parent too,
# because the Sentinel we'll launch at the end reads them directly.
# ---------------------------------------------------------------------------
$env:SANTUARIO_PORT        = "$SantuarioPort"
$env:AETERNA_ZMQ_ENDPOINT  = "tcp://*:$ZmqPort"


# ---------------------------------------------------------------------------
# MAIN -- try/finally guarantees teardown even on Ctrl-C or thrown exception.
# ---------------------------------------------------------------------------
try {
    # ------ 1. Santuario signer ------------------------------------------
    # Two-phase: cargo BUILD synchronously (blocks until artifact is on disk),
    # then spawn the produced .exe directly via Start-Child. This replaces the
    # old `cargo run` flow for two reasons:
    #
    #   * Signal handling. `cargo run` wraps the binary as a child process and
    #     re-emits its exit code. On Windows a Ctrl-C propagates as
    #     STATUS_CONTROL_C_EXIT (0xc000013a), and cargo dutifully reports
    #     "process didn't exit successfully" -- a cosmetic but jarring red
    #     line at the end of every clean shutdown.
    #   * Startup latency. After the first build, spawning the .exe directly
    #     skips all the cargo overhead (manifest re-parse, dependency graph
    #     walk, lockfile check) and the signer is online in <1s instead of
    #     ~2s.
    if (-not $SkipSigner) {
        Write-Host "[1/3] Building Santuario signer ($SignerProfile) ..." -ForegroundColor Cyan
        $buildArgs = @(
            "build",
            "--manifest-path", "santuario\Cargo.toml",
            "-p", "santuario-signer",
            "--bin", "santuario-signer",
            "--quiet"
        )
        if ($SignerProfile -eq "release") { $buildArgs += "--release" }
        & cargo @buildArgs
        if ($LASTEXITCODE -ne 0) {
            throw "[FATAL] cargo build failed (exit $LASTEXITCODE) -- inspect santuario\ source."
        }

        # Cargo's target dir layout: target\<profile>\<name>.exe. The "profile"
        # subfolder is literally "release" or "debug" -- matches our $SignerProfile.
        $signerExe = Join-Path $RepoRoot ("santuario\target\$SignerProfile\santuario-signer.exe")
        if (-not (Test-Path $signerExe)) {
            throw "[FATAL] Build succeeded but binary missing at $signerExe -- check Cargo.toml [[bin]] sections."
        }

        Write-Host "[1/3] Launching Santuario signer ($SignerProfile) ..." -ForegroundColor Cyan
        Start-Child -Label "santuario-signer" `
                    -FilePath $signerExe `
                    -ArgumentList @() `
                    -ExtraEnv @{ SANTUARIO_PORT = "$SantuarioPort" } | Out-Null
        Wait-TcpReady -Port $SantuarioPort -TimeoutSec $SignerReadyTimeoutSec `
                      -Label "santuario-signer"
    } else {
        Write-Host "[1/3] -SkipSigner: assuming signer already running on :$SantuarioPort" -ForegroundColor DarkYellow
    }

    # ------ 2. Julia scientific engine -----------------------------------
    if (-not $SkipJulia) {
        Write-Host "[2/3] Launching scientific engine (Julia, ZMQ) ..." -ForegroundColor Cyan
        Start-Child -Label "scientific-engine" `
                    -FilePath "julia" `
                    -ArgumentList @("--project=scientific", "scientific\zmq_server.jl") `
                    -ExtraEnv @{ AETERNA_ZMQ_ENDPOINT = "tcp://*:$ZmqPort" } | Out-Null
        Wait-TcpReady -Port $ZmqPort -TimeoutSec $ZmqReadyTimeoutSec `
                      -Label "scientific-engine"
    } else {
        Write-Host "[2/3] -SkipJulia: assuming engine already running on :$ZmqPort" -ForegroundColor DarkYellow
    }

    # ------ 3. Sentinel (foreground) -------------------------------------
    if (-not $SkipSentinel) {
        Write-Host "[3/3] Launching Sentinel (foreground -- Ctrl-C to stop) ..." -ForegroundColor Cyan
        # Sentinel runs in the CURRENT shell so Ctrl-C reaches it and the
        # finally-block gets to run cleanly. @PyPreArgs splats the "-3"
        # when Resolve-Python picked py.exe, and splats nothing otherwise.
        & $PyExe @PyPreArgs -m core.sentinel --config $Config
        $sentinelExit = $LASTEXITCODE
        Write-Host ("[i] Sentinel exited with code {0}" -f $sentinelExit) -ForegroundColor DarkGray
    } else {
        Write-Host "[3/3] -SkipSentinel: back-ends are up; exit with Ctrl-C to tear them down." -ForegroundColor DarkYellow
        # Keep the parent alive so Ctrl-C still triggers finally{}.
        while ($true) { Start-Sleep -Seconds 3600 }
    }
}
finally {
    # ---------- Teardown -- LIFO ----------------------------------------
    # We reverse the spawn list and stop each child in turn. Stop-Process
    # is a best-effort signal; if the process is already gone (Sentinel
    # self-exited, operator killed it from Task Manager) we swallow the
    # exception and keep going -- the whole point of this block is to
    # leave no orphans behind.
    Write-Host "`n[!] Teardown -- stopping children LIFO" -ForegroundColor Red
    for ($i = $Children.Count - 1; $i -ge 0; $i--) {
        $c = $Children[$i]
        try {
            if (-not $c.Process.HasExited) {
                Write-Host ("    - stopping {0} (PID {1})" -f $c.Label, $c.Process.Id) -ForegroundColor DarkRed
                Stop-Process -Id $c.Process.Id -Force -ErrorAction Stop
                # Give the OS a beat to release the TCP port before the
                # operator re-launches -- prevents AddrInUse on rapid
                # iteration.
                Start-Sleep -Milliseconds 300
            } else {
                Write-Host ("    - {0} already exited" -f $c.Label) -ForegroundColor DarkGray
            }
        } catch {
            Write-Warning ("Failed to stop {0}: {1}" -f $c.Label, $_.Exception.Message)
        }
    }
    Write-Host "[OK] Teardown complete." -ForegroundColor Green
}
