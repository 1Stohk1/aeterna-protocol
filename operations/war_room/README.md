# AETERNA War Room — v0.3.0 "Oculus"

A single-file Streamlit dashboard for the solo operator running a
Guardian node. Reads the Admin gRPC surface exposed by
`santuario-signer` and renders four panels: status banner, metrics,
peers, audit tail.

**Read-only by contract.** The Admin service never signs, never
unseals the vault, never mutates signer state. The dashboard cannot
break the signer; the worst it can do is show stale data.

## Install

The War Room lives in its own virtualenv so that Debian/Ubuntu 23.04+
(and WSL, which ships those) don't hit PEP 668 "externally managed
environment" errors on a system-wide `pip install`. The launch scripts
auto-activate the venv if it exists.

> **Windows + WSL caveat.** A venv has a platform-specific layout:
> POSIX lays it out under `.venv/bin/`, Windows under `.venv\Scripts\`.
> The same `.venv/` directory CANNOT serve both hosts — a WSL-built
> venv will make `launch.ps1` fall back to the system `python`, which
> on Windows often triggers the Microsoft Store "open with..." dialog.
> Pick the venv that matches where you launch from, and rebuild if you
> switch.

From the repo root, **Linux / macOS / WSL**:

```bash
python3 -m venv operations/war_room/.venv
operations/war_room/.venv/bin/pip install -r operations/war_room/requirements.txt
```

**Windows (PowerShell)**: first make sure Python 3.10+ is installed
natively on the Windows host (not only inside WSL). The fastest path
is `winget install Python.Python.3.12` or the installer from
<https://www.python.org/downloads/windows/> — tick "Add python.exe to
PATH" during install. Then, from the repo root:

```powershell
# If you previously created a WSL venv at the same path, remove it:
Remove-Item -Recurse -Force operations\war_room\.venv -ErrorAction SilentlyContinue

python -m venv operations\war_room\.venv
operations\war_room\.venv\Scripts\pip install -r operations\war_room\requirements.txt
```

The launcher also recognises the `py.exe` Python Launcher (bundled
with the python.org installer) as a fallback when no local venv is
present — useful for a quick one-off run, though the pinned deps in
`requirements.txt` only materialise in the venv.

The requirements file pins `streamlit==1.37.1`,
`streamlit-autorefresh==1.0.1`, `grpcio>=1.67.1,<2`, and
`protobuf>=5.27,<6`. Streamlit 1.37.1 pins `protobuf<6`, so the gRPC
stack has to be kept on a protobuf-5-compatible range — regenerate
stubs with `grpcio-tools<1.68` (see the comment at the top of
`requirements.txt`). Version churn in Streamlit has broken the
dashboard between minor releases before — see SPRINT-v0.3.0 §6
Risk #5.

If you already manage Python globally and prefer to skip the venv,
pass `--break-system-packages` to `pip` — but the launch scripts will
still prefer `.venv/` if one exists, so keep them in sync.

## Run

Windows PowerShell 5.1 (default on Windows 10/11):

```powershell
powershell -ExecutionPolicy Bypass -File operations\war_room\launch.ps1
```

If you've installed PowerShell 7+ separately (`pwsh` on PATH):

```powershell
pwsh operations/war_room/launch.ps1
```

The `-ExecutionPolicy Bypass` flag avoids the default "running scripts
is disabled on this system" block for this one invocation without
touching machine-wide policy.

Linux / macOS:

```bash
bash operations/war_room/launch.sh
```

Both open `http://127.0.0.1:8501`. Loopback-only by default; the
launchers pass `--server.fileWatcherType=none --server.runOnSave=false`
so an editor save during an incident shift does **not** restart the
dashboard.

### Port override

```powershell
powershell -ExecutionPolicy Bypass -File operations\war_room\launch.ps1 -Port 8502
```

```bash
PORT=8502 bash operations/war_room/launch.sh
```

### LAN bind (dangerous)

```powershell
powershell -ExecutionPolicy Bypass -File operations\war_room\launch.ps1 -PublicBind
```

```bash
PUBLIC_BIND=1 bash operations/war_room/launch.sh
```

The launcher prints a five-line red warning and sleeps three seconds
before binding `0.0.0.0`. Put a reverse proxy with auth in front of
the dashboard if you need off-box access. Do not skip this: Risk #1 in
the sprint plan is exactly this scenario.

### Pointing at a different signer

```powershell
powershell -ExecutionPolicy Bypass -File operations\war_room\launch.ps1 -AdminTarget "127.0.0.1:50052"
```

```bash
ADMIN_TARGET="127.0.0.1:50052" bash operations/war_room/launch.sh
```

Or override per-session from the sidebar's "Admin gRPC target" box —
empty means "use the default" (`$SANTUARIO_PORT` → Windows TCP →
Unix UDS, matching `core/santuario_client.py`).

## What each panel shows

| Panel     | Source RPC        | What you see |
|-----------|-------------------|--------------|
| Banner    | `GetMetrics`      | Node id, signer-ready/vault-sealed status, snapshot timestamp. Inferred from the `santuario_signer_ready` and `santuario_vault_sealed` gauges. |
| Metrics   | `GetMetrics`      | Every counter / gauge / quantile in the registry, split by namespace: `santuario_*` (Rust-side) and `aeterna_*` (Sentinel-side). |
| Peers     | `ListPeers`       | Gossip view. Address, last-seen age, rx/tx counters, bootstrap flag. |
| Audit     | `TailAuditLog`    | Last N records from the append-only audit log. JSON is byte-identical to disk — forensic-grade, no server-side reshaping. |

If an RPC times out or the channel breaks, the affected panel shows
"degraded" and the dashboard keeps polling. Observability must be
resilient to transient signer unavailability — a suspended or crashing
signer is exactly when the operator needs the dashboard most.

## Regenerating protobuf stubs

If you change `santuario/proto/admin.proto`, regenerate the Python
stubs:

```bash
python -m grpc_tools.protoc \
  --proto_path=santuario/proto \
  --python_out=operations/war_room \
  --grpc_python_out=operations/war_room \
  santuario/proto/admin.proto
```

Check the two `admin_pb2*.py` files back in — they're small and
auditable. Never import pb2 files directly from UI code; go through
`client.py` which wraps them in typed dataclasses.

## Tests

```bash
cd operations/war_room
.venv/bin/python -m unittest tests.test_client -v
```

(Or activate the venv first: `source .venv/bin/activate`.)

The test suite spins up an in-process fake `Admin` gRPC server, dials
it with `AdminObserver`, and asserts the typed dataclasses round-trip
correctly. It also covers the "dead port" path to make sure the UI
never crashes when the signer is down.
