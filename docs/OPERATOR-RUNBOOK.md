# AETERNA Operator Runbook

> **"The machine is sovereign, but the operator is the final judge."**

This runbook defines the standard operating procedures for an AETERNA
Guardian. It covers how to read the node's telemetry, diagnose Custos
kernel alerts, and safely recover a degraded Sanctuary.

**Audience**: solo operator on duty for one or more Guardian nodes.
**Goal**: take any alert this sprint can raise from "I see a red badge"
to "node is healthy again or I have made an informed decision to
escalate" in the shortest time and with the least cognitive load.

---

## 0. Read me first

The first three sections are pre-shift reading -- about ten minutes,
saves fifteen on every incident. When an alert fires, jump straight
to the section named after the alert kind. Every alert section is
self-contained.

If a procedure here disagrees with what your eyes are telling you on
the War Room, **trust your eyes and write up the discrepancy** in the
postmortem template at section 11. This document is a living artifact
and a contradiction is a bug.

---

## 1. Surfaces an operator should have ready

Confirm all four observability surfaces are reachable at shift start.
If any one is down, fix it before accepting the pager -- operating a
Guardian blind is worse than operating no Guardian at all.

| Surface | URL / channel | Purpose |
|---|---|---|
| War Room dashboard | `http://127.0.0.1:8501` (Streamlit) | Visual: status, peers, audit, metrics, integrity |
| Telegram bot | private chat with `@<your-bot>_bot` | Push: alpha / beta / gamma alerts, suspend, recovery_token_issued |
| Grafana dashboard | wherever your Prometheus / Grafana lives | Time series: Trust Score, sign rate, gossip, alerts |
| `santuarioctl` CLI | local terminal in repo root | Action: status, audit, peers, vault, suspend / resume |

**This document** belongs in the same browser tab group. Pin it.

### Pre-flight commands

Run at shift start. Each should succeed in under three seconds.

```powershell
# 1. Signer reachable, state visible
santuarioctl status

# 2. Audit tail is fresh (last record within the last hour)
santuarioctl status --tail 5

# 3. Gossip view is non-empty (at least the bootstrap peer)
santuarioctl status --peers

# 4. Exporter serves Prometheus text format
curl.exe -s http://127.0.0.1:9477/metrics | Select-String "aeterna_node_info"

# 5. War Room loads (browser opens, expect 5 panels in <2s)
Start-Process http://127.0.0.1:8501

# v0.4 Sigillum additions
# 6. Master key id is recognised (non-zero means key envelope is present)
santuarioctl key status

# 7. Ratchet session is established (phase C)
santuarioctl ratchet status
```

If any fails: see **section 9 -- node-health issues** before proceeding.

---

## 2. Conventions used in every alert section

Each alert below follows this template, in order:

1. **Trigger** -- exact firing condition, typically a registry threshold.
2. **Impact on the signer** -- what the node refuses to do while the
   alert is live.
3. **Come la vedi** -- exact strings / panel names on each of the four
   surfaces.
4. **Diagnosi: vero o fantasma?** -- rule-out checklist. About one
   alert in five turns out to be a benign cause.
5. **Recovery procedure** -- numbered, copy-pasteable commands.
6. **SLO atteso di ripristino** -- time bounds for return to normal,
   given correct recovery.
7. **Postmortem trigger** -- when this incident requires a write-up.

### Severity & auto-action legend

| Tag | Source | Auto-action by signer | Operator urgency |
|---|---|---|---|
| alpha | hourly SHA-256 sweep on monitored files | **enters SUSPENDED state** | within 1 hour |
| beta | rolling avg CPU% over `cpu_window_seconds` | **soft hibernation** (no new tasks pulled, in-flight continue) | within 30 min |
| gamma | unsolicited peer floods / portscans on gossip port | drops packets from offending IPs | within 2 hours unless sustained |
| vault sealed | manual or auto on TPM2 anomaly | refuses to sign | within 30 min |
| signer suspended | alpha trip OR manual `santuarioctl suspend` | refuses to sign | **immediate** |
| recovery_token_issued | informational | none -- this is itself a recovery action | distribute token securely |
| key_rotation_due | manual (v0.4 Sigillum) | none | within 24 hours of notice |
| ratchet_desync | 3 consecutive AuthFailed on the gRPC channel | refuses ratchet encrypt/decrypt | within 1 hour |

### The four mental questions

When any alert fires, ask in this order:

1. **Is this signal real?** (run the rule-out checklist for the kind)
2. **Is this MY change?** (`git status`, recent `santuarioctl` commands, recent config edits)
3. **Is the node still safe to sign?** (check `santuario_signer_state` -- if `SUSPENDED`, the answer is *no*; do not resume until root cause is gone)
4. **Do I need to escalate or recover solo?** (severity table above)

---

## 3. alpha-Alert -- Integrity Drift

### Trigger

The Custos hourly sweep computed a SHA-256 of one of the files in
`aeterna.toml [integrity] files` and the digest no longer matches
the signed baseline in `santuario/integrity/baseline.json`.

### Impact on the signer

**The signer immediately enters the `SUSPENDED` state.** No further
PoC blocks, no further gossip messages signed. The node continues to
receive and validate peer traffic for telemetry purposes only.

### Come la vedi

| Surface | What you see |
|---|---|
| War Room | `Integrity` panel turns RED. Header lists the offending file path. |
| Telegram | `alpha-alert: integrity drift on <file>` -- payload includes new digest, baseline digest, audit-record id. |
| Grafana | `santuario_integrity_alerts_total` counter steps up. `Signer State` stat flips to `SUSPENDED` (red). Sign Rate panel flatlines within 30s. |
| `santuarioctl` | `status --tail 5` shows a record with `record="alert"` and `severity="alpha"`. |

### Diagnosi: vero o fantasma?

```powershell
# 1. Identify the file
santuarioctl status --tail 5 | Select-String "alpha"

# 2. Did YOU touch it recently?
git log -1 --format="%h %ai %s" -- <file>
git diff HEAD -- <file>

# 3. Filesystem timestamp recent?
Get-Item <file> | Select-Object Name, LastWriteTime
```

| Outcome | Interpretation |
|---|---|
| Recent intentional commit you remember making | **False positive** -- the baseline is stale, recovery A. |
| Recent edit you do **not** remember making | **True positive -- possible compromise** -- recovery B. |
| File untouched, baseline file present | **Stale baseline entry** -- re-seal after `git diff HEAD` confirms no unintended delta (recovery A). |
| Baseline file missing or empty | **Configuration drift** -- investigate before re-sealing. |

### Recovery procedure

#### A. False positive -- operator-acknowledged drift

```powershell
# Acknowledge the drift, restart the signer.
santuarioctl resume --force
```

Use this when you are **certain** the change was intentional and the
new file content is the correct sealed state.

#### B. True positive -- suspected compromise

This is a **destructive** recovery. The node is presumed corrupted.

```powershell
# 1. Snapshot evidence BEFORE wiping.
$ts = Get-Date -Format yyyyMMddHHmmss
Copy-Item <file> "$env:USERPROFILE\Desktop\suspect_$ts.bin"
santuarioctl status --tail 50 > "$env:USERPROFILE\Desktop\incident_audit_$ts.log"

# 2. Stop the node, wipe local state.
#    (Press Ctrl-C in bootstrap terminal to LIFO-tear down all four legs.)

# 3. Wipe the working tree and re-clone from the canonical remote.
cd ..
Remove-Item aeterna-protocol -Recurse -Force
git clone <your-canonical-remote> aeterna-protocol
cd aeterna-protocol

# 4. Restore the vault from cold backup (offline secret-management
#    procedure -- out of scope for this runbook, in scope for your
#    vault key-management policy).

# 5. Re-bootstrap.
.\bootstrap.ps1
```

### SLO atteso di ripristino

| Recovery path | Target time |
|---|---|
| A -- `resume --force` | <= 60s after command |
| B -- wipe + restore | governed by your cold-backup recovery time |

### Postmortem trigger

**Always for path B.** Path A only requires a postmortem if alpha
fires on the same file more than once in a week (indicates baseline
policy needs revision).

---

## 4. beta-Alert -- Resource Exhaustion

### Trigger

The rolling average CPU% over `aeterna.toml [integrity]
cpu_window_seconds` (default 600s) crossed `cpu_threshold_pct`
(default 90%), or thermal throttling was detected on the GPU/CPU.

### Impact on the signer

**Soft hibernation.** The Sentinel stops pulling new tasks from the
gossip network. Computations already dispatched to the Julia engine
continue to completion. The signer remains in `NORMAL` state -- it
will sign blocks for the in-flight tasks.

### Come la vedi

| Surface | What you see |
|---|---|
| War Room | `Status` panel shows a yellow `HIBERNATING` badge. `Metrics` panel scrape may slow. |
| Telegram | `beta-alert: CPU stress` -- payload includes the measured average and the threshold. |
| Grafana | `santuario_integrity_alerts_total` (severity=beta) counter steps up. `Julia Task Queue Depth` panel may show queue draining. |
| OS task manager | `Get-Process | Sort-Object CPU -Descending | Select -First 5` reveals the culprit. |

### Diagnosi: vero o fantasma?

```powershell
# 1. Confirm load really exists
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 ProcessName, Id, CPU

# 2. Identify if it's an AETERNA process or external
Get-Process | Where-Object { $_.ProcessName -match "santuario|julia|python" } |
  Select-Object ProcessName, Id, CPU, WorkingSet

# 3. Check Julia jam vs honest workload spike
curl.exe -s http://127.0.0.1:9477/metrics | Select-String "task_queue_depth"
```

| Pattern | Interpretation |
|---|---|
| Non-AETERNA process pegging CPU (Windows update, antivirus scan, etc.) | **Benign external load** -- wait or throttle the offender. |
| Julia process pegged AND queue depth rising | **Julia jammed** -- unusual for hibernation mode. Investigate the in-flight task. |
| Python sentinel pegged | **Sentinel runaway loop** -- restart bootstrap. |
| All AETERNA processes idle but CPU% high | **External hostile process** -- incident response. |

### Recovery procedure

**No `santuarioctl` intervention required for the typical case.** When
the load drops below `cpu_threshold_pct` for `cpu_window_seconds`
consecutively, the node automatically resumes harvesting tasks. Your
job is to make the load go away.

```powershell
# Identify and stop the offending process
$badPid = (Get-Process | Where-Object {$_.CPU -gt 100} | Select-Object -First 1).Id
Stop-Process -Id $badPid -Force
```

If the offender is an AETERNA Julia process stuck in a runaway:

```powershell
# Press Ctrl-C in bootstrap terminal (LIFO teardown), then relaunch.
# -SkipSigner -SkipExporter avoids re-building the Rust crates.
.\bootstrap.ps1 -SkipSigner -SkipExporter
```

### SLO atteso di ripristino

Auto-resume occurs once CPU stays below threshold for the full
`cpu_window_seconds` window (default 10 min). Operator action just
shortens that window.

### Postmortem trigger

Write a postmortem if beta fires more than three times in 24h, or
if Julia jamming is the root cause (which usually means a reproducible
bad task input -- capture it).

---

## 5. gamma-Alert -- Network / Portscan

### Trigger

Unrecognized peers attempting rapid handshakes, OR a sustained flood
of malformed UDP packets on the gossip port (default 4444 for
Prometheus-1, 4445 for Prometheus-0). Threshold:
`portscan_abort_count` distinct unsolicited scans within
`portscan_window_seconds`.

### Impact on the signer

The node dynamically drops packets from the offending IPs. **The
signer remains in `NORMAL` state** -- gamma is a defensive posture,
not a suspension.

In v1.0+ "Sovereign", a sustained gamma event will additionally
trigger stealth migration. In v0.3.0 it stops at packet drop.

### Come la vedi

| Surface | What you see |
|---|---|
| War Room | `Peers` panel shows offending IPs with elevated `rx_count`. Audit panel shows a `record="alert"` with `severity="gamma"`. |
| Telegram | `gamma-alert: portscan from <ip>` -- payload includes source IP and packet count. |
| Grafana | `santuario_integrity_alerts_total` (severity=gamma) counter steps up. `Gossip Traffic` panel shows abnormal RX spike. |
| `santuarioctl` | `status --peers` shows the offending IP with `is_bootstrap=false` and high `rx_count`. |

### Diagnosi: vero o fantasma?

```powershell
# 1. Read the alert detail
santuarioctl status --tail 10 --json | jq -r '.audit_tail[] | select(.record == "alert") | .json'

# 2. Identify source IP
santuarioctl status --peers | Select-String "<source_ip>"
```

| Pattern | Interpretation |
|---|---|
| Source is a known bootstrap peer | **Possible peer compromise** -- recovery A. |
| Source unknown to peer table | **External attacker** -- recovery B. |
| Source is `127.0.0.1` or your own LAN IP | **Self-scan** (you ran nmap, masscan, etc.) -- recovery C. |
| Multiple distinct source IPs | **Distributed scan / attack** -- recovery B + escalate. |

### Recovery procedure

#### A. Compromised known peer

```powershell
# 1. Remove the peer from bootstrap_peers in aeterna.toml
notepad aeterna.toml
# Edit [gossip] bootstrap_peers, drop the offending entry.

# 2. Notify the peer operator via your out-of-band channel.

# 3. Restart the gossip leg
# (Ctrl-C in bootstrap, relaunch)
.\bootstrap.ps1
```

#### B. External attacker

```powershell
# 1. Block at the OS firewall
New-NetFirewallRule -DisplayName "AETERNA-block-<ip>" -Direction Inbound `
    -Action Block -RemoteAddress <source_ip>

# 2. If sustained from many IPs, rotate the gossip port
notepad aeterna.toml
# Change [gossip] port to a new value (and update peers).

# 3. Restart bootstrap
.\bootstrap.ps1
```

#### C. Self-inflicted scan

Stop scanning your own node. The packet drops will subside on their
own; no further action needed.

### SLO atteso di ripristino

The packet-drop posture self-clears when the offending IP stops
sending. No state to "recover" from beyond fixing the upstream cause.

### Postmortem trigger

Write a postmortem for any gamma from an unknown external IP that
persists for more than 1 hour. Also for any gamma from a known peer.

---

## 6. The Vault is SEALED

### Trigger

The Dilithium-5 private key envelope is locked. This happens manually
(`santuarioctl seal`) OR automatically on:

- TPM2 attestation failure
- Vault file tamper detection (cross-fires with alpha)
- A fresh OS reboot before operator unseal

### Impact on the signer

The signer cannot sign anything until the vault is unsealed.
`santuario_signer_state_suspended` reads `1`.

### Come la vedi

| Surface | What you see |
|---|---|
| War Room | `Vault` banner is RED. Sign rate flatlines. |
| Telegram | `Vault sealed (reason: <...>)` |
| Grafana | `santuario_vault_sealed` stat = `SEALED` (red). |
| `santuarioctl status` | `vault: sealed`. |

### Diagnosi: vero o fantasma?

```powershell
# 1. Was it sealed manually or automatically?
santuarioctl status --tail 10 --json | jq -r '.audit_tail[] | select(.record == "vault_sealed") | .json'
# Look for the "reason" field. Manual seals carry your reason string;
# automatic seals carry "tpm2_attest_failure", "vault_tamper", etc.

# 2. Is the TPM2 reachable?
santuarioctl vault attest
# Healthy: "TPM2 attestation OK, PCR digest <hex>"
# Unhealthy: error identifying the TPM2 failure mode.
```

| Outcome | Interpretation |
|---|---|
| Manual seal you remember | **Benign** -- recovery A. |
| Manual seal you don't remember | **Operator confusion or unauthorized access** -- investigate audit log first. |
| Auto seal due to TPM2 attestation failure | **Hardware / driver issue** -- recovery B. |
| Auto seal due to vault file tamper | **Cross-check with alpha** -- likely the same incident, treat as compromise (section 3 path B). |
| Cause = "fresh boot" | **Normal startup** -- operator must unseal as part of every boot, recovery A. |

### Recovery procedure

#### A. Manual unseal (you have the passphrase)

```powershell
santuarioctl unseal
# Prompts for the unseal passphrase. Paste, do not echo to history.
# On success: "Vault unsealed. Signer warming up."
```

#### B. TPM2 attestation failure

```powershell
# 1. Capture state
santuarioctl vault attest --verbose > attest.log 2>&1

# 2. Check vendor BIOS / TPM2 firmware updates

# 3. If hardware is healthy but PCRs drifted (expected after a BIOS
#    update or bootloader change), re-seal against the new PCR set.
#    KEEP the old unseal passphrase until the re-key completes.
santuarioctl vault rekey --new-pcr-set
```

If TPM2 is genuinely dead, the node is operationally compromised
until hardware is replaced. By design, there is no soft recovery
from a real TPM2 failure.

### SLO atteso di ripristino

| Recovery path | Target time |
|---|---|
| A -- manual unseal | <= 30s after passphrase paste |
| B -- TPM2 re-key (healthy hardware) | <= 5 min |
| B -- TPM2 hardware failure | hardware replacement window |

### Postmortem trigger

Always for any auto-seal (paths in B). Manual seals do not require one.

---

## 7. The Signer is SUSPENDED

### Trigger

`santuario_signer_state == 2`. Reached via:

- alpha trip (section 3)
- manual `santuarioctl suspend`
- cascading failure from an upstream alert

### Impact on the signer

Refuses all sign / verify / resume requests. Telegram bot refuses to
acknowledge `/audit_now` (read endpoints still work). Unlike beta's
hibernation, suspension does **not** auto-clear.

### Come la vedi

| Surface | What you see |
|---|---|
| War Room | `Status` panel shows `SUSPENDED` in red. |
| Telegram | `Signer suspended (cause: <...>)` |
| Grafana | `santuario_signer_state_suspended` gauge = 1. Sign Rate panel flatlines. |
| `santuarioctl status` | `state: suspended` plus a `cause` field. |

### Diagnosi: vero o fantasma?

```powershell
santuarioctl status --tail 10 --json | jq -r '.audit_tail[] | select(.record == "signer_suspend") | .json'
```

| Cause field | Cross-reference |
|---|---|
| `alpha_drift` | section 3 -- recover via that procedure |
| `manual_operator_<reason>` | You suspended it -- recovery A here |
| `cascading_vault_seal` | section 6 -- recover via that, then come back here |
| `cascading_critic_reject` | The critic refused a payload -- investigate audit detail before resuming |

### Recovery procedure

#### A. Operator-initiated clean resume

After the upstream cause is cleared (or for an operator-initiated
suspension where the operator decides it's safe to resume):

```powershell
santuarioctl resume
```

The signer transitions back to `NORMAL` within 60s.

#### B. Cascading suspensions

After resolving the upstream alert per its own section, the signer
does **not** auto-resume. Run `santuarioctl resume` explicitly.

If `resume` fails with "upstream condition still present", re-diagnose
the upstream alert -- it was not truly resolved.

### SLO atteso di ripristino

<= 60s after `santuarioctl resume`, given the upstream cause is
genuinely cleared.

### Postmortem trigger

Always for cascading failures. Optional for clean operator
suspensions during planned maintenance.

---

## 8. Recovery token issued

### Trigger

A one-time-use recovery token has been minted by an operator (or by
a higher-trust authority in multi-operator deployments). Telegram
emits a `recovery_token_issued` push.

### Impact on the signer

None directly. This is **informational** -- the existence of this
record signals that someone has just initiated a recovery sequence.
If that someone wasn't you, something is wrong.

### Come la vedi

| Surface | What you see |
|---|---|
| War Room | New entry in the `Audit` panel with `record="recovery_token_issued"`. |
| Telegram | `Recovery token issued (valid until <ts>)`. The token itself is **not** in the push -- by design, to keep Telegram out of the secret path. |
| Grafana | No metric (this is a state transition, not a counter). |
| `santuarioctl recovery status` | Shows the active token's expiry timestamp (never the value). |

### Diagnosi: vero o fantasma?

```powershell
santuarioctl status --tail 5 --json | jq -r '.audit_tail[] | select(.record == "recovery_token_issued")'
```

The audit record carries an `issued_by` field with the operator
identity. If that's not you, treat as a section 3 path B compromise.

### Recovery procedure

This section has no recovery procedure of its own -- it is informational.

- **If you issued it**: distribute and apply within the validity window.
- **If you did not issue it**: invalidate immediately.

```powershell
# Invalidate an active token (renders it un-applyable)
santuarioctl recovery revoke
```

### SLO atteso di ripristino

N/A -- this is a recovery-in-progress signal.

### Postmortem trigger

Write a postmortem for any token issued by an operator other than
you, or any token that expires without being applied.

---

## 9. Node-health issues (not alerts, but operator-actionable)

These are not protocol alerts -- they are operational degradations the
operator should notice and correct. They surface in Prometheus and
the War Room, but typically not in Telegram (which is reserved for
audit-log-grade events).

### 9.1 Signer unreachable

**Symptom**: `santuario_exporter_scrape_errors_total` increments. War
Room "Connection" badge red. `santuarioctl status` returns gRPC
connection error.

**Diagnosis**:

```powershell
Get-Process santuario-signer -ErrorAction SilentlyContinue
Test-NetConnection 127.0.0.1 -Port 50051 -InformationLevel Quiet
```

**Recovery**: re-launch via bootstrap. If the signer panicked, the
bootstrap terminal stderr will tell you why -- capture before re-launch.

```powershell
# Ctrl-C in bootstrap, then:
.\bootstrap.ps1
```

### 9.2 Engine unreachable (Julia ZMQ)

**Symptom**: Sentinel logs show `ZMQ REQ timeout` or
`SciEngineUnavailable`. War Room "Engine" badge red.
`aeterna_task_queue_depth` Grafana panel grows monotonically.

**Diagnosis**:

```powershell
Get-Process julia -ErrorAction SilentlyContinue
Test-NetConnection 127.0.0.1 -Port 5555 -InformationLevel Quiet
```

**Recovery**: same as 9.1. If Julia is consistently crashing, check
the Manifest with `bootstrap.ps1 -RegenJuliaManifest`.

### 9.3 Gossip silence

**Symptom**: `aeterna_gossip_peers_active == 0` for more than 5 min.
War Room "Peers" panel empty.

**Diagnosis**:

```powershell
# Are bootstrap peers reachable from this host?
$peers = (Get-Content aeterna.toml | Select-String 'udp://').Matches.Value
foreach ($p in $peers) {
    $hostport = $p -replace 'udp://', ''
    $h, $port = $hostport -split ':'
    Test-NetConnection $h -Port $port -InformationLevel Quiet
}
```

**Recovery**:

- Peer down -> contact peer operator. Your node is healthy, just isolated.
- Firewall changed -> open UDP on the gossip port (default 4444 / 4445).
- `bootstrap_peers` wrong -> edit `aeterna.toml`, restart.

A node alone in the network is **not** in alerting state. It can
still produce blocks, they just won't be PoC-validated by anyone, and
its Trust Score won't grow. Prolonged isolation is a problem worth
fixing within hours, not days.

---

## 10. The Telemetry Triad -- surface-by-surface guide

| Surface | When to use it | Strengths | Limits |
|---|---|---|---|
| **War Room** (`localhost:8501`) | At your desk, mid-incident | Real-time, all five panels in one screen, audit replay | Local only, single-node view |
| **Telegram bot** | Mobile, away from desk | Push notifications, no need to be at terminal | Read-only, no recovery actions |
| **Grafana** (port 9477 -> Prom -> Grafana) | Fleet operations, trend analysis | Multi-node, time series, alert rules | Lags real-time by scrape interval |
| **`santuarioctl` CLI** | Recovery actions | The only surface that can mutate state | Local terminal only |

**Default recovery flow**: see it on Telegram -> confirm on War Room
-> recover via `santuarioctl` -> verify on Grafana that the metric
cleared.

---

## 11. Postmortem template

Save under `docs/postmortems/<yyyy-mm-dd>-<slug>.md`. Keep them
public -- the next operator on shift learns from them.

```markdown
# Postmortem -- <one-line summary>

**Incident date**: yyyy-mm-dd hh:mm UTC
**Operator**: <name / handle>
**Severity**: alpha | beta | gamma | vault | suspend | recovery
**Time to detect**: <minutes from first audit-log entry to operator awareness>
**Time to recover**: <minutes from awareness to signer back to NORMAL>
**Postmortem trigger**: <which section of the runbook required this>

## Timeline

- hh:mm -- first audit-log entry
- hh:mm -- operator alerted (which surface?)
- hh:mm -- diagnosis complete
- hh:mm -- recovery initiated
- hh:mm -- signer state back to NORMAL

## Root cause

One paragraph. Be specific about the chain of cause-and-effect.

## What worked

What in the runbook, dashboards, or alerts helped you?

## What didn't

What was missing or misleading? File issues for runbook updates.

## Action items

- [ ] <concrete change to runbook / config / code>
- [ ] <...>
```

---

---

## 12. Key rotation (v0.4 Sigillum)

> **Signal → Diagnosis → Recovery → SLO**

### When to rotate

Rotate the BIP-39 master seed when:

1. You suspect the seed phrase was exposed (written down in an insecure location, observed by an unauthorised person, stored unencrypted on a device that was stolen or compromised).
2. The previous operator's tenure ends and key custody must transfer.
3. A periodic rotation policy requires it (recommended maximum: 12 months).
4. `santuarioctl key status` shows `last_rotation_utc` older than your policy window.

Do **not** rotate on routine reboots, software upgrades, or mere suspicion without evidence. Each rotation discards all prior ciphertext (segments cannot be re-encrypted retrospectively). Plan archival before rotating.

### Diagnosis

Confirm that rotation is actually warranted before proceeding:

```powershell
santuarioctl key status
# Review: master_key_id, derivation_utc, last_rotation_utc
santuarioctl ratchet status
# If established=no: ratchet is inactive (separate issue, see §13)
```

If `last_rotation_utc` is within your policy window and there is no exposure event, stop here. No rotation needed.

### Recovery procedure

> **Archive first.** Encrypted segments written under the OLD key cannot be decrypted after the new key is in place. Store a copy of `./logs/audit/` under a clearly dated path before rotating.

```powershell
# 1. Archive current encrypted segments.
$ts = Get-Date -Format "yyyyMMdd-HHmm"
Copy-Item -Recurse ./logs/audit "./logs/audit-archive-$ts"
Write-Host "Archived segments to logs/audit-archive-$ts"

# 2. Generate a new BIP-39 seed phrase (use a CSPRNG tool, e.g.
#    `bip39-keygen` or hardware wallet). Write 24 words on paper.
#    Store the paper in a physically secured location.

# 3. Save the new phrase to a temporary file.
notepad.exe ./new_seed.bip39   # type the 24 words, save, close

# 4. Import the new seed. Confirm the paper-backup prompt.
santuarioctl key import ./new_seed.bip39

# 5. Delete the temporary seed file securely.
Remove-Item ./new_seed.bip39

# 6. Verify the new master key id is recorded.
santuarioctl key status

# 7. Restart the signer so it re-derives the log key on next boot.
#    (The signer will start a new segment chain from the new key.)
#    Kill and restart via bootstrap.ps1 -SeedFile <vault/seed.bip39>

# 8. Re-handshake the operator-endpoint ratchet under the new identity.
santuarioctl identity show | Out-File -Encoding utf8 ./signer_identity.pub
santuarioctl identity import ./signer_identity.pub
santuarioctl ratchet rehandshake
Remove-Item ./signer_identity.pub

# 9. Confirm: read a new audit record under the new key.
santuarioctl tail
```

### SLO

| Step | Target |
|---|---|
| Archive segments | < 5 min |
| Generate + import new seed | < 15 min |
| Signer restart + ratchet re-handshake | < 5 min |
| **Total rotation window** | **< 30 min** |

Escalate if any step exceeds its target by 100%: the most likely cause is a missing or corrupted `keys.envelope`, which requires re-deriving from the seed phrase manually.

---

## 13. Operator key compromise recovery (v0.4 Sigillum)

> **Signal → Diagnosis → Recovery → SLO**

### Signals of key compromise

The operator notices one or more of the following:

1. **Suspicious Telegram pushes**: alerts arrive from a `chat_id` that is not in `aeterna.toml [operations.telegram] allowed_chat_ids`.
2. **Decryption failures**: `santuarioctl tail` returns `Err(InvalidTag)` on segments the operator knows are intact.
3. **Ratchet desync without operator action**: `santuarioctl ratchet status` shows `tombstoned=yes` and the operator did not trigger a step or rehandshake.
4. **Audit of recent gRPC sessions** shows calls the operator cannot account for.

### Diagnosis

```powershell
# 1. Check ratchet state.
santuarioctl ratchet status
# expected: established=yes, tombstoned=no
# if tombstoned=yes: proceed to recovery

# 2. Check audit tail for unexpected RPCs.
santuarioctl tail --limit 50
# Look for unusual patterns: many GetRatchetStatus calls in a burst,
# rehandshake calls at unexpected times, etc.

# 3. Verify the master key id matches your paper backup.
santuarioctl key status
# Compare master_key_id to the fingerprint on your paper backup card.
# A mismatch means the keys.envelope was replaced by an attacker.
```

If none of the signals are present, the desync is likely transient (network jitter, process restart). Run `santuarioctl ratchet rehandshake` and monitor.

If one or more signals are confirmed, treat this as a key compromise event:

### Recovery procedure

**Treat the signer's gRPC port as hostile until a new ratchet session is established under a fresh identity.**

```powershell
# 1. Suspend the signer immediately (prevents further signing).
santuarioctl audit --accept    # force a baseline capture so the
                               # post-incident sweep is clean

# 2. Rotate the master seed (see §12 Key rotation). This also rotates
#    the ratchet identity, because both are derived from the same seed.

# 3. Verify the signer has restarted with the new identity.
santuarioctl identity show
# Record the new identity_id_hex on your paper backup card.

# 4. Re-import the new signer identity and re-handshake.
santuarioctl identity show | Out-File -Encoding utf8 ./new_identity.pub
santuarioctl identity import ./new_identity.pub
santuarioctl ratchet rehandshake
Remove-Item ./new_identity.pub

# 5. Confirm the session is established under the new step-0 key.
santuarioctl ratchet status
# expected: established=yes, step=0, tombstoned=no

# 6. Resume the signer after manual review of the audit tail.
santuarioctl resume --token <challenge-hex> --operator "key-rotation-recovery"
```

### SLO

| Step | Target |
|---|---|
| Suspend signer | < 2 min |
| Rotate key + restart | < 30 min (see §12) |
| Re-handshake + confirm | < 5 min |
| **Total recovery window** | **< 40 min** |

The signer is unsigned-safe during this window (it refuses to sign while suspended). The recovery is complete when `santuarioctl ratchet status` shows `established=yes` on the NEW session and `santuarioctl key status` shows the new `master_key_id`.

### Postmortem

File a postmortem within 24 hours using the template in §11. Include:
- When the first signal was observed vs. when recovery began.
- Whether the compromise was confirmed or precautionary.
- Which surface surfaced the signal first (Telegram, ratchet desync, decryption error).

---

## 14. Closing principle

This runbook is the operator-facing closure of sprint v0.3.0 "Oculus"
extended to sprint v0.4.0 "Sigillum".
It owes its structure to the principle that the worst moment to learn
how a system fails is when it is failing.

Improve it. Every section should start its life as somebody's
postmortem.

---

*See also:*

- [`docs/SPRINT-v0.3.0.md`](./SPRINT-v0.3.0.md) -- prior sprint (Oculus visibility primitives)
- [`docs/SPRINT-v0.4.0.md`](./SPRINT-v0.4.0.md) -- current sprint plan (Sigillum, §§12-13 source)
- [`docs/CONSENSUS.md`](./CONSENSUS.md) -- Trust Score formula referenced in section 0
- [`docs/AGP-v1.md`](./AGP-v1.md) -- AGP-v1 payload format
- [`aeterna.toml`](../aeterna.toml) -- `[integrity]` and `[sigillum]` thresholds
- [`operations/grafana/aeterna-overview.json`](../operations/grafana/aeterna-overview.json) -- Grafana dashboard JSON
- [`operations/grafana/prometheus-scrape-snippet.yaml`](../operations/grafana/prometheus-scrape-snippet.yaml) -- Prometheus scrape config snippet
