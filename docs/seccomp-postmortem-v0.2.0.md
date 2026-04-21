# Postmortem: Seccomp-BPF Policy Tuning for Julia (v0.2.0 "Custos")

## 1. Overview
During the Phase B implementation of the v0.2.0 sprint, we transitioned the `isolation_mode` from `none` to `seccomp`. The goal was to strictly sandbox the Julia scientific engine (`zmq_server.jl`) to prevent any compromised workload from executing arbitrary shell commands (e.g., `Sys.exec("ls")`). We adopted a **strict allowlist** model rather than a permissive denylist.

## 2. The Issue: False Positives on Cold Start
Initially, the strict seccomp policy caused the Julia process to crash with `SIGSYS` (Bad system call) during its JIT precompilation phase. This happened because the baseline profile was collected during a warm run, completely missing the extensive system calls Julia makes when compiling LLVM IR and loading dynamic libraries at cold start.

### Key Symptoms:
- `bootstrap.sh` spawned the Julia process, but ZMQ heartbeats timed out.
- The system `dmesg` logs showed `audit` lines indicating that the seccomp filter killed the Julia process for attempting `mprotect`, `mmap`, and `futex` with unexpected flags.

## 3. Root Cause Analysis
Julia's JIT compiler (LLVM-based) requires dynamic generation of code, which means it relies heavily on allocating memory that is both writable and executable (often transitioning between `PROT_WRITE` and `PROT_EXEC` via `mprotect`). Our initial policy blocked `mprotect` calls that requested `PROT_EXEC`, as this is a common anti-exploit mitigation (W^X). 

Furthermore, `Pkg.instantiate()` makes several network-related syscalls (`socket`, `connect`, `recvfrom`) to fetch registries, which were also blocked by the strict profile since we assumed the scientific workload would only use the predefined ZMQ IPC sockets.

## 4. Resolution
To fix the false positives without compromising the security model, we implemented a dual-phase policy approach:
1. **Precompile Phase (Permissive Network, W^X Relaxed)**: A setup script is allowed to run `Pkg.instantiate()` with a slightly relaxed policy.
2. **Runtime Phase (Strict, No Network)**: The actual `zmq_server.jl` daemon runs with a hardened profile. We explicitly added the required `mprotect` and `futex` variants that Julia uses for garbage collection and threading, but strictly denied `execve`, `fork`, and external network sockets.

## 5. Lessons Learned & Action Items
- **Always profile from a clean slate**: Seccomp profiling must include the cold-start and precompilation paths, not just the steady-state loop.
- **W^X is tricky with JITs**: Standard seccomp hardening templates break JIT compilers. Allowlisting `mprotect` for Julia was unavoidable, but we compensated by completely locking down `execve` and `ptrace` to prevent shellcode from doing anything useful even if it compromises the JIT.

*Date: 2026-04-21*
*Author: Terminale di Comando / Santuario Team*
