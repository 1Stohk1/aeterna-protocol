//! Linux seccomp-bpf launcher. The flow is:
//!
//!   1. Parent validates program and policy.
//!   2. Parent forks.
//!   3. Child:
//!      - `chdir` to `workdir` if set.
//!      - Install a seccomp-bpf filter derived from the text policy.
//!        Default action is `SCMP_ACT_ERRNO(ENOSYS)` so denied syscalls
//!        fail loudly; allowed syscalls get `SCMP_ACT_ALLOW`.
//!      - `execve` the target. At this point the child has no cap to
//!        broaden its own syscall surface.
//!   4. Parent reads the PID, hashes the binary on disk, stamps the
//!      attestation and stores it in an in-memory table.
//!
//! If the `seccomp` Cargo feature is disabled, the launcher compiles but
//! the filter installation step is a no-op — useful for CI hosts that
//! don't ship `libseccomp-dev`. That permissive mode is refused in
//! production by `Launcher::is_enforcing` returning `false`.
//!
//! See `docs/sprint-v0.2.0.md §3 Phase B` for the contract.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::policy::Policy;
use crate::{hash_file, now_utc, Attestation, IsolationError, LaunchSpec, LaunchedChild, Launcher};

/// In-process table: pid -> attestation. The signer queries this before
/// every signature; unknown PIDs are refused.
#[derive(Debug, Default)]
pub struct AttestationTable {
    inner: Mutex<std::collections::HashMap<i32, Attestation>>,
}

impl AttestationTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, att: Attestation) {
        self.inner.lock().unwrap().insert(att.pid, att);
    }

    pub fn get(&self, pid: i32) -> Option<Attestation> {
        self.inner.lock().unwrap().get(&pid).cloned()
    }

    pub fn forget(&self, pid: i32) -> Option<Attestation> {
        self.inner.lock().unwrap().remove(&pid)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The Linux launcher. Construct with [`SeccompLauncher::new`].
pub struct SeccompLauncher {
    pub table: AttestationTable,
}

impl SeccompLauncher {
    pub fn new() -> Self {
        Self {
            table: AttestationTable::new(),
        }
    }
}

impl Default for SeccompLauncher {
    fn default() -> Self {
        Self::new()
    }
}

impl Launcher for SeccompLauncher {
    fn launch(&self, spec: &LaunchSpec) -> Result<LaunchedChild, IsolationError> {
        validate_program(&spec.program)?;
        let policy = Policy::load(spec.policy)?;
        let exe_hash_hex = hash_file(&spec.program)?;
        let pid = spawn_under_policy(spec, &policy)?;

        let att = Attestation {
            pid,
            policy: spec.policy,
            exe_hash_hex,
            started_utc: now_utc(),
            program: spec.program.clone(),
        };
        self.table.insert(att.clone());
        Ok(LaunchedChild { attestation: att })
    }

    fn attest(&self, pid: i32) -> Result<Attestation, IsolationError> {
        let att = self.table.get(pid).ok_or(IsolationError::UnknownPid(pid))?;
        if !pid_alive(pid) {
            return Err(IsolationError::Dead(pid));
        }
        let current = hash_file(&att.program)?;
        if current != att.exe_hash_hex {
            return Err(IsolationError::Seccomp(format!(
                "pid {pid}: on-disk exe hash drifted since launch (expected {}, got {current})",
                att.exe_hash_hex
            )));
        }
        Ok(att)
    }

    fn is_enforcing(&self) -> bool {
        cfg!(feature = "seccomp")
    }
}

fn validate_program(path: &Path) -> Result<(), IsolationError> {
    if !path.exists() {
        return Err(IsolationError::ProgramMissing(path.to_path_buf()));
    }
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)?;
    let mode = meta.permissions().mode();
    if mode & 0o111 == 0 {
        return Err(IsolationError::ProgramNotExecutable(path.to_path_buf()));
    }
    Ok(())
}

fn pid_alive(pid: i32) -> bool {
    PathBuf::from(format!("/proc/{pid}")).exists()
}

// ---- libseccomp-gated fork+exec under policy ------------------------------

#[cfg(feature = "seccomp")]
fn spawn_under_policy(spec: &LaunchSpec, policy: &Policy) -> Result<i32, IsolationError> {
    use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
    use nix::unistd::{fork, ForkResult};

    // SAFETY: `fork` is unsafe in general-purpose Rust because post-fork
    // the child must touch only async-signal-safe APIs until execve. We
    // uphold that: the child runs only libseccomp filter install and
    // execve, both of which are fork-safe.
    match unsafe { fork() }.map_err(|e| IsolationError::Fork(e.to_string()))? {
        ForkResult::Parent { child } => Ok(child.as_raw()),
        ForkResult::Child => {
            // chdir
            if let Some(wd) = &spec.workdir {
                let cs = CString::new(wd.as_os_str().as_bytes()).unwrap();
                // Using libc directly to avoid async-unsafe Rust paths.
                unsafe {
                    if libc::chdir(cs.as_ptr()) != 0 {
                        libc::_exit(127);
                    }
                }
            }

            // Build seccomp filter.
            let mut f = match ScmpFilterContext::new(ScmpAction::Errno(libc::ENOSYS)) {
                Ok(f) => f,
                Err(_) => unsafe { libc::_exit(126) },
            };
            for name in &policy.allow {
                let sc = match ScmpSyscall::from_name(name) {
                    Ok(s) => s,
                    Err(_) => {
                        eprintln!("seccomp: unknown syscall '{name}'");
                        unsafe { libc::_exit(126) }
                    }
                };
                if f.add_rule(ScmpAction::Allow, sc).is_err() {
                    unsafe { libc::_exit(126) }
                }
            }
            if f.load().is_err() {
                unsafe { libc::_exit(126) }
            }

            // execve. We rebuild argv / envp as C strings.
            let prog_c = match CString::new(spec.program.as_os_str().as_bytes()) {
                Ok(c) => c,
                Err(_) => unsafe { libc::_exit(125) },
            };
            let mut argv: Vec<CString> = vec![prog_c.clone()];
            for a in &spec.args {
                match CString::new(a.as_bytes()) {
                    Ok(c) => argv.push(c),
                    Err(_) => unsafe { libc::_exit(125) },
                }
            }
            let mut envp: Vec<CString> = Vec::with_capacity(spec.env.len());
            for (k, v) in &spec.env {
                let s = format!("{k}={v}");
                match CString::new(s) {
                    Ok(c) => envp.push(c),
                    Err(_) => unsafe { libc::_exit(125) },
                }
            }
            let argv_ptrs: Vec<*const libc::c_char> = argv
                .iter()
                .map(|c| c.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();
            let envp_ptrs: Vec<*const libc::c_char> = envp
                .iter()
                .map(|c| c.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();
            unsafe {
                libc::execve(prog_c.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
                // reached only on execve failure
                libc::_exit(124);
            }
        }
    }
}

#[cfg(not(feature = "seccomp"))]
fn spawn_under_policy(spec: &LaunchSpec, _policy: &Policy) -> Result<i32, IsolationError> {
    // Permissive mode — fork+exec without a seccomp filter. `is_enforcing`
    // returns false, which the signer treats as a hard downgrade.
    use nix::unistd::{fork, ForkResult};
    match unsafe { fork() }.map_err(|e| IsolationError::Fork(e.to_string()))? {
        ForkResult::Parent { child } => Ok(child.as_raw()),
        ForkResult::Child => {
            if let Some(wd) = &spec.workdir {
                let cs = CString::new(wd.as_os_str().as_bytes()).unwrap();
                unsafe {
                    if libc::chdir(cs.as_ptr()) != 0 {
                        libc::_exit(127);
                    }
                }
            }
            let prog_c = CString::new(spec.program.as_os_str().as_bytes()).unwrap();
            let mut argv: Vec<CString> = vec![prog_c.clone()];
            for a in &spec.args {
                argv.push(CString::new(a.as_bytes()).unwrap());
            }
            let mut envp: Vec<CString> = Vec::new();
            for (k, v) in &spec.env {
                envp.push(CString::new(format!("{k}={v}")).unwrap());
            }
            let argv_ptrs: Vec<*const libc::c_char> = argv
                .iter()
                .map(|c| c.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();
            let envp_ptrs: Vec<*const libc::c_char> = envp
                .iter()
                .map(|c| c.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect();
            unsafe {
                libc::execve(prog_c.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
                libc::_exit(124);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyKind;

    #[test]
    fn attestation_table_roundtrips() {
        let t = AttestationTable::new();
        let a = Attestation {
            pid: 10,
            policy: PolicyKind::Restricted,
            exe_hash_hex: "x".repeat(64),
            started_utc: 1,
            program: PathBuf::from("/bin/true"),
        };
        t.insert(a.clone());
        assert_eq!(t.get(10), Some(a.clone()));
        assert_eq!(t.forget(10), Some(a));
        assert!(t.is_empty());
    }

    #[test]
    fn validates_missing_program() {
        let spec = LaunchSpec::new("/definitely/not/here/xyz", PolicyKind::Restricted);
        let l = SeccompLauncher::new();
        match l.launch(&spec) {
            Err(IsolationError::ProgramMissing(_)) => {}
            other => panic!("expected ProgramMissing, got {other:?}"),
        }
    }
}
