//! gVisor workload launcher alias for Linux.
//!
//! Replaces the old seccomp-bpf filter launcher to isolate processes inside
//! user-space containers running runsc.

#![cfg(target_os = "linux")]

use std::sync::Mutex;
use crate::Attestation;

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

pub type SeccompLauncher = crate::gvisor::GvisorLauncher;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PolicyKind, LaunchSpec, Launcher, IsolationError};
    use std::path::PathBuf;

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
