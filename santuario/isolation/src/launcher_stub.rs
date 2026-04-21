//! Non-Linux stub launcher. Refuses every launch — nodes on non-Linux
//! targets cannot participate in signing (they run only as
//! `osservatore`). Compiled in `#[cfg(not(target_os = "linux"))]`.
//!
//! We still expose the same types so the rest of the workspace
//! (signer, critic, vault) compiles cross-platform.

#![cfg(not(target_os = "linux"))]

use crate::{Attestation, IsolationError, LaunchSpec, LaunchedChild, Launcher};

#[derive(Debug, Default, Clone)]
pub struct StubLauncher;

impl StubLauncher {
    pub fn new() -> Self {
        Self
    }
}

impl Launcher for StubLauncher {
    fn launch(&self, _spec: &LaunchSpec) -> Result<LaunchedChild, IsolationError> {
        Err(IsolationError::UnsupportedPlatform)
    }

    fn attest(&self, _pid: i32) -> Result<Attestation, IsolationError> {
        Err(IsolationError::UnsupportedPlatform)
    }

    fn is_enforcing(&self) -> bool {
        false
    }
}

/// Type alias so callers can `use santuario_isolation::launcher::SeccompLauncher`
/// regardless of target. On non-Linux hosts this is the stub.
pub type SeccompLauncher = StubLauncher;
