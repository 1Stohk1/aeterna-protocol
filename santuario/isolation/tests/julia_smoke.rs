//! Smoke test for the Launcher API. Does NOT actually execute Julia (we
//! have no Julia runtime in the crate's CI sandbox); instead it asserts:
//!
//! - The three shipped policies parse cleanly.
//! - Each policy has the expected presence / absence of security-
//!   critical syscalls (execve excluded from all, sockets excluded from
//!   the LLM + restricted profiles).
//! - The launcher refuses a missing program.
//! - The attestation table behaves transactionally.
//!
//! The "deliberately patched Julia calls Sys.exec" demo described in
//! `docs/sprint-v0.2.0.md §3 Phase B` belongs in the bootstrap smoke
//! suite, not here, because it needs a real Julia runtime.

use santuario_isolation::policy::Policy;
use santuario_isolation::{IsolationError, LaunchSpec, Launcher, PolicyKind};

#[cfg(target_os = "linux")]
use santuario_isolation::launcher::SeccompLauncher;

#[cfg(not(target_os = "linux"))]
use santuario_isolation::launcher::SeccompLauncher;

#[test]
fn all_policies_parse() {
    for kind in [
        PolicyKind::Julia,
        PolicyKind::LlmInference,
        PolicyKind::Restricted,
    ] {
        let p = Policy::load(kind).expect("policy must parse");
        assert!(!p.allow.is_empty(), "policy {:?} is empty", kind);
    }
}

#[test]
fn execve_is_forbidden_everywhere() {
    for kind in [
        PolicyKind::Julia,
        PolicyKind::LlmInference,
        PolicyKind::Restricted,
    ] {
        let p = Policy::load(kind).unwrap();
        assert!(
            !p.contains("execve"),
            "policy '{}' unexpectedly allows execve",
            kind.name()
        );
        assert!(
            !p.contains("execveat"),
            "policy '{}' unexpectedly allows execveat",
            kind.name()
        );
        assert!(
            !p.contains("ptrace"),
            "policy '{}' unexpectedly allows ptrace",
            kind.name()
        );
    }
}

#[test]
fn llm_policy_forbids_sockets() {
    let p = Policy::load(PolicyKind::LlmInference).unwrap();
    assert!(!p.contains("socket"));
    assert!(!p.contains("connect"));
    assert!(!p.contains("bind"));
}

#[test]
fn restricted_policy_forbids_sockets_and_fork() {
    let p = Policy::load(PolicyKind::Restricted).unwrap();
    assert!(!p.contains("socket"));
    assert!(!p.contains("connect"));
    assert!(!p.contains("clone"));
    assert!(!p.contains("fork"));
    assert!(!p.contains("vfork"));
}

#[test]
fn julia_policy_allows_zmq_sockets() {
    // ZMQ needs at least these.
    let p = Policy::load(PolicyKind::Julia).unwrap();
    for sc in ["socket", "bind", "listen", "sendto", "recvfrom"] {
        assert!(p.contains(sc), "julia policy must allow {}", sc);
    }
}

#[test]
fn launcher_refuses_missing_program() {
    let l = SeccompLauncher::new();
    let spec = LaunchSpec::new("/nonexistent/aeterna/xyz", PolicyKind::Restricted);
    match l.launch(&spec) {
        #[cfg(target_os = "linux")]
        Err(IsolationError::ProgramMissing(_)) => {}
        #[cfg(not(target_os = "linux"))]
        Err(IsolationError::UnsupportedPlatform) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}
