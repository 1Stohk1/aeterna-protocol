//! Policy loader. Each seccomp-bpf allowlist is shipped as a newline-
//! delimited text file under `santuario/isolation/policies/`. The format
//! is intentionally trivial so an operator can audit it with `cat`:
//!
//! ```text
//! # lines beginning with '#' are comments, blank lines ignored
//! read
//! write
//! exit
//! exit_group
//! rt_sigreturn
//! ...
//! ```
//!
//! At runtime the launcher reads the file, derives the list of permitted
//! syscall numbers via `libseccomp::ScmpSyscall::from_name`, and installs
//! a filter whose default action is `ENOSYS` (so offending calls fail
//! loudly rather than silently return).
//!
//! This module is pure: it only parses the text file and returns a
//! validated `Policy`. The Linux-only launcher is the sole caller that
//! actually hands the policy to libseccomp.

use std::path::{Path, PathBuf};

use crate::{IsolationError, PolicyKind};

/// Parsed syscall allowlist for a given [`PolicyKind`].
#[derive(Debug, Clone)]
pub struct Policy {
    pub kind: PolicyKind,
    pub source: PathBuf,
    pub allow: Vec<String>,
}

impl Policy {
    /// Resolve the default policy file for `kind`. Uses
    /// `SANTUARIO_POLICY_DIR` if set, otherwise the compile-time
    /// `santuario/isolation/policies/` path.
    pub fn default_path(kind: PolicyKind) -> PathBuf {
        if let Ok(dir) = std::env::var("SANTUARIO_POLICY_DIR") {
            PathBuf::from(dir).join(format!("{}.bpf", kind.name()))
        } else {
            let manifest = env!("CARGO_MANIFEST_DIR");
            PathBuf::from(manifest)
                .join("policies")
                .join(format!("{}.bpf", kind.name()))
        }
    }

    pub fn load(kind: PolicyKind) -> Result<Self, IsolationError> {
        Self::load_from(kind, &Self::default_path(kind))
    }

    pub fn load_from(kind: PolicyKind, path: &Path) -> Result<Self, IsolationError> {
        if !path.exists() {
            return Err(IsolationError::PolicyMissing(path.display().to_string()));
        }
        let text = std::fs::read_to_string(path)?;
        let mut allow = Vec::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if !line.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(IsolationError::PolicyInvalid(format!(
                    "{}:{}: illegal characters in syscall name '{}'",
                    path.display(),
                    lineno + 1,
                    line
                )));
            }
            allow.push(line.to_string());
        }
        if allow.is_empty() {
            return Err(IsolationError::PolicyInvalid(format!(
                "{}: allowlist is empty",
                path.display()
            )));
        }
        // Deduplicate while preserving order.
        let mut seen = std::collections::HashSet::new();
        allow.retain(|s| seen.insert(s.clone()));
        Ok(Self {
            kind,
            source: path.to_path_buf(),
            allow,
        })
    }

    pub fn contains(&self, syscall: &str) -> bool {
        self.allow.iter().any(|s| s == syscall)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_simple_policy() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "# a comment").unwrap();
        writeln!(tmp, "read").unwrap();
        writeln!(tmp, "write # inline comment").unwrap();
        writeln!(tmp).unwrap();
        writeln!(tmp, "exit").unwrap();
        writeln!(tmp, "exit_group").unwrap();
        writeln!(tmp, "read").unwrap(); // dedup
        let p = Policy::load_from(PolicyKind::Restricted, tmp.path()).unwrap();
        assert_eq!(p.allow, vec!["read", "write", "exit", "exit_group"]);
        assert!(p.contains("read"));
        assert!(!p.contains("execve"));
    }

    #[test]
    fn rejects_illegal_syscall_name() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "bad syscall; rm -rf /").unwrap();
        let r = Policy::load_from(PolicyKind::Restricted, tmp.path());
        match r {
            Err(IsolationError::PolicyInvalid(_)) => {}
            other => panic!("expected PolicyInvalid, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_policy() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let r = Policy::load_from(PolicyKind::Restricted, tmp.path());
        match r {
            Err(IsolationError::PolicyInvalid(_)) => {}
            other => panic!("expected PolicyInvalid, got {other:?}"),
        }
    }
}
