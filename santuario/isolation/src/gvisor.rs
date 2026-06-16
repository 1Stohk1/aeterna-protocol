//! gVisor sandbox runner.
//!
//! Generates OCI specifications dynamically and executes workloads inside
//! a `runsc` sandbox using ptrace or KVM system call interceptors.

#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use serde::Serialize;

use crate::launcher::AttestationTable;
use crate::{hash_file, now_utc, Attestation, IsolationError, LaunchSpec, LaunchedChild, Launcher};

/// The gVisor launcher.
pub struct GvisorLauncher {
    pub table: AttestationTable,
    pub runsc_path: PathBuf,
    pub platform: String, // "ptrace" (default) or "kvm"
}

impl GvisorLauncher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(runsc_path: PathBuf, platform: String) -> Self {
        Self {
            table: AttestationTable::new(),
            runsc_path,
            platform,
        }
    }

    /// Generates the OCI specification (`config.json`) dynamically.
    fn build_oci_spec(&self, spec: &LaunchSpec, uid: u32, gid: u32) -> OciSpec {
        // Configure Bind Mounts (Host Paths -> Guest Paths)
        let mut mounts = vec![
            OciMount {
                destination: "/proc".to_string(),
                mount_type: "proc".to_string(),
                source: "proc".to_string(),
                options: Vec::new(),
            },
            OciMount {
                destination: "/dev".to_string(),
                mount_type: "tmpfs".to_string(),
                source: "tmpfs".to_string(),
                options: vec![
                    "nosuid".to_string(),
                    "strictatime".to_string(),
                    "mode=755".to_string(),
                    "size=65536k".to_string(),
                ],
            },
            OciMount {
                destination: "/sys".to_string(),
                mount_type: "sysfs".to_string(),
                source: "sysfs".to_string(),
                options: vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "nodev".to_string(),
                    "ro".to_string(),
                ],
            },
        ];

        // Bind mount system files (libraries, dynamic linker)
        let system_paths = vec!["/lib", "/lib64", "/usr", "/bin", "/sbin", "/etc"];
        for path in system_paths {
            if Path::new(path).exists() {
                mounts.push(OciMount {
                    destination: path.to_string(),
                    mount_type: "bind".to_string(),
                    source: path.to_string(),
                    options: vec![
                        "ro".to_string(),
                        "nosuid".to_string(),
                        "nodev".to_string(),
                        "bind".to_string(),
                    ],
                });
            }
        }

        // Bind mount program parent folder
        if let Some(parent) = spec.program.parent() {
            if let Ok(abs_parent) = fs::canonicalize(parent) {
                let dest = abs_parent.to_string_lossy().to_string();
                mounts.push(OciMount {
                    destination: dest.clone(),
                    mount_type: "bind".to_string(),
                    source: abs_parent.to_string_lossy().to_string(),
                    options: vec![
                        "ro".to_string(),
                        "nosuid".to_string(),
                        "nodev".to_string(),
                        "bind".to_string(),
                    ],
                });
            }
        }

        // Bind mount workdir or workspace (read-only)
        let current_dir = fs::canonicalize(".").unwrap_or_else(|_| PathBuf::from("."));
        let workspace_path = current_dir.to_string_lossy().to_string();
        mounts.push(OciMount {
            destination: workspace_path.clone(),
            mount_type: "bind".to_string(),
            source: workspace_path,
            options: vec![
                "ro".to_string(),
                "nosuid".to_string(),
                "nodev".to_string(),
                "bind".to_string(),
            ],
        });

        // Bind mount Spools (Read-Write)
        let vault_dir = current_dir.join("santuario/vault");
        let inbound_dir = vault_dir.join("inbound");
        let outbound_dir = vault_dir.join("outbound");

        for dir in &[inbound_dir, outbound_dir] {
            if dir.exists() {
                let abs_dir = fs::canonicalize(dir).unwrap_or_else(|_| dir.clone());
                let dest = abs_dir.to_string_lossy().to_string();
                mounts.push(OciMount {
                    destination: dest.clone(),
                    mount_type: "bind".to_string(),
                    source: abs_dir.to_string_lossy().to_string(),
                    options: vec![
                        "rw".to_string(),
                        "nosuid".to_string(),
                        "nodev".to_string(),
                        "bind".to_string(),
                    ],
                });
            }
        }

        // Construct OCI Process spec
        let mut args = vec![spec.program.to_string_lossy().to_string()];
        args.extend(spec.args.clone());

        let mut env = vec![
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        ];
        for (k, v) in &spec.env {
            env.push(format!("{}={}", k, v));
        }

        let cwd = spec.workdir.as_ref()
            .map(|wd| wd.to_string_lossy().to_string())
            .unwrap_or_else(|| "/".to_string());

        OciSpec {
            oci_version: "1.0.0".to_string(),
            process: OciProcess {
                terminal: false,
                user: OciUser { uid, gid },
                args,
                env,
                cwd,
                capabilities: OciCapabilities {
                    bounding: Vec::new(),
                    effective: Vec::new(),
                    inheritable: Vec::new(),
                    permitted: Vec::new(),
                },
                no_new_privileges: true,
            },
            root: OciRoot {
                path: "rootfs".to_string(),
                readonly: true,
            },
            mounts,
            linux: OciLinux {
                namespaces: vec![
                    OciNamespace { ns_type: "pid".to_string() },
                    OciNamespace { ns_type: "ipc".to_string() },
                    OciNamespace { ns_type: "uts".to_string() },
                    OciNamespace { ns_type: "mount".to_string() },
                    OciNamespace { ns_type: "network".to_string() }, // Isolate network stack
                ],
            },
        }
    }
}

impl Default for GvisorLauncher {
    fn default() -> Self {
        Self::with_options(PathBuf::from("runsc"), "ptrace".to_string())
    }
}

// OCI Spec structure definitions
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OciSpec {
    oci_version: String,
    process: OciProcess,
    root: OciRoot,
    mounts: Vec<OciMount>,
    linux: OciLinux,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OciProcess {
    terminal: bool,
    user: OciUser,
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    capabilities: OciCapabilities,
    no_new_privileges: bool,
}

#[derive(Serialize)]
struct OciUser {
    uid: u32,
    gid: u32,
}

#[derive(Serialize)]
struct OciCapabilities {
    bounding: Vec<String>,
    effective: Vec<String>,
    inheritable: Vec<String>,
    permitted: Vec<String>,
}

#[derive(Serialize)]
struct OciRoot {
    path: String,
    readonly: bool,
}

#[derive(Serialize)]
struct OciMount {
    destination: String,
    #[serde(rename = "type")]
    mount_type: String,
    source: String,
    options: Vec<String>,
}

#[derive(Serialize)]
struct OciLinux {
    namespaces: Vec<OciNamespace>,
}

#[derive(Serialize)]
struct OciNamespace {
    #[serde(rename = "type")]
    ns_type: String,
}

impl Launcher for GvisorLauncher {
    fn launch(&self, spec: &LaunchSpec) -> Result<LaunchedChild, IsolationError> {
        // 1. Basic validations
        if !spec.program.exists() {
            return Err(IsolationError::ProgramMissing(spec.program.clone()));
        }
        let exe_hash_hex = hash_file(&spec.program)?;

        // 2. Prepare OCI bundle directory under /tmp
        let timestamp = now_utc();
        let container_id = format!("santuario-sandbox-{}-{}", timestamp, rand::random::<u32>());
        let bundle_dir = std::env::temp_dir().join(format!("santuario-bundle-{}", container_id));
        fs::create_dir_all(&bundle_dir)?;

        let rootfs_dir = bundle_dir.join("rootfs");
        fs::create_dir_all(&rootfs_dir)?;

        // 3. Resolve Current UID/GID via libc
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // 4. Generate spec dynamically using helper
        let spec_json = self.build_oci_spec(spec, uid, gid);

        // Write config.json
        let config_file = File::create(bundle_dir.join("config.json"))?;
        serde_json::to_writer_pretty(config_file, &spec_json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // 5. Spawn runsc process
        log::info!("Spawning gVisor sandbox container {} via {:?}", container_id, self.runsc_path);
        let mut child = Command::new(&self.runsc_path)
            .arg("--rootless=true")
            .arg(format!("--platform={}", self.platform))
            .arg("run")
            .arg("--bundle")
            .arg(&bundle_dir)
            .arg(&container_id)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| IsolationError::Fork(e.to_string()))?;

        let pid = child.id() as i32;

        let att = Attestation {
            pid,
            policy: spec.policy,
            exe_hash_hex,
            started_utc: timestamp,
            program: spec.program.clone(),
        };

        self.table.insert(att.clone());

        // Spawn a background thread to clean up the bundle folder once the child exits
        std::thread::spawn(move || {
            let _ = child.wait();
            log::info!("gVisor sandbox container {} exited. Cleaning up bundle directory.", container_id);
            let _ = fs::remove_dir_all(bundle_dir);
        });

        Ok(LaunchedChild { attestation: att })
    }

    fn attest(&self, pid: i32) -> Result<Attestation, IsolationError> {
        let att = self.table.get(pid).ok_or(IsolationError::UnknownPid(pid))?;
        
        // Check if process is still running
        if !Path::new(&format!("/proc/{}", pid)).exists() {
            return Err(IsolationError::Dead(pid));
        }

        // Verify the binary on disk hasn't changed since launch
        let current_hash = hash_file(&att.program)?;
        if current_hash != att.exe_hash_hex {
            return Err(IsolationError::Seccomp(format!(
                "pid {pid}: on-disk exe hash drifted since launch (expected {}, got {current_hash})",
                att.exe_hash_hex
            )));
        }

        Ok(att)
    }

    fn is_enforcing(&self) -> bool {
        // gVisor is enforcing if we can run it
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyKind;
    use std::path::PathBuf;

    #[test]
    fn test_gvisor_launcher_new_default() {
        let l = GvisorLauncher::new();
        assert_eq!(l.runsc_path, PathBuf::from("runsc"));
        assert_eq!(l.platform, "ptrace");
        assert!(l.is_enforcing());
    }

    #[test]
    fn test_gvisor_launcher_with_options() {
        let l = GvisorLauncher::with_options(PathBuf::from("/usr/local/bin/runsc"), "kvm".to_string());
        assert_eq!(l.runsc_path, PathBuf::from("/usr/local/bin/runsc"));
        assert_eq!(l.platform, "kvm");
    }

    #[test]
    fn test_build_oci_spec() {
        let launcher = GvisorLauncher::new();
        // Create a temporary file to act as the program
        let temp_dir = tempfile::tempdir().unwrap();
        let program_path = temp_dir.path().join("dummy_program");
        fs::write(&program_path, b"dummy content").unwrap();

        let spec = LaunchSpec::new(&program_path, PolicyKind::Restricted)
            .with_arg("--foo")
            .with_arg("bar")
            .with_env("KEY", "VALUE")
            .with_workdir("/custom/workdir");

        let oci_spec = launcher.build_oci_spec(&spec, 1000, 1000);

        assert_eq!(oci_spec.oci_version, "1.0.0");
        assert_eq!(oci_spec.process.args[0], program_path.to_string_lossy().to_string());
        assert_eq!(oci_spec.process.args[1], "--foo");
        assert_eq!(oci_spec.process.args[2], "bar");
        assert!(oci_spec.process.env.iter().any(|e| e == "KEY=VALUE"));
        assert_eq!(oci_spec.process.cwd, "/custom/workdir");
        assert_eq!(oci_spec.process.user.uid, 1000);
        assert_eq!(oci_spec.process.user.gid, 1000);

        // Verify standard mounts
        let mount_destinations: Vec<&str> = oci_spec.mounts.iter().map(|m| m.destination.as_str()).collect();
        assert!(mount_destinations.contains(&"/proc"));
        assert!(mount_destinations.contains(&"/dev"));
        assert!(mount_destinations.contains(&"/sys"));

        // System mounts (if they exist on the test host)
        let system_paths = vec!["/lib", "/lib64", "/usr", "/bin", "/sbin", "/etc"];
        for path in system_paths {
            if Path::new(path).exists() {
                let m = oci_spec.mounts.iter().find(|m| m.destination == path).unwrap();
                assert_eq!(m.mount_type, "bind");
                assert!(m.options.contains(&"ro".to_string()));
                assert!(m.options.contains(&"bind".to_string()));
            }
        }

        // Program parent mount
        let program_parent = fs::canonicalize(program_path.parent().unwrap()).unwrap();
        let parent_dest = program_parent.to_string_lossy().to_string();
        let parent_mount = oci_spec.mounts.iter().find(|m| m.destination == parent_dest).unwrap();
        assert_eq!(parent_mount.mount_type, "bind");
        assert!(parent_mount.options.contains(&"ro".to_string()));

        // Network isolating namespaces should be included
        let ns_types: Vec<&str> = oci_spec.linux.namespaces.iter().map(|n| n.ns_type.as_str()).collect();
        assert!(ns_types.contains(&"network"));
        assert!(ns_types.contains(&"pid"));
        assert!(ns_types.contains(&"ipc"));
        assert!(ns_types.contains(&"uts"));
        assert!(ns_types.contains(&"mount"));
    }
}
