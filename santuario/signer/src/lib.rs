//! santuario-signer — library surface.
//!
//! The binary `santuario-signer` (see `src/main.rs`) is the gRPC
//! server process. This library exposes the same internal modules so
//! integration tests in `tests/` can construct services directly —
//! in particular the v0.3.0 Admin service — without having to spawn
//! and orchestrate the binary over UDS.
//!
//! The split is deliberately thin: no re-exports at the crate root,
//! no convenience shims. Test code imports the concrete types from
//! their module paths (`santuario_signer::admin::AdminService`,
//! `santuario_signer::metrics::MetricsRegistry`, …).
//!
//! Generated gRPC code for the v0.2.0 Signer service lives under
//! `santuario::signer::v1`. The v0.3.0 Admin service's generated code
//! lives inside `admin::pb` (see `admin.rs`); this mirrors the
//! protocol's package layout (`santuario.signer.v1`,
//! `santuario.admin.v1`).

pub mod admin;
pub mod attestation;
pub mod keystore;
pub mod metrics;
pub mod peers;
pub mod recovery;
pub mod sentinel_metrics;

pub mod santuario {
    pub mod signer {
        pub mod v1 {
            tonic::include_proto!("santuario.signer.v1");
        }
    }
}
