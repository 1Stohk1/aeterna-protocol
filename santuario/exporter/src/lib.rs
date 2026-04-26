//! AETERNA v0.3.0 "Oculus" — Prometheus exporter library.
//!
//! Module map:
//!
//! ```text
//!   admin_proto   -> generated tonic client for santuario.admin.v1
//!   admin_client  -> thin wrapper that adds connect-on-demand + retry
//!   catalog       -> static lookup table of "well-known" registry keys
//!                    paired with HELP text + Prometheus type
//!   render        -> pure function: AdminMetrics -> Prometheus text
//!                    format (no I/O, fully unit-tested)
//!   server        -> hyper 0.14 HTTP server exposing GET /metrics
//! ```
//!
//! The library split exists so `render` is exercised by deterministic
//! unit tests using synthetic snapshots. `main.rs` is the wiring layer.

pub mod admin_proto {
    // tonic-build emits the package as `santuario.admin.v1`, which becomes
    // a nested module path. We re-export the leaf module under a friendlier
    // name so callers say `admin_proto::AdminClient` rather than
    // `admin_proto::santuario::admin::v1::admin_client::AdminClient`.
    tonic::include_proto!("santuario.admin.v1");
}

pub mod admin_client;
pub mod catalog;
pub mod render;
pub mod server;
