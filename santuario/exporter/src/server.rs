//! Hyper 0.14 HTTP server. One route: `GET /metrics`.
//!
//! Why hyper directly and not axum: the exporter has a single endpoint
//! and a single piece of shared state (the gRPC client). Axum would add
//! ~80 transitive dependencies and a second hyper major version into
//! the workspace. Hyper 0.14 is already pulled in by tonic 0.10 -- we
//! reuse it for free.
//!
//! Behaviour:
//!   GET /metrics  -> 200 with Prometheus text body
//!   GET /         -> 200 with a one-line ASCII pointer to /metrics
//!   anything else -> 404
//!
//! Failure on the gRPC fetch path returns a 200 anyway, with an
//! exporter-internal counter `santuario_exporter_scrape_errors_total`
//! incremented. Returning 5xx would cause Prometheus to treat the
//! whole scrape as failed and lose the up-time series, which is the
//! opposite of what observability wants.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};

use crate::admin_client::AdminGrpcClient;
use crate::render::{self, MetricsSnapshot, NodeIdentity};

/// Shared exporter state. Owned by the hyper service factory and cloned
/// per-connection (Arc bump only).
#[derive(Clone)]
pub struct ExporterState {
    pub client: AdminGrpcClient,
    pub identity: NodeIdentity,
    pub scrape_errors: Arc<AtomicU64>,
    pub scrapes_total: Arc<AtomicU64>,
}

impl ExporterState {
    pub fn new(client: AdminGrpcClient, identity: NodeIdentity) -> Self {
        Self {
            client,
            identity,
            scrape_errors: Arc::new(AtomicU64::new(0)),
            scrapes_total: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Bind and serve until `shutdown` resolves (typically Ctrl-C). Returns
/// when the server has fully drained.
pub async fn serve(addr: SocketAddr, state: ExporterState) -> anyhow::Result<()> {
    let make_svc = make_service_fn(move |_conn| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle(req, state).await) }
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);
    log::info!("santuario-exporter HTTP listening on http://{}/metrics", addr);

    let graceful = server.with_graceful_shutdown(async {
        // Cross-platform Ctrl-C. tokio::signal::ctrl_c is the right
        // primitive on both Windows (CTRL_C_EVENT) and Unix (SIGINT).
        let _ = tokio::signal::ctrl_c().await;
        log::info!("Ctrl-C received, draining HTTP connections");
    });

    graceful.await?;
    Ok(())
}

async fn handle(req: Request<Body>, state: ExporterState) -> Response<Body> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => render_metrics(state).await,
        (&Method::GET, "/") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Body::from(
                "santuario-exporter -- scrape /metrics for Prometheus text format\n",
            ))
            .unwrap_or_else(|_| internal_error()),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Body::from("404 not found\n"))
            .unwrap_or_else(|_| internal_error()),
    }
}

async fn render_metrics(state: ExporterState) -> Response<Body> {
    state.scrapes_total.fetch_add(1, Ordering::Relaxed);

    // Pull from the signer. If it's down, render an EMPTY snapshot so
    // the exporter's own self-metrics still appear in the body and
    // Prometheus's `up{job="santuario"}` reflects the success of the
    // SCRAPE (which is what's nominal -- the exporter is alive even if
    // the signer isn't).
    let snapshot = match state.client.fetch_snapshot().await {
        Ok(snap) => snap,
        Err(err) => {
            state.scrape_errors.fetch_add(1, Ordering::Relaxed);
            log::warn!(
                "Admin GetMetrics failed against {}: {:#}",
                state.client.endpoint_uri(),
                err
            );
            MetricsSnapshot::default()
        }
    };

    let mut body = render::render(&snapshot, &state.identity);
    append_self_metrics(&mut body, &state);

    Response::builder()
        .status(StatusCode::OK)
        // Prometheus is lenient on Content-Type but the canonical
        // text-format MIME is "text/plain; version=0.0.4".
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(body))
        .unwrap_or_else(|_| internal_error())
}

/// Self-metrics about the exporter process. These DO NOT round-trip
/// through the Admin gRPC -- they live in the exporter's own atomics --
/// because we need them to be available even when the gRPC fetch fails.
fn append_self_metrics(out: &mut String, state: &ExporterState) {
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "# HELP santuario_exporter_scrapes_total Total /metrics requests served (200 only)."
    );
    let _ = writeln!(out, "# TYPE santuario_exporter_scrapes_total counter");
    let _ = writeln!(
        out,
        "santuario_exporter_scrapes_total {}",
        state.scrapes_total.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "# HELP santuario_exporter_scrape_errors_total Scrapes where the upstream Admin RPC failed."
    );
    let _ = writeln!(out, "# TYPE santuario_exporter_scrape_errors_total counter");
    let _ = writeln!(
        out,
        "santuario_exporter_scrape_errors_total {}",
        state.scrape_errors.load(Ordering::Relaxed)
    );
}

fn internal_error() -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from("500 internal\n"))
        .expect("static 500 response always builds")
}
