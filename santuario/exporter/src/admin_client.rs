//! Thin wrapper around the generated tonic `AdminClient`.
//!
//! Two responsibilities:
//!   1. Hide the proto types from the rest of the exporter -- callers
//!      get back a `render::MetricsSnapshot`, never a tonic message.
//!   2. Connect-on-demand semantics. We do NOT hold a long-lived
//!      gRPC channel because the signer process can restart out from
//!      under us (Phase E bootstrap brings it up and down). Each scrape
//!      dials fresh; tonic's HTTP/2 channel has a fast path for
//!      already-resolved endpoints so the cost is small.
//!
//! Failure mode: any error (signer down, port unbound, mid-flight RST)
//! returns `Err`. The HTTP layer translates that into an empty snapshot
//! plus a `santuario_exporter_scrape_errors_total` counter increment so
//! the operator can graph "how often is the signer unreachable".

use std::time::Duration;

use anyhow::{Context, Result};
use tonic::transport::Endpoint;

use crate::admin_proto::admin_client::AdminClient;
use crate::admin_proto::GetMetricsRequest;
use crate::render::MetricsSnapshot;

/// gRPC client. Cheap to construct; clones the endpoint URI only.
#[derive(Debug, Clone)]
pub struct AdminGrpcClient {
    endpoint_uri: String,
    connect_timeout: Duration,
    request_timeout: Duration,
}

impl AdminGrpcClient {
    /// `host_port` looks like `127.0.0.1:50051`. We prepend `http://` for
    /// tonic; the Admin gRPC channel is plaintext on loopback (the
    /// signing path itself is on the same listener and is also plaintext
    /// on loopback -- see SPRINT-v0.3.0 §7.1, no TLS in v0.3 because
    /// the operator surfaces are 127.0.0.1-bound by default).
    pub fn new(host_port: impl Into<String>) -> Self {
        Self {
            endpoint_uri: format!("http://{}", host_port.into()),
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(5),
        }
    }

    pub fn endpoint_uri(&self) -> &str {
        &self.endpoint_uri
    }

    /// Single round-trip: connect, GetMetrics, drop the channel.
    pub async fn fetch_snapshot(&self) -> Result<MetricsSnapshot> {
        let endpoint = Endpoint::from_shared(self.endpoint_uri.clone())
            .with_context(|| format!("invalid Admin endpoint URI: {}", self.endpoint_uri))?
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout);

        let mut client = AdminClient::connect(endpoint)
            .await
            .with_context(|| format!("connecting to {}", self.endpoint_uri))?;

        let resp = client
            .get_metrics(GetMetricsRequest {})
            .await
            .context("GetMetrics RPC failed")?
            .into_inner();

        Ok(MetricsSnapshot {
            node_id: resp.node_id,
            schema_version: resp.schema_version,
            ts_utc: resp.ts_utc,
            counters: resp.counters,
            gauges: resp.gauges,
        })
    }
}
