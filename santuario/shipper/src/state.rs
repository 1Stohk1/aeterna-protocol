use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::client::{build_pinned_client, push_segment};
use crate::config::ShipperConfig;
use crate::error::{Error, Result};
use crate::segments::find_finalized;

pub struct Shipper {
    config: ShipperConfig,
    audit_dir: PathBuf,
}

impl Shipper {
    pub fn new(config: ShipperConfig, audit_dir: PathBuf) -> Self {
        Self { config, audit_dir }
    }

    /// Runs the main shipping loop until the shutdown receiver is triggered or a hard stop occurs.
    pub async fn run(&self, mut shutdown: tokio::sync::oneshot::Receiver<()>) -> Result<()> {
        if !self.config.enabled {
            log::info!("Shipper is disabled. Exiting shipping loop.");
            return Ok(());
        }

        // Validate config before launching
        self.config.validate()?;

        log::info!(
            "Starting Remote Log Shipper daemon. Endpoint: {}, Poll interval: {}s",
            self.config.endpoint_url,
            self.config.poll_interval_seconds
        );

        // Build the HTTPS client with cert pinning
        let client = build_pinned_client(&self.config.endpoint_pin_sha256)?;

        // Map keeping track of retry counters per segment_id
        let mut retries: HashMap<u64, u32> = HashMap::new();

        loop {
            // 1. Scan the audit directory for finalized segments
            let segments = match find_finalized(&self.audit_dir) {
                Ok(segs) => segs,
                Err(e) => {
                    log::error!("Error scanning audit log directory: {:?}", e);
                    Vec::new()
                }
            };

            for segment in segments {
                let segment_id = segment.segment_id;

                // Skip if this segment has exceeded max retries
                if let Some(&count) = retries.get(&segment_id) {
                    if count >= self.config.max_retries_per_segment {
                        continue;
                    }
                }

                // Check if the segment was already pushed using the .pushed sidecar file
                let pushed_marker = marker_path(&segment.path);
                if pushed_marker.exists() {
                    continue;
                }

                log::info!("Discovered unsent segment: {segment_id}. Preparing upload...");

                // Read segment data
                let data = match std::fs::read(&segment.path) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        log::error!("Failed to read segment file {}: {:?}", segment.path.display(), e);
                        continue;
                    }
                };

                // Perform upload with cert-pinning verified client
                match push_segment(&client, &self.config.endpoint_url, segment_id, data).await {
                    Ok(_) => {
                        log::info!("Successfully shipped segment {segment_id}. Writing marker file.");
                        let metadata = serde_json::json!({
                            "pushed_at": chrono::Utc::now().to_rfc3339(),
                            "size_bytes": segment.size_bytes,
                            "sha256": hash_bytes(&std::fs::read(&segment.path).unwrap_or_default()),
                        });
                        if let Err(e) = std::fs::write(&pushed_marker, metadata.to_string()) {
                            log::error!("Failed to write pushed marker file {}: {:?}", pushed_marker.display(), e);
                        }
                        // Clear retries on success
                        retries.remove(&segment_id);
                    }
                    Err(Error::CertPinMismatch { expected, observed }) => {
                        log::error!(
                            "CRITICAL: TLS cert pin mismatch aborting shipper! Expected: {}, Observed: {}",
                            expected,
                            observed
                        );
                        // Hard stop on cert pin mismatch
                        return Err(Error::CertPinMismatch { expected, observed });
                    }
                    Err(e) => {
                        let count = retries.entry(segment_id).or_insert(0);
                        *count += 1;
                        log::warn!(
                            "Transient failure shipping segment {} (attempt {}/{}): {:?}",
                            segment_id,
                            count,
                            self.config.max_retries_per_segment,
                            e
                        );

                        if *count >= self.config.max_retries_per_segment {
                            log::error!(
                                "Segment {} reached max retries. Marking as permanently failed for this session.",
                                segment_id
                            );
                        }

                        // Sleep using back-off interval on errors before processing next segments
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(self.config.back_off_seconds)) => {}
                            _ = &mut shutdown => {
                                log::info!("Shutdown signal received during back-off. Exiting.");
                                return Ok(());
                            }
                        }
                        break; // Break the inner loop to re-scan
                    }
                }
            }

            // Sleep for the poll interval or exit on shutdown signal
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(self.config.poll_interval_seconds)) => {}
                _ = &mut shutdown => {
                    log::info!("Shutdown signal received. Exiting shipping loop.");
                    return Ok(());
                }
            }
        }
    }
}

/// Helper to generate the sidecar marker path: e.g. `000042.sigillum` -> `000042.sigillum.pushed`
fn marker_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".pushed");
    PathBuf::from(s)
}

/// Helper to compute SHA-256 hash of bytes
fn hash_bytes(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tempfile::tempdir;

    fn write_test_segment(path: &Path, segment_id: u64) {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"SIGILLUM-v1\0\0\0\0\0");
        buf.extend_from_slice(&segment_id.to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        std::fs::write(path, buf).unwrap();
    }

    #[tokio::test]
    async fn test_shipper_run_loop() {
        let tmp = tempdir().unwrap();
        let audit_dir = tmp.path().to_path_buf();

        // Write a test segment (ID = 7)
        let seg_path = audit_dir.join("000007.sigillum");
        write_test_segment(&seg_path, 7);

        // Bind a local TCP listener to act as HTTP endpoint
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config = ShipperConfig {
            enabled: true,
            endpoint_url: format!("http://{}", addr),
            endpoint_pin_sha256: "00".repeat(32), // dummy pin
            poll_interval_seconds: 1,
            back_off_seconds: 1,
            max_retries_per_segment: 3,
        };

        let shipper = Shipper::new(config, audit_dir.clone());

        // Spawn mock server task
        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let req_str = String::from_utf8_lossy(&buf[..n]);

            assert!(req_str.starts_with("POST /000007.sigillum HTTP/1.1"));

            // Write 200 OK
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        // Run the shipper in a separate task with shutdown control
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let shipper_task = tokio::spawn(async move {
            shipper.run(shutdown_rx).await
        });

        // Wait a bit for shipper to run and complete shipping the segment
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Check if marker file exists
        let marker = audit_dir.join("000007.sigillum.pushed");
        assert!(marker.exists(), "Pushed marker sidecar file should be written");

        // Verify marker metadata
        let marker_content = std::fs::read_to_string(&marker).unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&marker_content).unwrap();
        assert!(metadata.get("pushed_at").is_some());
        assert_eq!(metadata.get("size_bytes").unwrap().as_u64().unwrap(), 40); // 16 + 8 + 16 = 40 bytes
        assert!(metadata.get("sha256").is_some());

        // Trigger shutdown and wait for shipper task
        let _ = shutdown_tx.send(());
        let shipper_res = shipper_task.await.unwrap();
        assert!(shipper_res.is_ok());

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_shipper_gap_recovery() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let tmp = tempdir().unwrap();
        let audit_dir = tmp.path().to_path_buf();

        // Write two test segments (ID = 8 and ID = 9)
        let seg8_path = audit_dir.join("000008.sigillum");
        let seg9_path = audit_dir.join("000009.sigillum");
        write_test_segment(&seg8_path, 8);
        write_test_segment(&seg9_path, 9);

        // Bind local TCP listener
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint_url = format!("http://{}", addr);

        let is_online = Arc::new(AtomicBool::new(false));
        let is_online_clone = is_online.clone();

        // Spawn mock server task that loops, accepting connections
        let server_task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };

                if is_online_clone.load(Ordering::SeqCst) {
                    let mut buf = [0u8; 1024];
                    let n = match socket.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => continue,
                    };
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    if req_str.starts_with("POST /000008.sigillum HTTP/1.1") || req_str.starts_with("POST /000009.sigillum HTTP/1.1") {
                        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                } else {
                    // Send 503 Service Unavailable when offline
                    let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
                    let _ = socket.write_all(response.as_bytes()).await;
                }
            }
        });

        let config = ShipperConfig {
            enabled: true,
            endpoint_url,
            endpoint_pin_sha256: "00".repeat(32),
            poll_interval_seconds: 1,
            back_off_seconds: 1,
            max_retries_per_segment: 5,
        };

        let shipper = Shipper::new(config, audit_dir.clone());

        // Run the shipper in a separate task with shutdown control
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let shipper_task = tokio::spawn(async move {
            shipper.run(shutdown_rx).await
        });

        // Wait to verify no `.pushed` files exist yet (shipper hits 503 error)
        tokio::time::sleep(Duration::from_millis(500)).await;

        let marker8 = audit_dir.join("000008.sigillum.pushed");
        let marker9 = audit_dir.join("000009.sigillum.pushed");
        assert!(!marker8.exists());
        assert!(!marker9.exists());

        // Now, bring the server online by toggling the flag
        is_online.store(true, Ordering::SeqCst);

        // Wait for shipper to retry, detect the server is back, and successfully push the segments
        // We poll marker existence for up to 6 seconds (generous timeout)
        let mut success = false;
        for _ in 0..60 {
            if marker8.exists() && marker9.exists() {
                success = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(success, "Pushed marker files should be written once server comes online");

        // Verify marker metadata for segment 8
        let marker8_content = std::fs::read_to_string(&marker8).unwrap();
        let metadata8: serde_json::Value = serde_json::from_str(&marker8_content).unwrap();
        assert!(metadata8.get("pushed_at").is_some());
        assert_eq!(metadata8.get("size_bytes").unwrap().as_u64().unwrap(), 40);

        // Verify marker metadata for segment 9
        let marker9_content = std::fs::read_to_string(&marker9).unwrap();
        let metadata9: serde_json::Value = serde_json::from_str(&marker9_content).unwrap();
        assert!(metadata9.get("pushed_at").is_some());
        assert_eq!(metadata9.get("size_bytes").unwrap().as_u64().unwrap(), 40);

        // Stop the shipper
        let _ = shutdown_tx.send(());
        let shipper_res = shipper_task.await.unwrap();
        assert!(shipper_res.is_ok());

        // Stop the server task by aborting it
        server_task.abort();
    }
}
