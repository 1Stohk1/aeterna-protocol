use std::sync::Arc;
use std::time::SystemTime;

use rustls::client::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, Error, ServerName, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::error::{Error as ShipperError, Result};

pub struct PinningVerifier {
    pub expected_pin_hex: String,
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        let mut hasher = Sha256::new();
        hasher.update(&end_entity.0);
        let hash = hasher.finalize();
        let hash_hex = hex::encode(hash);

        if hash_hex.eq_ignore_ascii_case(&self.expected_pin_hex) {
            Ok(ServerCertVerified::assertion())
        } else {
            log::error!(
                "TLS cert pin mismatch! Expected: {}, observed: {}",
                self.expected_pin_hex,
                hash_hex
            );
            Err(Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// Helper to build a reqwest::Client preconfigured with a custom rustls verifier
pub fn build_pinned_client(expected_pin_hex: &str) -> Result<reqwest::Client> {
    let verifier = PinningVerifier {
        expected_pin_hex: expected_pin_hex.to_string(),
    };

    let client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    let client = reqwest::Client::builder()
        .use_preconfigured_tls(client_config)
        .no_proxy()
        .build()
        .map_err(|e| ShipperError::Transport(e.to_string()))?;

    Ok(client)
}

/// Sends the segment raw bytes using HTTP POST to `<base_url>/<segment_id:06>.sigillum`
pub async fn push_segment(
    client: &reqwest::Client,
    base_url: &str,
    segment_id: u64,
    data: Vec<u8>,
) -> Result<()> {
    let url = format!("{}/{:06}.sigillum", base_url.trim_end_matches('/'), segment_id);

    let res = client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .body(data)
        .send()
        .await
        .map_err(|e| {
            let err_msg = e.to_string();
            // Map handshake/unknown issuer errors back to cert pin mismatch error
            if err_msg.contains("UnknownIssuer") || err_msg.contains("invalid certificate") {
                ShipperError::CertPinMismatch {
                    expected: "configured fingerprint".to_string(),
                    observed: "mismatched fingerprint during TLS handshake".to_string(),
                }
            } else {
                ShipperError::Transport(err_msg)
            }
        })?;

    let status = res.status().as_u16();
    if status >= 400 {
        let body = res
            .text()
            .await
            .unwrap_or_else(|_| "unreadable response body".to_string());
        return Err(ShipperError::RemoteRejected { status, body });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_pinning_verifier_success() {
        let dummy_cert_bytes = vec![1, 2, 3, 4, 5];
        let mut hasher = Sha256::new();
        hasher.update(&dummy_cert_bytes);
        let hash = hasher.finalize();
        let expected_pin = hex::encode(hash);

        let verifier = PinningVerifier {
            expected_pin_hex: expected_pin,
        };

        let cert = Certificate(dummy_cert_bytes);
        let name = ServerName::try_from("example.com").unwrap();

        let res = verifier.verify_server_cert(
            &cert,
            &[],
            &name,
            &mut std::iter::empty(),
            &[],
            SystemTime::now(),
        );

        assert!(res.is_ok());
    }

    #[test]
    fn test_pinning_verifier_mismatch() {
        let dummy_cert_bytes = vec![1, 2, 3, 4, 5];
        let verifier = PinningVerifier {
            expected_pin_hex: "00".repeat(32), // completely wrong hash
        };

        let cert = Certificate(dummy_cert_bytes);
        let name = ServerName::try_from("example.com").unwrap();

        let res = verifier.verify_server_cert(
            &cert,
            &[],
            &name,
            &mut std::iter::empty(),
            &[],
            SystemTime::now(),
        );

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(matches!(err, Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)));
    }

    #[tokio::test]
    async fn test_push_segment_success() {
        // Start a local HTTP mock server using TcpListener
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{}", addr);

        let segment_id = 42;
        let payload = vec![0xde, 0xad, 0xbe, 0xef];
        let payload_clone = payload.clone();

        // Spawn a background task to handle the request
        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            let req_str = String::from_utf8_lossy(&buf[..n]);

            // Verify the request details
            assert!(req_str.starts_with("POST /000042.sigillum HTTP/1.1"));
            assert!(req_str.contains("content-type: application/octet-stream"));
            
            // Check that the body matches
            if let Some(pos) = req_str.find("\r\n\r\n") {
                let body = &buf[pos + 4 .. n];
                assert_eq!(body, payload_clone.as_slice());
            } else {
                panic!("No body separator found in request");
            }

            // Write a successful HTTP response
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = reqwest::Client::new();
        let push_res = push_segment(&client, &base_url, segment_id, payload).await;
        assert!(push_res.is_ok());

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_push_segment_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{}", addr);

        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await.unwrap();

            // Write an HTTP error response
            let response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nforbidden";
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let client = reqwest::Client::new();
        let push_res = push_segment(&client, &base_url, 42, vec![1, 2, 3]).await;
        
        assert!(push_res.is_err());
        let err = push_res.unwrap_err();
        if let ShipperError::RemoteRejected { status, body } = err {
            assert_eq!(status, 403);
            assert_eq!(body, "forbidden");
        } else {
            panic!("Expected RemoteRejected error, got {:?}", err);
        }

        server_task.await.unwrap();
    }

    fn run_mock_https_server() -> (std::net::SocketAddr, std::thread::JoinHandle<std::result::Result<(), String>>) {
        use crate::mock_cert_data::{MOCK_CERT_DER, MOCK_KEY_DER};
        use std::io::{Read, Write};
        
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let cert = Certificate(MOCK_CERT_DER.to_vec());
            let key = rustls::PrivateKey(MOCK_KEY_DER.to_vec());
            let server_config = rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .map_err(|e| format!("Failed to create server config: {:?}", e))?;
            
            let (mut stream, _) = listener.accept()
                .map_err(|e| format!("Failed to accept TCP connection: {:?}", e))?;
            
            let mut conn = rustls::ServerConnection::new(Arc::new(server_config))
                .map_err(|e| format!("Failed to create server connection: {:?}", e))?;
            
            // Perform the TLS handshake manually.
            while conn.is_handshaking() {
                if conn.wants_write() {
                    conn.write_tls(&mut stream)
                        .map_err(|e| format!("TLS write error: {:?}", e))?;
                }
                if conn.wants_read() {
                    let n = conn.read_tls(&mut stream)
                        .map_err(|e| format!("TLS read error: {:?}", e))?;
                    if n == 0 {
                        return Err("Handshake aborted: client closed connection".to_string());
                    }
                    if let Err(e) = conn.process_new_packets() {
                        return Err(format!("TLS packet processing error: {:?}", e));
                    }
                }
            }

            // Flush any remaining handshake write buffer
            while conn.wants_write() {
                conn.write_tls(&mut stream)
                    .map_err(|e| format!("TLS write error: {:?}", e))?;
            }

            // Once the handshake is done, process HTTP data
            let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);
            let mut buf = [0u8; 1024];
            let n = tls_stream.read(&mut buf)
                .map_err(|e| format!("Failed to read HTTP request: {:?}", e))?;
            
            let req_str = String::from_utf8_lossy(&buf[..n]);
            if !req_str.starts_with("POST ") {
                return Err(format!("Expected POST request, got: {}", req_str));
            }

            // Write 200 OK response
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            tls_stream.write_all(response.as_bytes())
                .map_err(|e| format!("Failed to write HTTP response: {:?}", e))?;
            tls_stream.flush()
                .map_err(|e| format!("Failed to flush HTTP response: {:?}", e))?;

            Ok(())
        });

        (addr, handle)
    }

    #[tokio::test]
    async fn test_tls_pinning_handshake_success() {
        use crate::mock_cert_data::MOCK_CERT_PIN;
        
        let (addr, server_thread) = run_mock_https_server();
        let base_url = format!("https://localhost:{}", addr.port());

        // Build client with CORRECT pin
        let client = build_pinned_client(MOCK_CERT_PIN).unwrap();
        
        let segment_id = 77;
        let payload = vec![0xaa, 0xbb, 0xcc];
        
        let push_res = push_segment(&client, &base_url, segment_id, payload).await;
        assert!(push_res.is_ok(), "Push with matching cert pin should succeed, got error: {:?}", push_res);

        let server_res = server_thread.join().unwrap();
        assert!(server_res.is_ok(), "Server side of handshake should succeed, got error: {:?}", server_res);
    }

    #[tokio::test]
    async fn test_tls_pinning_handshake_mismatch_fails() {
        let (addr, server_thread) = run_mock_https_server();
        let base_url = format!("https://localhost:{}", addr.port());

        // Build client with WRONG pin (32 bytes of zeros)
        let wrong_pin = "00".repeat(32);
        let client = build_pinned_client(&wrong_pin).unwrap();
        
        let segment_id = 77;
        let payload = vec![0xaa, 0xbb, 0xcc];
        
        let push_res = push_segment(&client, &base_url, segment_id, payload).await;
        
        assert!(push_res.is_err(), "Push with mismatched cert pin must fail");
        let err = push_res.unwrap_err();
        assert!(
            matches!(err, ShipperError::CertPinMismatch { .. }),
            "Expected CertPinMismatch, got {:?}",
            err
        );

        let server_res = server_thread.join().unwrap();
        assert!(
            server_res.is_err(),
            "Server side of handshake must fail due to client aborting, got Ok"
        );
        let server_err = server_res.unwrap_err();
        assert!(
            server_err.contains("Handshake aborted") 
                || server_err.contains("TLS read error") 
                || server_err.contains("ConnectionReset") 
                || server_err.contains("ConnectionAborted")
                || server_err.contains("AlertReceived")
                || server_err.contains("TLS packet processing error"),
            "Expected handshake abort error on server, got: {}",
            server_err
        );
    }
}

