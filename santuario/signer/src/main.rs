use pqcrypto_traits::sign::SignedMessage;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};

pub mod santuario {
    pub mod signer {
        pub mod v1 {
            tonic::include_proto!("santuario.signer.v1");
        }
    }
}

use santuario::signer::v1::signer_server::{Signer, SignerServer};
use santuario::signer::v1::{
    GetPublicKeyRequest, GetPublicKeyResponse, SignRequest, SignResponse, VerifyRequest,
    VerifyResponse,
};

mod keystore;
use keystore::KeyStore;

use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::PublicKey;

pub struct SantuarioSigner {
    keystore: Arc<KeyStore>,
}

impl SantuarioSigner {
    pub fn new(keystore: Arc<KeyStore>) -> Self {
        Self { keystore }
    }
}

#[tonic::async_trait]
impl Signer for SantuarioSigner {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let req = request.into_inner();

        if req.payload_hash.len() != 32 {
            return Err(Status::invalid_argument(
                "payload_hash must be exactly 32 bytes",
            ));
        }

        let signature = dilithium5::sign(&req.payload_hash, &self.keystore.secret_key);

        Ok(Response::new(SignResponse {
            signature: signature.as_bytes().to_vec(),
        }))
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let req = request.into_inner();

        let pub_key = dilithium5::PublicKey::from_bytes(&req.public_key)
            .map_err(|_| Status::invalid_argument("Invalid Dilithium-5 public key format"))?;

        // 1. Convertiamo i byte ricevuti nel tipo SignedMessage atteso dalla libreria
        let signed_msg = match dilithium5::SignedMessage::from_bytes(&req.signature) {
            Ok(sm) => sm,
            Err(_) => return Ok(Response::new(VerifyResponse { valid: false })), // Se i byte sono formattati male, rifiutiamo la firma
        };

        // 2. Passiamo il riferimento al nuovo oggetto `signed_msg` al posto di `&req.signature`
        let valid = dilithium5::open(&signed_msg, &pub_key)
            .map(|msg| msg == req.payload_hash)
            .unwrap_or(false);

        Ok(Response::new(VerifyResponse { valid }))
    }

    async fn get_public_key(
        &self,
        _request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        Ok(Response::new(GetPublicKeyResponse {
            public_key: self.keystore.public_key.as_bytes().to_vec(),
        }))
    }
}

#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let keys_dir = std::env::var_os("SANTUARIO_KEYS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let home_dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            home_dir.join(".santuario").join("keys")
        });
    let keystore = Arc::new(KeyStore::load_or_generate(&keys_dir)?);

    let signer_service = SantuarioSigner::new(keystore);
    let server = Server::builder().add_service(SignerServer::new(signer_service));

    #[cfg(unix)]
    {
        let socket_path = std::env::var("SANTUARIO_SOCKET")
            .unwrap_or_else(|_| "/run/aeterna/santuario.sock".to_string());
        let socket_path = std::path::PathBuf::from(socket_path);

        // Ensure directory exists
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Remove old socket if exists
        let _ = std::fs::remove_file(&socket_path);

        let uds = UnixListener::bind(&socket_path)?;
        let uds_stream = UnixListenerStream::new(uds);

        // Set permissions so only the user can access it
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&socket_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&socket_path, perms)?;

        log::info!("Santuario Signer starting on UDS {}", socket_path.display());
        server.serve_with_incoming(uds_stream).await?;
    }

    #[cfg(not(unix))]
    {
        let port = std::env::var("SANTUARIO_PORT").unwrap_or_else(|_| "50051".to_string());
        let addr_str = format!("127.0.0.1:{}", port);
        let addr = addr_str.parse()?;

        log::info!("Santuario Signer starting on TCP {}", addr);
        server.serve(addr).await?;
    }

    Ok(())
}
