use log::{info, warn};
use pqcrypto_dilithium::dilithium5::{self, PublicKey, SecretKey};
use pqcrypto_traits::sign::{PublicKey as TraitPubKey, SecretKey as TraitSecKey};
use std::fs;
use std::path::Path;

pub struct KeyStore {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl KeyStore {
    pub fn load_or_generate(keys_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if !keys_dir.exists() {
            fs::create_dir_all(keys_dir)?;
        }

        let pub_path = keys_dir.join("key.pub");
        let priv_path = keys_dir.join("key.priv");

        if pub_path.exists() && priv_path.exists() {
            info!("Loading existing keys from {:?}", keys_dir);
            let pub_bytes = fs::read(&pub_path)?;
            let priv_bytes = fs::read(&priv_path)?;

            let public_key = PublicKey::from_bytes(&pub_bytes)?;
            let secret_key = SecretKey::from_bytes(&priv_bytes)?;

            Ok(Self {
                public_key,
                secret_key,
            })
        } else {
            warn!("Keys not found in {:?}. Generating new ones...", keys_dir);
            let (public_key, secret_key) = dilithium5::keypair();

            fs::write(&pub_path, public_key.as_bytes())?;
            fs::write(&priv_path, secret_key.as_bytes())?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&priv_path)?.permissions();
                perms.set_mode(0o600);
                fs::set_permissions(&priv_path, perms)?;
            }

            info!("Generated and saved new Dilithium-5 keys.");

            Ok(Self {
                public_key,
                secret_key,
            })
        }
    }
}
