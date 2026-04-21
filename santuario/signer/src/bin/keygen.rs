use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{PublicKey as TraitPubKey, SecretKey as TraitSecKey};
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating new Dilithium-5 keypair...");
    let (public_key, secret_key) = dilithium5::keypair();

    let keys_dir = std::env::var_os("SANTUARIO_KEYS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            home_dir.join(".santuario").join("keys")
        });

    if !keys_dir.exists() {
        fs::create_dir_all(&keys_dir)?;
    }

    let pub_path = keys_dir.join("key.pub");
    let priv_path = keys_dir.join("key.priv");

    fs::write(&pub_path, public_key.as_bytes())?;
    fs::write(&priv_path, secret_key.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&priv_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&priv_path, perms)?;
    }

    println!("Keys saved to {:?}", keys_dir);
    println!("Public key length: {} bytes", public_key.as_bytes().len());
    println!("Secret key length: {} bytes", secret_key.as_bytes().len());

    Ok(())
}
