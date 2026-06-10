pub mod contract;
pub mod error;
pub mod msg;
pub mod pqc;
pub mod state;
pub mod stargate;


#[cfg(target_arch = "wasm32")]
fn custom_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    for byte in buf.iter_mut() {
        *byte = 0;
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(custom_getrandom);

