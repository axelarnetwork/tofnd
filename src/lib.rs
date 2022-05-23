pub mod encrypted_sled;
pub mod gg20;
pub mod kv_manager;
pub mod mnemonic;
pub mod multisig;
pub mod proto {
    tonic::include_proto!("tofnd");
}
pub mod config;
// error handling
pub type TofndResult<Success> = anyhow::Result<Success>;