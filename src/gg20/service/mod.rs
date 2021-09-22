//! This mod includes the service implementation derived from

use super::mnemonic::file_io::FileIo;
use super::proto;
use super::types::{KeySharesKv, MnemonicKv, DEFAULT_MNEMONIC_KV_NAME, DEFAULT_SHARE_KV_NAME};
use crate::config::Config;
use crate::encrypted_sled::Password;
use std::path::PathBuf;

// error handling
use crate::TofndResult;
use anyhow::anyhow;

#[cfg(feature = "malicious")]
pub mod malicious;

/// Gg20Service
#[derive(Clone)]
pub struct Gg20Service {
    pub(super) shares_kv: KeySharesKv,
    pub(super) mnemonic_kv: MnemonicKv,
    pub(super) io: FileIo,
    pub(super) cfg: Config,
}

/// create a new Gg20 gRPC server
pub async fn new_service(
    cfg: Config,
    password: Password,
) -> TofndResult<impl proto::gg20_server::Gg20> {
    let shares_kv = KeySharesKv::new(
        cfg.tofnd_path.as_str(),
        DEFAULT_SHARE_KV_NAME,
        password.clone(),
    )
    .map_err(|err| anyhow!("Shares KV store error: {}", err))?;
    let mnemonic_kv = MnemonicKv::new(cfg.tofnd_path.as_str(), DEFAULT_MNEMONIC_KV_NAME, password)
        .map_err(|err| anyhow!("Mnemonic KV store error: {}", err))?;

    let io = FileIo::new(PathBuf::from(&cfg.tofnd_path));

    let gg20 = Gg20Service {
        shares_kv,
        mnemonic_kv,
        io,
        cfg,
    };

    gg20.handle_mnemonic().await?;
    Ok(gg20)
}
