//! This mod includes the service implementation derived from

use super::mnemonic::FileIo;
use super::proto;
use crate::config::Config;
use crate::kv_manager::KvManager;
use std::path::PathBuf;

// error handling
use crate::TofndResult;

#[cfg(feature = "malicious")]
pub mod malicious;

/// Gg20Service
#[derive(Clone)]
pub struct Gg20Service {
    pub(super) kv: KvManager,
    pub(super) io: FileIo,
    pub(super) cfg: Config,
}

/// create a new Gg20 gRPC server
pub async fn new_service(
    cfg: Config,
    kv_manager: KvManager,
) -> TofndResult<impl proto::gg20_server::Gg20> {
    let io = FileIo::new(PathBuf::from(&cfg.tofnd_path));

    let gg20 = Gg20Service {
        kv: kv_manager,
        io,
        cfg,
    };

    gg20.handle_mnemonic().await?;
    Ok(gg20)
}
