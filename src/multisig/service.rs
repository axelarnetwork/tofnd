use crate::proto;
use crate::kv_manager::KvManager;
use std::path::PathBuf;

// error handling
use crate::TofndResult;

/// Gg20Service
#[derive(Clone)]
pub struct MultsigService {
    pub(super) kv: KvManager,
}

/// create a new Gg20 gRPC server
pub async fn new_service(
    kv_manager: KvManager,
) -> TofndResult<impl proto::gg20_server::Gg20> {

    let gg20 = Gg20Service {
        kv: kv_manager,
        io,
    };

    gg20.handle_mnemonic().await?;
    Ok(gg20)
}
