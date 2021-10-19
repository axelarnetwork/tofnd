//! This mod includes the service implementation derived from

use super::proto;
use crate::config::Config;
use crate::kv_manager::KvManager;

#[cfg(feature = "malicious")]
pub mod malicious;

/// Gg20Service
#[derive(Clone)]
pub struct Gg20Service {
    pub(super) kv_manager: KvManager,
    pub(super) cfg: Config,
}

/// create a new Gg20 gRPC server
pub fn new_service(cfg: Config, kv_manager: KvManager) -> impl proto::gg20_server::Gg20 {
    Gg20Service { kv_manager, cfg }
}
