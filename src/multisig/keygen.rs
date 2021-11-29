use super::service::MultisigService;
use crate::{proto::KeygenRequest, TofndResult};
use tofn::ecdsa::keygen;

use anyhow::anyhow;

impl MultisigService {
    pub(super) async fn handle_keygen(&self, request: &KeygenRequest) -> TofndResult<Vec<u8>> {
        let secret_recovery_key = self.kv_manager.seed().await?;

        let key_pair = keygen(&secret_recovery_key, request.key_uid.as_bytes())
            .map_err(|_| anyhow!("Cannot generate keypair"))?;

        Ok(key_pair.encoded_verifying_key().to_vec())
    }
}
