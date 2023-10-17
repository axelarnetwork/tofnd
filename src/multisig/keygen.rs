use super::{keypair::KeyPair, service::MultisigService};
use crate::{
    proto::{Algorithm, KeygenRequest},
    TofndResult,
};
use anyhow::anyhow;

impl MultisigService {
    pub(super) async fn handle_keygen(&self, request: &KeygenRequest) -> TofndResult<Vec<u8>> {
        let algorithm = Algorithm::from_i32(request.algorithm)
            .ok_or(anyhow!("Invalid algorithm: {}", request.algorithm))?;
        let secret_recovery_key = self.kv_manager.seed().await?;

        Ok(
            KeyPair::generate(&secret_recovery_key, request.key_uid.as_bytes(), algorithm)?
                .encoded_verifying_key(),
        )
    }
}
