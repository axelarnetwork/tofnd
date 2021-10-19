use super::service::MultisigService;
use crate::{proto::KeygenRequest, TofndResult};

use anyhow::anyhow;
use tofn::{ecdsa::keygen, sdk::api::serialize};

impl MultisigService {
    pub(super) async fn handle_keygen(&self, request: KeygenRequest) -> TofndResult<Vec<u8>> {
        let session_nonce = request.key_id;
        let secret_key_share = self.kv_manager.seed().await?;

        let key_pair = keygen(&secret_key_share, session_nonce.as_bytes())
            .map_err(|_| anyhow!("Cannot generate keypair"))?;

        let reservation = self.kv_manager.kv().reserve_key(session_nonce).await?;

        let signing_key_bytes = serialize(key_pair.signing_key())
            .map_err(|_| anyhow!("Cannot serialize signing key"))?;

        let encoded_verifying_key = key_pair
            .encoded_verifying_key()
            .map_err(|_| anyhow!("Cannot encode verifying key"))?;

        self.kv_manager
            .kv()
            .put(reservation, signing_key_bytes.into())
            .await?;
        Ok(encoded_verifying_key.to_vec())
    }
}
