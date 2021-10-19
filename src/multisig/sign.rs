use super::service::MultisigService;
use crate::{proto::SignRequest, TofndResult};
use std::convert::TryInto;

use anyhow::anyhow;
use tofn::{ecdsa::sign, sdk::api::deserialize};

impl MultisigService {
    pub(super) async fn handle_sign(&self, request: SignRequest) -> TofndResult<Vec<u8>> {
        let session_nonce = request.key_uid;

        let kv_value = self.kv_manager.kv().get(&session_nonce).await?;
        let signing_key_bytes: Vec<u8> = kv_value.try_into()?;
        let signing_key = deserialize(&signing_key_bytes)
            .ok_or_else(|| anyhow!("Cannot deserialize SigningKey"))?;

        let signature = sign(&signing_key, &request.msg_to_sign.as_slice().try_into()?)
            .map_err(|_| anyhow!("Cannot generate keypair"))?;

        Ok(signature)
    }
}
