use super::service::MultisigService;
use crate::{proto::SignRequest, TofndResult};
use std::convert::TryInto;

use anyhow::anyhow;
use tofn::{ecdsa::sign, sdk::api::deserialize};

impl MultisigService {
    pub(super) async fn handle_sign(&self, request: &SignRequest) -> TofndResult<Vec<u8>> {
        // get multisig value from kv store
        let kv_value = self.kv_manager.kv().get(&request.key_uid).await?;

        // convert multisig value into signing key bytes
        let signing_key_bytes: Vec<u8> = kv_value.try_into()?;

        // deserialize to signing key
        let signing_key = deserialize(&signing_key_bytes)
            .ok_or_else(|| anyhow!("Cannot deserialize SigningKey"))?;

        // get signature
        let signature = sign(&signing_key, &request.msg_to_sign.as_slice().try_into()?)
            .map_err(|_| anyhow!("Cannot generate keypair"))?;

        // return signature
        Ok(signature)
    }
}
