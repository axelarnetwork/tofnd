use super::service::MultisigService;
use crate::{proto::SignRequest, TofndResult};
use std::convert::TryInto;

use anyhow::anyhow;
use tofn::{ecdsa::sign, sdk::api::deserialize};

impl MultisigService {
    pub(super) async fn handle_sign(&self, request: &SignRequest) -> TofndResult<Vec<u8>> {
        // get signing key bytes from kv store
        let signing_key_bytes = self.kv_manager.kv().get(&request.key_uid).await?;

        // deserialize to signing key
        // SecretScalar is not exposed, so we need to deserialize manually here
        let signing_key = deserialize(&signing_key_bytes)
            .ok_or_else(|| anyhow!("Cannot deserialize SigningKey"))?;

        // get signature
        let signature = sign(&signing_key, &request.msg_to_sign.as_slice().try_into()?)
            .map_err(|_| anyhow!("Cannot generate keypair"))?;

        // return signature
        Ok(signature)
    }
}
