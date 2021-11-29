use super::service::MultisigService;
use crate::{proto::SignRequest, TofndResult};
use std::convert::TryInto;

use anyhow::anyhow;
use tofn::ecdsa::{keygen, sign};

impl MultisigService {
    pub(super) async fn handle_sign(&self, request: &SignRequest) -> TofndResult<Vec<u8>> {
        // re-generate secret key from seed, then sign
        let secret_recovery_key = self.kv_manager.seed().await?;

        let key_pair = keygen(&secret_recovery_key, request.key_uid.as_bytes())
            .map_err(|_| anyhow!("key re-generation failed"))?;

        let signature = sign(
            key_pair.signing_key(),
            &request.msg_to_sign.as_slice().try_into()?,
        )
        .map_err(|_| anyhow!("sign failed"))?;

        Ok(signature)
    }
}
