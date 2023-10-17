use super::{keypair::KeyPair, service::MultisigService};
use crate::{
    proto::{Algorithm, SignRequest},
    TofndResult,
};
use anyhow::anyhow;
use std::convert::TryInto;
use tofn::multisig::keygen::SecretRecoveryKey;

impl MultisigService {
    pub(super) async fn handle_sign(&self, request: &SignRequest) -> TofndResult<Vec<u8>> {
        // re-generate secret key from seed, then sign
        let algorithm = Algorithm::from_i32(request.algorithm)
            .ok_or(anyhow!("Invalid algorithm: {}", request.algorithm))?;

        let secret_recovery_key = self
            .find_matching_seed(&request.key_uid, &request.pub_key, algorithm)
            .await?;

        let key_pair =
            KeyPair::generate(&secret_recovery_key, request.key_uid.as_bytes(), algorithm)
                .map_err(|_| anyhow!("key re-generation failed"))?;

        let signature = key_pair
            .sign(&request.msg_to_sign.as_slice().try_into()?)
            .map_err(|_| anyhow!("sign failed"))?;

        Ok(signature)
    }

    /// Given a `key_uid` and `pub_key`, find the matching mnemonic.
    /// If `pub_key` is [None], use the currently active mnemonic.
    pub(super) async fn find_matching_seed(
        &self,
        key_uid: &str,
        pub_key: &[u8],
        algorithm: Algorithm,
    ) -> TofndResult<SecretRecoveryKey> {
        if pub_key.is_empty() {
            return self
                .kv_manager
                .seed()
                .await
                .map_err(|_| anyhow!("could not find current mnemonic"));
        }

        let seed_key_iter = self
            .kv_manager
            .seed_key_iter()
            .await
            .map_err(|_e| anyhow!("could not iterate over mnemonic keys"))?;

        for seed_key in seed_key_iter {
            let secret_recovery_key = self.kv_manager.get_seed(&seed_key).await?;

            let key_pair = KeyPair::generate(&secret_recovery_key, key_uid.as_bytes(), algorithm)
                .map_err(|_| anyhow!("key re-generation failed"))?;

            if pub_key == key_pair.encoded_verifying_key() {
                return Ok(secret_recovery_key);
            }
        }

        Err(anyhow!(
            "could not find a matching mnemonic for key {:?}",
            key_uid
        ))
    }
}
