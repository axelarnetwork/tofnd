use crate::grpc::{
    keygen::types::{Context, KeygenInitSanitized},
    service::Service,
};
use crate::TofndResult;
use tofn::{
    collections::TypedUsize, gg20::keygen::SecretRecoveryKey, multisig::keygen::KeygenPartyId,
};
use tofn::{multisig::keygen::KeygenPartyShareCounts, sdk::api::BytesVec};

use anyhow::anyhow;

#[derive(Clone)]
pub struct MultisigContext {
    pub(super) base: Context,
    pub(super) secret_recovery_key: SecretRecoveryKey,
    pub(super) session_nonce: BytesVec,
}

impl MultisigContext {
    async fn new(
        service: &Service,
        keygen_init: &KeygenInitSanitized,
        tofnd_subindex: usize,
    ) -> TofndResult<Self> {
        Ok(Self {
            base: Context::new(keygen_init, tofnd_subindex),
            secret_recovery_key: service.seed().await?,
            session_nonce: keygen_init.new_key_uid.as_bytes().to_vec(),
        })
    }

    pub async fn new_without_subindex(
        service: &Service,
        keygen_init: &KeygenInitSanitized,
    ) -> TofndResult<Self> {
        Self::new(service, keygen_init, 0).await
    }

    /// get share_counts in the form of tofn::PartyShareCounts
    pub fn share_counts(&self) -> TofndResult<KeygenPartyShareCounts> {
        match KeygenPartyShareCounts::from_vec(self.base.share_counts.clone()) {
            Ok(party_share_counts) => Ok(party_share_counts),
            Err(_) => Err(anyhow!("failed to create party_share_counts")),
        }
    }

    pub fn tofnd_index(&self) -> TypedUsize<KeygenPartyId> {
        TypedUsize::from_usize(self.base.tofnd_index)
    }

    pub fn base_uids(&self) -> &[String] {
        &self.base.uids
    }

    pub fn base_share_counts(&self) -> &[usize] {
        &self.base.share_counts
    }

    pub fn clone_with_subindex(&self, tofnd_subindex: usize) -> Self {
        let mut cloned = self.clone();
        cloned.base.tofnd_subindex = tofnd_subindex;
        cloned
    }

    pub fn log_info(&self) -> String {
        self.base.log_info()
    }
}
