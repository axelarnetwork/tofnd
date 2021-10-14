use crate::grpc::{
    keygen::types::{Context, KeygenInitSanitized},
    service::Service,
};
use crate::TofndResult;
use tofn::{
    collections::TypedUsize,
    gg20::keygen::{
        create_party_keypair_and_zksetup, create_party_keypair_and_zksetup_unsafe, KeygenPartyId,
        KeygenPartyShareCounts, PartyKeygenData,
    },
};

use anyhow::anyhow;

#[derive(Clone)]
pub struct Gg20Context {
    pub(super) base: Context,
    pub(super) party_keygen_data: PartyKeygenData,
}

impl Gg20Context {
    async fn new(
        service: &Service,
        keygen_init: &KeygenInitSanitized,
        tofnd_subindex: usize,
    ) -> TofndResult<Self> {
        let secret_recovery_key = service.seed().await?;

        let party_id = TypedUsize::<KeygenPartyId>::from_usize(keygen_init.my_index);
        let session_nonce = keygen_init.new_key_uid.as_bytes();
        let party_keygen_data = match service.cfg.safe_keygen {
            true => create_party_keypair_and_zksetup(party_id, &secret_recovery_key, session_nonce),
            false => create_party_keypair_and_zksetup_unsafe(
                party_id,
                &secret_recovery_key,
                session_nonce,
            ),
        }
        .map_err(|_| anyhow!("Party keypair generation failed"))?;

        Ok(Self {
            base: Context::new(keygen_init, tofnd_subindex),
            party_keygen_data,
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
