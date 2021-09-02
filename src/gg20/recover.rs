//! This module handles the recover gRPC.
//! Request includes [proto::message_in::Data::KeygenInit] struct and encrypted recovery info.
//! The recovery info is decrypted by party's mnemonic seed and saved in the KvStore.

use super::{keygen::types::KeygenInitSanitized, proto, service::Gg20Service, types::PartyInfo};
use tofn::{
    collections::TypedUsize,
    gg20::keygen::{
        recover_party_keypair, recover_party_keypair_unsafe, KeyShareRecoveryInfo, KeygenPartyId,
        KeygenPartyShareCounts, PartyKeyPair, SecretKeyShare, SecretRecoveryKey,
    },
    sdk::api::PartyShareCounts,
};

// logging
use tracing::{info, warn};

// error handling
use crate::TofndResult;
use anyhow::anyhow;

impl Gg20Service {
    pub(super) async fn handle_recover(&self, request: proto::RecoverRequest) -> TofndResult<()> {
        // get keygen init sanitized from request
        let keygen_init_sanitized = {
            let keygen_init = match request.keygen_init {
                Some(keygen_init) => keygen_init,
                None => return Err(anyhow!("missing keygen_init field in recovery request")),
            };
            Self::keygen_sanitize_args(keygen_init)?
        };

        // check if key-uid already exists in kv-store. If yes, return success and don't update the kv-store
        if self
            .shares_kv
            .exists(&keygen_init_sanitized.new_key_uid)
            .await
            .map_err(|err| anyhow!(err))?
        {
            warn!(
                "Attempting to recover shares for party {} which already exist in kv-store",
                keygen_init_sanitized.new_key_uid
            );
            return Ok(());
        }

        // recover secret key shares from request
        // get mnemonic seed
        let secret_recovery_key = self.seed().await?;
        let secret_key_shares = self
            .recover_secret_key_shares(
                &secret_recovery_key,
                &request.share_recovery_infos,
                keygen_init_sanitized.my_index,
                keygen_init_sanitized.new_key_uid.as_bytes(),
                &keygen_init_sanitized.party_share_counts,
                keygen_init_sanitized.threshold,
            )
            .map_err(|err| anyhow!("Failed to acquire secret key share {}", err))?;

        Ok(self
            .update_share_kv_store(keygen_init_sanitized, secret_key_shares)
            .await?)
    }

    // allow for users to select whether to use big primes or not
    #[allow(clippy::too_many_arguments)]
    fn recover(
        &self,
        party_keypair: &PartyKeyPair,
        recovery_infos: &[KeyShareRecoveryInfo],
        party_id: TypedUsize<KeygenPartyId>,
        subshare_id: usize, // in 0..party_share_counts[party_id]
        party_share_counts: KeygenPartyShareCounts,
        threshold: usize,
    ) -> TofndResult<SecretKeyShare> {
        let recover = SecretKeyShare::recover(
            party_keypair,
            recovery_infos,
            party_id,
            subshare_id,
            party_share_counts,
            threshold,
        );

        // map error and return result
        recover.map_err(|_| {
            anyhow!(
                "Cannot recover share [{}] or party [{}]",
                subshare_id,
                party_id,
            )
        })
    }

    /// get recovered secret key shares from serilized share recovery info
    fn recover_secret_key_shares(
        &self,
        secret_recovery_key: &SecretRecoveryKey,
        serialized_share_recovery_infos: &[Vec<u8>],
        my_tofnd_index: usize,
        session_nonce: &[u8],
        party_share_counts: &[usize],
        threshold: usize,
    ) -> TofndResult<Vec<SecretKeyShare>> {
        // gather deserialized share recovery infos. Avoid using map() because deserialization returns Result
        let mut deserialized_share_recovery_infos =
            Vec::with_capacity(serialized_share_recovery_infos.len());
        for bytes in serialized_share_recovery_infos {
            deserialized_share_recovery_infos.push(bincode::deserialize(bytes)?);
        }

        // get my share count safely
        let my_share_count = *party_share_counts.get(my_tofnd_index).ok_or_else(|| {
            anyhow!(
                "index {} is out of party_share_counts bounds {}",
                my_tofnd_index,
                party_share_counts.len()
            )
        })?;
        if my_share_count == 0 {
            return Err(anyhow!("Party {} has 0 shares assigned", my_tofnd_index));
        }

        let party_share_counts = PartyShareCounts::from_vec(party_share_counts.to_owned())
            .map_err(|_| anyhow!("PartyCounts::from_vec() error for {:?}", party_share_counts))?;

        info!("Recovering keypair for party {} ...", my_tofnd_index);

        let party_id = TypedUsize::<KeygenPartyId>::from_usize(my_tofnd_index);

        let party_keypair = match self.safe_keygen {
            true => recover_party_keypair(party_id, secret_recovery_key, session_nonce),
            false => recover_party_keypair_unsafe(party_id, secret_recovery_key, session_nonce),
        }
        .map_err(|_| anyhow!("party keypair recovery failed"))?;

        info!("Finished recovering keypair for party {}", my_tofnd_index);

        // gather secret key shares from recovery infos
        let mut secret_key_shares = Vec::with_capacity(my_share_count);
        for i in 0..my_share_count {
            secret_key_shares.push(self.recover(
                &party_keypair,
                &deserialized_share_recovery_infos,
                party_id,
                i,
                party_share_counts.clone(),
                threshold,
            )?);
        }

        Ok(secret_key_shares)
    }

    /// attempt to write recovered secret key shares to the kv-store
    async fn update_share_kv_store(
        &self,
        keygen_init_sanitized: KeygenInitSanitized,
        secret_key_shares: Vec<SecretKeyShare>,
    ) -> TofndResult<()> {
        // try to make a reservation
        let reservation = self
            .shares_kv
            .reserve_key(keygen_init_sanitized.new_key_uid)
            .await
            .map_err(|err| anyhow!("failed to complete reservation: {}", err))?;
        // acquire kv-data
        let kv_data = PartyInfo::get_party_info(
            secret_key_shares,
            keygen_init_sanitized.party_uids,
            keygen_init_sanitized.party_share_counts,
            keygen_init_sanitized.my_index,
        );
        // try writing the data to the kv-store
        Ok(self
            .shares_kv
            .put(reservation, kv_data)
            .await
            .map_err(|err| anyhow!("failed to update kv store: {}", err))?)
    }
}
