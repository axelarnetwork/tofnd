//! This module handles the recover gRPC.
//! Request includes [proto::message_in::Data::KeygenInit] struct and encrypted recovery info.
//! The recovery info is decrypted by party's mnemonic seed and saved in the KvStore.

use super::{keygen::types::KeygenInitSanitized, proto, service::Gg20Service, types::PartyInfo};
use tofn::{
    collections::TypedUsize,
    gg20::keygen::{
        recover_party_keypair, recover_party_keypair_unsafe, KeygenPartyId, SecretKeyShare,
        SecretRecoveryKey,
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
        let keygen_init = {
            let keygen_init = request
                .keygen_init
                .ok_or_else(|| anyhow!("missing keygen_init field in recovery request"))?;
            Self::keygen_sanitize_args(keygen_init)?
        };

        let keygen_output = request
            .keygen_output
            .ok_or_else(|| "missing keygen_output field in recovery request".to_string())?;

        // check if key-uid already exists in kv-store. If yes, return success and don't update the kv-store
        if self
            .shares_kv
            .exists(&keygen_init.new_key_uid)
            .await
            .map_err(|err| anyhow!(err))?
        {
            warn!(
                "Attempting to recover shares for party {} which already exist in kv-store",
                keygen_init.new_key_uid
            );
            return Ok(());
        }

        // recover secret key shares from request
        // get mnemonic seed
        let secret_recovery_key = self.seed().await?;
        let secret_key_shares = self
            .recover_secret_key_shares(&secret_recovery_key, &keygen_init, &keygen_output)
            .map_err(|err| anyhow!("Failed to acquire secret key share {}", err))?;

        Ok(self
            .update_share_kv_store(keygen_init, secret_key_shares)
            .await?)
    }

    /// get recovered secret key shares from serilized share recovery info
    fn recover_secret_key_shares(
        &self,
        secret_recovery_key: &SecretRecoveryKey,
        init: &KeygenInitSanitized,
        output: &proto::KeygenOutput,
    ) -> Result<Vec<SecretKeyShare>, TofndError> {
        // get my share count safely
        let my_share_count = *init
            .party_share_counts
            .get(init.my_index)
            .ok_or_else(anyhow!(
                "index {} is out of party_share_counts bounds {}",
                init.my_index,
                init.party_share_counts.len()
            ))?;
        if my_share_count == 0 {
            return Err(anyhow!("Party {} has 0 shares assigned", init.my_index).into());
        }

        let party_share_counts = PartyShareCounts::from_vec(init.party_share_counts.to_owned())
            .map_err(|_| {
                anyhow!(
                    "PartyCounts::from_vec() error for {:?}",
                    init.party_share_counts
                )
            })?;

        info!("Recovering keypair for party {} ...", init.my_index);

        let party_id = TypedUsize::<KeygenPartyId>::from_usize(init.my_index);

        let session_nonce = init.new_key_uid.as_bytes();
        let party_keypair = match self.safe_keygen {
            true => recover_party_keypair(party_id, secret_recovery_key, session_nonce),
            false => recover_party_keypair_unsafe(party_id, secret_recovery_key, session_nonce),
        }
        .map_err(|_| anyhow!("party keypair recovery failed"))?;

        info!("Finished recovering keypair for party {}", init.my_index);

        // gather secret key shares from recovery infos
        let mut secret_key_shares = Vec::with_capacity(my_share_count);
        // TODO: make recover() handle all shares of the party to simplify the API?
        for (i, share_recovery_info_bytes) in output.recovery_info.iter().enumerate() {
            let secret_key_share = SecretKeyShare::recover(
                &party_keypair,
                share_recovery_info_bytes, // request recovery for ith share
                &output.group_info,
                &output.pub_key,
                party_id,
                i,
                party_share_counts.clone(),
                init.threshold,
            )
            .map_err(|_| format!("Cannot recover share [{}] of party [{}]", i, party_id,))?;
            secret_key_shares.push(secret_key_share);
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
