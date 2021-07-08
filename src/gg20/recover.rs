//! This module handles Recover gRPC

use super::{proto, Gg20Service, KeygenInitSanitized, PartyInfo};
use crate::TofndError;
use tofn::protocol::gg20::{keygen::SecretRecoveryKey, SecretKeyShare};

impl Gg20Service {
    /// attempt to write recovered secret key shares to the kv-store
    async fn update_share_kv_store(
        &mut self,
        keygen_init_sanitized: KeygenInitSanitized,
        secret_key_shares: Vec<SecretKeyShare>,
    ) -> Result<(), TofndError> {
        // try to make a reservation
        let reservation = self
            .shares_kv
            .reserve_key(keygen_init_sanitized.new_key_uid)
            .await?;
        // acquire kv-data
        let kv_data = PartyInfo::get_party_info(
            secret_key_shares,
            keygen_init_sanitized.party_uids,
            keygen_init_sanitized.party_share_counts,
            keygen_init_sanitized.my_index,
        );
        // try writing the data to the kv-store
        Ok(self.shares_kv.put(reservation, kv_data).await?)
    }

    /// get recovered secret key shares from serilized share recovery info
    fn recover_secret_key_shares(
        secret_recovery_key: &SecretRecoveryKey,
        serialized_share_recovery_infos: &[Vec<u8>],
        my_tofnd_index: usize,
        session_nonce: &[u8],
        party_share_counts: &[usize],
        threshold: usize,
    ) -> Result<Vec<SecretKeyShare>, TofndError> {
        // gather deserialized share recovery infos. Avoid using map() because deserialization returns Result
        let mut deserialized_share_recovery_infos =
            Vec::with_capacity(serialized_share_recovery_infos.len());
        for bytes in serialized_share_recovery_infos {
            deserialized_share_recovery_infos.push(bincode::deserialize(bytes)?);
        }

        // get my share count safely
        let my_share_count = match party_share_counts.get(my_tofnd_index) {
            Some(my_share_count) => my_share_count,
            None => {
                return Err(From::from(format!(
                    "index {} is out of party_share_counts bounds {}",
                    my_tofnd_index,
                    party_share_counts.len()
                )))
            }
        };

        // gather secret key shares from recovery infos
        let mut secret_key_shares = Vec::with_capacity(*my_share_count);
        for i in 0..*my_share_count {
            let recovered_secret_key_share = SecretKeyShare::recover(
                &secret_recovery_key,
                &session_nonce,
                &deserialized_share_recovery_infos,
                starting_tofn_index + i, // create tofn share index from starting tofn index + share count
                threshold,
            );
            // check that recovery was successful for share tofnd_index + i
            match recovered_secret_key_share {
                Ok(secret_key_share) => secret_key_shares.push(secret_key_share),
                Err(err) => {
                    return Err(From::from(format!(
                        "Unable to recover share [{}] of party [{}]. {}",
                        i, my_tofnd_index, err
                    )))
                }
            }
        }

        Ok(secret_key_shares)
    }

    pub(super) async fn handle_recover(
        &mut self,
        request: proto::RecoverRequest,
    ) -> Result<(), TofndError> {
        // get keygen init sanitized from request
        let keygen_init_sanitized = {
            let keygen_init = match request.keygen_init {
                Some(keygen_init) => keygen_init,
                None => return Err(From::from("missing keygen_init field in recovery request")),
            };
            Self::keygen_sanitize_args(keygen_init)?
        };

        // get mnemonic seed
        let secret_recovery_key = self.seed().await?;

        // recover secret key shares from request
        let secret_key_shares = {
            let secret_key_shares = Self::recover_secret_key_shares(
                &secret_recovery_key,
                &request.share_recovery_infos,
                keygen_init_sanitized.my_index,
                &keygen_init_sanitized.new_key_uid.as_bytes(),
                &keygen_init_sanitized.party_share_counts,
                keygen_init_sanitized.threshold,
            );
            match secret_key_shares {
                Ok(secret_key_shares) => secret_key_shares,
                Err(err) => {
                    return Err(From::from(format!(
                        "Failed to acquire secret key share {}",
                        err
                    )))
                }
            }
        };

        Ok(self
            .update_share_kv_store(keygen_init_sanitized, secret_key_shares)
            .await?)
    }
}
