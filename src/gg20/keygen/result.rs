//! This module handles the aggregation of process of keygen results.
//! When all keygen threads finish, we aggregate their results and retrieve:
//!  1. the public key - must be the same across all results; stored in KvStore
//!  2. all secret share data - data used to allow parties to participate to future Signs; stored in KvStore
//!  3. all secret share recovery info - information used to allow client to issue secret share recovery in case of data loss; sent to client

use tofn::refactor::keygen::SecretKeyShare;

use super::{
    proto::{self, message_out::keygen_result},
    types::{KeygenInitSanitized, TofnKeygenOutput, TofndKeygenOutput},
    Gg20Service,
};
use crate::{gg20::types::PartyInfo, kv_manager::KeyReservation, TofndError};

// tonic cruft
use tokio::sync::{
    mpsc,
    oneshot::{self, Receiver},
};
use tonic::Status;

impl Gg20Service {
    /// aggregate results from all keygen threads, create a record and insert it in the KvStore
    pub(super) async fn aggregate_results(
        &mut self,
        aggregator_receivers: Vec<oneshot::Receiver<TofndKeygenOutput>>,
        stream_out_sender: &mut mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
        key_uid_reservation: KeyReservation,
        keygen_init: KeygenInitSanitized,
    ) -> Result<(), TofndError> {
        // wait all keygen threads and aggregate results
        let keygen_outputs = match Self::aggregate_keygen_outputs(aggregator_receivers).await {
            Ok(keygen_outputs) => keygen_outputs,
            Err(err) => {
                self.shares_kv.unreserve_key(key_uid_reservation).await;
                return Err(From::from(format!(
                    "Error at Keygen output aggregation. Unreserving key {}",
                    err
                )));
            }
        };

        // try to process keygen outputs
        let (pub_key, secret_key_shares) =
            Self::process_keygen_outputs(&keygen_init, keygen_outputs, stream_out_sender)?;

        // try to retrieve recovery info from all shares
        let mut share_recovery_infos = vec![];
        for secret_key_share in secret_key_shares.iter() {
            let recovery_info = match secret_key_share.recovery_info() {
                Ok(recovery_info) => recovery_info,
                Err(_) => {
                    return Err(From::from("Unable to get recovery info"));
                }
            };
            share_recovery_infos.push(bincode::serialize(&recovery_info)?);
        }

        // combine responses from all keygen threads to a single struct
        let kv_data = PartyInfo::get_party_info(
            secret_key_shares,
            keygen_init.party_uids.clone(),
            keygen_init.party_share_counts.clone(),
            keygen_init.my_index,
        );

        // try to put data inside kv store
        self.shares_kv.put(key_uid_reservation, kv_data).await?;

        // try to send result
        Ok(
            stream_out_sender.send(Ok(proto::MessageOut::new_keygen_result(
                &keygen_init.party_uids,
                Ok(keygen_result::KeygenOutput {
                    pub_key,
                    share_recovery_infos,
                }),
            )))?,
        )
    }

    /// iterate all keygen outputs, and return data that need to be permenantly stored
    /// from all keygen outputs we need to extract the common public key and each secret key share
    fn process_keygen_outputs(
        keygen_init: &KeygenInitSanitized,
        keygen_outputs: Vec<TofnKeygenOutput>,
        stream_out_sender: &mut mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
    ) -> Result<(Vec<u8>, Vec<SecretKeyShare>), TofndError> {
        // all shares must return the same public key. To ease pub key uniqueness, we use a hasmap
        let mut pub_key_map = std::collections::HashMap::new();

        // prepare a vec to hold secret key shares for each share
        let mut secret_key_shares = Vec::with_capacity(keygen_outputs.len());

        for keygen_output in keygen_outputs {
            match keygen_output {
                // if keygen output was ok, hold `secret_key_share` in a vec and add public key to a hasmap
                Ok(secret_key_share) => {
                    let pub_key = secret_key_share.group().pubkey_bytes();
                    secret_key_shares.push(secret_key_share);
                    // hashmap [pub key -> count] with default value 0
                    *pub_key_map.entry(pub_key).or_insert(0) += 1;
                }
                // if keygen output was an error, send discovered criminals to client and exit
                Err(crimes) => {
                    // send crimes and exit with an error
                    stream_out_sender.send(Ok(proto::MessageOut::new_keygen_result(
                        &keygen_init.party_uids,
                        Err(crimes.clone()),
                    )))?;
                    return Err(From::from(format!("Crimes found: {:?}", crimes)));
                }
            }
        }

        // assert that all shares returned the same public key
        let pub_key = Self::validate_pubkey(pub_key_map)?;

        Ok((pub_key, secret_key_shares))
    }

    /// wait all keygen threads and get keygen outputs
    async fn aggregate_keygen_outputs(
        aggregator_receivers: Vec<Receiver<TofndKeygenOutput>>,
    ) -> Result<Vec<TofnKeygenOutput>, TofndError> {
        let mut keygen_outputs = Vec::with_capacity(aggregator_receivers.len());
        for aggregator in aggregator_receivers {
            let res = aggregator.await??;
            keygen_outputs.push(res);
        }
        Ok(keygen_outputs)
    }

    /// check that all shares returned the same public key
    fn validate_pubkey(
        pub_key_map: std::collections::HashMap<Vec<u8>, i32>,
    ) -> Result<Vec<u8>, TofndError> {
        if pub_key_map.len() != 1 {
            return Err(From::from(format!(
                "Shares returned different public key {:?}",
                pub_key_map
            )));
        }
        Ok(pub_key_map
            .keys()
            .last()
            .ok_or("no keys in pubkey hashmap")?
            .to_owned())
    }
}
