//! This module handles the aggregation of process of keygen results.
//! When all keygen threads finish, we aggregate their results and retrieve:
//!  1. the public key - must be the same across all results; stored in KvStore
//!  2. all secret share data - data used to allow parties to participate to future Signs; stored in KvStore
//!  3. all secret share recovery info - information used to allow client to issue secret share recovery in case of data loss; sent to client

use tofn::gg20::keygen::SecretKeyShare;

use super::{
    proto::{self, message_out::keygen_result},
    types::{KeygenInitSanitized, TofnKeygenOutput, TofndKeygenOutput},
    Gg20Service,
};
use crate::{gg20::types::PartyInfo, kv_manager::KeyReservation};

// tonic cruft
use tokio::sync::{
    mpsc,
    oneshot::{self, Receiver},
};
use tonic::Status;

// error handling
use anyhow::{anyhow, Result};

impl Gg20Service {
    /// aggregate results from all keygen threads, create a record and insert it in the KvStore
    pub(super) async fn aggregate_results(
        &self,
        aggregator_receivers: Vec<oneshot::Receiver<TofndKeygenOutput>>,
        stream_out_sender: &mut mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
        key_uid_reservation: KeyReservation,
        keygen_init: KeygenInitSanitized,
    ) -> Result<()> {
        // wait all keygen threads and aggregate results
        // can't use `map_err` because of `.await` func :(
        let keygen_outputs = match Self::aggregate_keygen_outputs(aggregator_receivers).await {
            Ok(keygen_outputs) => keygen_outputs,
            Err(err) => {
                self.shares_kv.unreserve_key(key_uid_reservation).await;
                return Err(anyhow!(
                    "Error at Keygen output aggregation. Unreserving key {}",
                    err
                ));
            }
        };

        // try to process keygen outputs
        let (pub_key, secret_key_shares) =
            Self::process_keygen_outputs(&keygen_init, keygen_outputs, stream_out_sender)?;

        // try to retrieve recovery info from all shares
        let share_recovery_infos = secret_key_shares
            .iter()
            .map(|secret_key_share| {
                let recovery_info = secret_key_share
                    .recovery_info()
                    .map_err(|_| anyhow!("Unable to get recovery info"))?;

                bincode::serialize(&recovery_info).map_err(|e| anyhow!("{}", e))
            })
            .collect::<Result<_>>()?;

        // combine responses from all keygen threads to a single struct
        let kv_data = PartyInfo::get_party_info(
            secret_key_shares,
            keygen_init.party_uids.clone(),
            keygen_init.party_share_counts.clone(),
            keygen_init.my_index,
        );

        // try to put data inside kv store
        self.shares_kv
            .put(key_uid_reservation, kv_data)
            .await
            .map_err(|err| anyhow!("{}", err))?;

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
    ) -> Result<(Vec<u8>, Vec<SecretKeyShare>)> {
        // Collect all key shares unless there's a protocol fault
        let keygen_outputs = keygen_outputs
            .into_iter()
            .collect::<Result<Vec<SecretKeyShare>, _>>();

        match keygen_outputs {
            Ok(secret_key_shares) => {
                if secret_key_shares.is_empty() {
                    return Err(anyhow!(
                        "Party {} created no secret key shares",
                        keygen_init.my_index
                    ));
                }

                // check that all shares returned the same public key
                let share_id = secret_key_shares[0].share().index();
                let pub_key = secret_key_shares[0].group().pubkey_bytes();

                for secret_key_share in &secret_key_shares[1..] {
                    if pub_key != secret_key_share.group().pubkey_bytes() {
                        return Err(anyhow!(
                            "Party {}'s share {} and {} returned different public key",
                            keygen_init.my_index,
                            share_id,
                            secret_key_share.share().index()
                        ));
                    }
                }

                Ok((pub_key, secret_key_shares))
            }
            Err(crimes) => {
                // send crimes and exit with an error
                stream_out_sender.send(Ok(proto::MessageOut::new_keygen_result(
                    &keygen_init.party_uids,
                    Err(crimes.clone()),
                )))?;

                Err(anyhow!(
                    "Party {} found crimes: {:?}",
                    keygen_init.my_index,
                    crimes
                ))
            }
        }
    }

    /// wait all keygen threads and get keygen outputs
    async fn aggregate_keygen_outputs(
        aggregator_receivers: Vec<Receiver<TofndKeygenOutput>>,
    ) -> Result<Vec<TofnKeygenOutput>> {
        let mut keygen_outputs = Vec::with_capacity(aggregator_receivers.len());

        for aggregator in aggregator_receivers {
            let res = aggregator.await??;
            keygen_outputs.push(res);
        }

        Ok(keygen_outputs)
    }
}
