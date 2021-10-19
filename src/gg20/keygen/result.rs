//! This module handles the aggregation of process of keygen results.
//! When all keygen threads finish, we aggregate their results and retrieve:
//!  1. the public key - must be the same across all results; stored in KvStore
//!  2. all secret share data - data used to allow parties to participate to future Signs; stored in KvStore
//!  3. all secret share recovery info - information used to allow client to issue secret share recovery in case of data loss; sent to client

use tofn::{gg20::keygen::SecretKeyShare, sdk::api::serialize};

use super::{
    proto::{self},
    types::{BytesVec, KeygenInitSanitized, TofnKeygenOutput, TofndKeygenOutput},
    Gg20Service,
};
use crate::{gg20::types::PartyInfo, kv_manager::types::KeyReservation};

// tonic cruft
use tokio::sync::{
    mpsc,
    oneshot::{self, Receiver},
};
use tonic::Status;

// error handling
use crate::TofndResult;
use anyhow::anyhow;

impl Gg20Service {
    /// aggregate results from all keygen threads, create a record and insert it in the KvStore
    pub(super) async fn aggregate_results(
        &self,
        aggregator_receivers: Vec<oneshot::Receiver<TofndKeygenOutput>>,
        stream_out_sender: &mut mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
        key_uid_reservation: KeyReservation,
        keygen_init: KeygenInitSanitized,
    ) -> TofndResult<()> {
        // wait all keygen threads and aggregate results
        // can't use `map_err` because of `.await` func :(
        let keygen_outputs = match Self::aggregate_keygen_outputs(aggregator_receivers).await {
            Ok(keygen_outputs) => keygen_outputs,
            Err(err) => {
                self.kv.unreserve_key(key_uid_reservation).await;
                return Err(anyhow!(
                    "Error at Keygen output aggregation. Unreserving key {}",
                    err
                ));
            }
        };

        // try to process keygen outputs
        let (pub_key, group_recover_info, secret_key_shares) =
            Self::process_keygen_outputs(&keygen_init, keygen_outputs, stream_out_sender)?;

        // try to retrieve private recovery info from all shares
        let private_recover_info =
            Self::get_private_recovery_data(&secret_key_shares).map_err(|err| anyhow!(err))?;

        // combine responses from all keygen threads to a single struct
        let kv_data = PartyInfo::get_party_info(
            secret_key_shares,
            keygen_init.party_uids.clone(),
            keygen_init.party_share_counts.clone(),
            keygen_init.my_index,
        );

        // try to put data inside kv store
        self.kv
            .put(key_uid_reservation, kv_data.into())
            .await
            .map_err(|err| anyhow!(err))?;

        // try to send result
        Ok(
            stream_out_sender.send(Ok(proto::MessageOut::new_keygen_result(
                &keygen_init.party_uids,
                Ok(proto::KeygenOutput {
                    pub_key,
                    group_recover_info,
                    private_recover_info,
                }),
            )))?,
        )
    }

    /// iterate all keygen outputs, and return data that need to be permenantly stored
    /// we perform a sanity check that all shares produces the same pubkey and group recovery
    /// and then return a single copy of the common info and a vec with `SecretKeyShares` of each party
    /// This vec is later used to derive private recovery info
    fn process_keygen_outputs(
        keygen_init: &KeygenInitSanitized,
        keygen_outputs: Vec<TofnKeygenOutput>,
        stream_out_sender: &mut mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
    ) -> TofndResult<(BytesVec, BytesVec, Vec<SecretKeyShare>)> {
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

                // check that all shares returned the same public key and group recover info
                let share_id = secret_key_shares[0].share().index();
                let pub_key = secret_key_shares[0].group().encoded_pubkey();
                let group_info = secret_key_shares[0]
                    .group()
                    .all_shares_bytes()
                    .map_err(|_| anyhow!("unable to call all_shares_bytes()"))?;

                // sanity check: pubkey and group recovery info should be the same across all shares
                // Here we check that the first share produced the same info as the i-th.
                for secret_key_share in &secret_key_shares[1..] {
                    // try to get pubkey of i-th share. Each share should produce the same pubkey
                    if pub_key != secret_key_share.group().encoded_pubkey() {
                        return Err(anyhow!(
                            "Party {}'s share {} and {} returned different public key",
                            keygen_init.my_index,
                            share_id,
                            secret_key_share.share().index()
                        ));
                    }

                    // try to get group recovery info of i-th share. Each share should produce the same group info
                    let curr_group_info = secret_key_share
                        .group()
                        .all_shares_bytes()
                        .map_err(|_| anyhow!("unable to call all_shares_bytes()"))?;
                    if group_info != curr_group_info {
                        return Err(anyhow!(
                            "Party {}'s share {} and {} returned different group recovery info",
                            keygen_init.my_index,
                            share_id,
                            secret_key_share.share().index()
                        ));
                    }
                }

                Ok((pub_key, group_info, secret_key_shares))
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

    /// Create private recovery info out of a vec with all parties' SecretKeyShares
    fn get_private_recovery_data(secret_key_shares: &[SecretKeyShare]) -> TofndResult<BytesVec> {
        // try to retrieve private recovery info from all party's shares
        let private_infos = secret_key_shares
            .iter()
            .enumerate()
            .map(|(index, secret_key_share)| {
                secret_key_share
                    .recovery_info()
                    .map_err(|_| anyhow!("Unable to get recovery info for share {}", index))
            })
            .collect::<TofndResult<Vec<_>>>()?;

        // We use an additional layer of serialization to simplify the protobuf definition
        let private_bytes = serialize(&private_infos)
            .map_err(|_| anyhow!("Failed to serialize private recovery infos"))?;

        Ok(private_bytes)
    }

    /// wait all keygen threads and get keygen outputs
    async fn aggregate_keygen_outputs(
        aggregator_receivers: Vec<Receiver<TofndKeygenOutput>>,
    ) -> TofndResult<Vec<TofnKeygenOutput>> {
        let mut keygen_outputs = Vec::with_capacity(aggregator_receivers.len());

        for aggregator in aggregator_receivers {
            let res = aggregator.await??;
            keygen_outputs.push(res);
        }

        Ok(keygen_outputs)
    }
}
