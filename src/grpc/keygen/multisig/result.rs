//! This module handles the aggregation of process of keygen results.
//! When all keygen threads finish, we aggregate their results and retrieve:
//!  1. the public key - must be the same across all results; stored in KvStore
//!  2. all secret share data - data used to allow parties to participate to future Signs; stored in KvStore
//!  3. all secret share recovery info - information used to allow client to issue secret share recovery in case of data loss; sent to client

use tofn::{multisig::keygen::SecretKeyShare, sdk::api::serialize};

use crate::{
    grpc::{
        keygen::types::{BytesVec, KeygenInitSanitized, MultisigTofnKeygenOutput},
        service::Service,
        types::multisig::PartyInfo,
    },
    kv_manager::types::KeyReservation,
    proto,
};

use super::super::execute::KeygenOutput;

// tonic cruft
use tokio::sync::mpsc;
use tonic::Status;

// error handling
use crate::TofndResult;
use anyhow::anyhow;

fn to_multisig_keygen_outputs(
    outs: Vec<KeygenOutput>,
) -> TofndResult<Vec<MultisigTofnKeygenOutput>> {
    let mut multisig_outs = Vec::with_capacity(outs.len());
    for out in outs {
        match out {
            KeygenOutput::Multisig(multisig_out) => multisig_outs.push(multisig_out?),
            KeygenOutput::Gg20(_) => return Err(anyhow!("Wrong Keygen type. Expecting Multisig")),
        }
    }
    Ok(multisig_outs)
}

impl Service {
    /// aggregate results from all keygen threads, create a record and insert it in the KvStore
    pub(in super::super) async fn aggregate_multisig_results(
        &self,
        keygen_outputs: Vec<KeygenOutput>,
        stream_out_sender: &mut mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
        key_uid_reservation: KeyReservation,
        keygen_init: KeygenInitSanitized,
    ) -> TofndResult<()> {
        let keygen_outputs = to_multisig_keygen_outputs(keygen_outputs)?;

        // try to process keygen outputs
        let (pub_key, group_recover_info, secret_key_shares) =
            Self::process_multisig_keygen_outputs(&keygen_init, keygen_outputs, stream_out_sender)?;

        // try to retrieve private recovery info from all shares
        let private_recover_info = Self::get_multisig_private_recovery_data(&secret_key_shares)
            .map_err(|err| anyhow!(err))?;

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
            stream_out_sender.send(Ok(proto::MessageOut::new_multisig_keygen_result(
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
    pub fn process_multisig_keygen_outputs(
        keygen_init: &KeygenInitSanitized,
        keygen_outputs: Vec<MultisigTofnKeygenOutput>,
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
                // TODO: get `.pub_key_bytes()`, do basic validity checks and return (public keys, recovery info, secret_key_shares)
                let output_bytes = serialize(&secret_key_shares[0].group().all_verifying_keys())
                    .map_err(|_| anyhow!("Cannot serialize multisig output"))?;

                Ok((output_bytes, vec![], secret_key_shares))
            }
            Err(crimes) => {
                // send crimes and exit with an error
                stream_out_sender.send(Ok(proto::MessageOut::new_multisig_keygen_result(
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
    fn get_multisig_private_recovery_data(_: &[SecretKeyShare]) -> TofndResult<BytesVec> {
        // TODO: implement recovery for multisig
        let private_bytes = vec![];
        Ok(private_bytes)
    }
}
