use tofn::protocol::gg20::keygen::KeygenOutput;

use super::{
    proto::{self, message_out::keygen_result},
    types::KeygenInitSanitized,
    Gg20Service, PartyInfo,
};
use crate::{kv_manager::KeyReservation, TofndError};

// tonic cruft
use tokio::sync::{
    mpsc,
    oneshot::{self, Receiver},
};
use tonic::Status;

impl Gg20Service {
    // aggregate messages from all keygen workers, create a single record and insert it in the KVStore
    pub(super) async fn aggregate_messages(
        &mut self,
        aggregator_receivers: Vec<oneshot::Receiver<Result<KeygenOutput, TofndError>>>,
        stream_out_sender: &mut mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
        key_uid_reservation: KeyReservation,
        keygen_init: KeygenInitSanitized,
    ) -> Result<(), TofndError> {
        //  wait all keygen threads and aggregate results
        let keygen_outputs = match aggregate_keygen_outputs(aggregator_receivers).await {
            Ok(keygen_outputs) => keygen_outputs,
            Err(err) => {
                self.shares_kv.unreserve_key(key_uid_reservation).await;
                return Err(From::from(format!(
                    "Error at Keygen output aggregation. Unreserving key {}",
                    err
                )));
            }
        };

        // create a hashmap to store pub keys to ease assetion of uniqueness
        let mut pub_key_map = std::collections::HashMap::new();

        let mut secret_key_shares = vec![];
        for keygen_output in keygen_outputs {
            match keygen_output {
                Ok(secret_key_share) => {
                    let pub_key = secret_key_share.group.pubkey_bytes();
                    secret_key_shares.push(secret_key_share);
                    // hashmap [pub key -> count] with default value 0
                    *pub_key_map.entry(pub_key).or_insert(0) += 1;
                }
                Err(crimes) => {
                    // send crimes and exit
                    stream_out_sender.send(Ok(proto::MessageOut::new_keygen_result(
                        &keygen_init.party_uids,
                        &keygen_init.party_share_counts,
                        Err(crimes),
                    )))?;
                    return Ok(());
                }
            }
        }

        // check that all shares returned the same public key
        if pub_key_map.len() != 1 {
            return Err(From::from(format!(
                "Shares returned different public key {:?}",
                pub_key_map
            )));
        }
        let pub_key = pub_key_map.keys().last().unwrap().to_owned();

        // retrieve recovery info from all shares
        let mut share_recovery_infos = vec![];
        for secret_key_share in secret_key_shares.iter() {
            share_recovery_infos.push(bincode::serialize(&secret_key_share.recovery_info())?);
        }

        // combine all keygen threads responses to a single struct
        let kv_data = PartyInfo::get_party_info(
            secret_key_shares,
            keygen_init.party_uids.clone(),
            keygen_init.party_share_counts.clone(),
            keygen_init.my_index,
        );

        // try to put data inside kv store
        self.shares_kv.put(key_uid_reservation, kv_data).await?;

        // serialize generated public key and send to client
        stream_out_sender.send(Ok(proto::MessageOut::new_keygen_result(
            &keygen_init.party_uids,
            &keygen_init.party_share_counts,
            Ok(keygen_result::KeygenOutput {
                pub_key,
                share_recovery_infos,
            }),
        )))?;

        Ok(())
    }
}

async fn aggregate_keygen_outputs(
    aggregator_receivers: Vec<Receiver<Result<KeygenOutput, TofndError>>>,
) -> Result<Vec<KeygenOutput>, TofndError> {
    //  wait all keygen threads and get keygen output
    let mut keygen_outputs = Vec::with_capacity(aggregator_receivers.len());
    for aggregator in aggregator_receivers {
        let res = aggregator.await??;
        keygen_outputs.push(res);
    }
    Ok(keygen_outputs)
}
