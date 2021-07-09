use tracing::{span, Level, Span};

use tofn::protocol::gg20::keygen::{crimes::Crime, KeygenOutput};

use super::{
    proto::{self, message_out::keygen_result},
    protocol::{self, map_tofnd_to_tofn_idx},
    routing::route_messages,
    Gg20Service, PartyInfo, ProtocolCommunication,
};
use crate::{kv_manager::KeyReservation, TofndError};

use tonic::Status;

// tonic cruft
use tokio::sync::{
    mpsc,
    oneshot::{self, Receiver},
};

pub mod types;
use types::*;

mod execute;
mod init;

// wrapper type for proto::message_out::new_keygen_result
pub(super) type KeygenResultData = Result<keygen_result::KeygenOutput, Vec<Vec<Crime>>>;

impl Gg20Service {
    // we wrap the functionality of keygen gRPC here because we can't handle errors
    // conveniently when spawning theads.
    pub async fn handle_keygen(
        &mut self,
        mut stream_in: tonic::Streaming<proto::MessageIn>,
        mut stream_out_sender: mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
        keygen_span: Span,
    ) -> Result<(), TofndError> {
        // 1. Receive KeygenInit, open message, sanitize arguments
        // 2. Spawn N keygen threads to execute the protocol in parallel; one of each of our shares
        // 3. Spawn 1 router thread to route messages from client to the respective keygen thread
        // 4. Wait for all keygen threads to finish and aggregate all responses

        // get KeygenInit message from stream, sanitize arguments and reserve key
        let (keygen_init, key_uid_reservation) = self
            .handle_keygen_init(&mut stream_in, keygen_span.clone())
            .await?;

        // find my share count to allocate channel vectors
        let my_share_count = keygen_init.my_shares_count();

        // create in and out channels for each share, and spawn as many threads
        let mut keygen_senders = Vec::with_capacity(my_share_count);
        let mut aggregator_receivers = Vec::with_capacity(my_share_count);

        for my_tofnd_subindex in 0..my_share_count {
            let (keygen_sender, keygen_receiver) = mpsc::unbounded_channel();
            let (aggregator_sender, aggregator_receiver) = oneshot::channel();
            keygen_senders.push(keygen_sender);
            aggregator_receivers.push(aggregator_receiver);

            let chans = ProtocolCommunication::new(keygen_receiver, stream_out_sender.clone());
            let ctx = Context::new(&keygen_init, keygen_init.my_index, my_tofnd_subindex);
            let gg20 = self.clone(); // need to clone service because tokio thread takes ownership

            // set up log state
            let log_info = ctx.log_info();
            let state = log_info.as_str();
            let execute_span = span!(parent: &keygen_span, Level::DEBUG, "execute", state);

            // spawn keygen threads
            tokio::spawn(async move {
                // get result of keygen
                let secret_key_share = gg20.execute_keygen(chans, &ctx, execute_span.clone()).await;
                let _ = aggregator_sender.send(secret_key_share);
            });
        }

        let span = keygen_span.clone();
        tokio::spawn(async move {
            route_messages(&mut stream_in, keygen_senders, span).await;
        });

        // wait for all keygen threads to end, aggregate their responses, and store data in KV store
        self.aggregate_messages(
            aggregator_receivers,
            &mut stream_out_sender,
            key_uid_reservation,
            keygen_init,
        )
        .await?;

        Ok(())
    }

    // aggregate messages from all keygen workers, create a single record and insert it in the KVStore
    async fn aggregate_messages(
        &mut self,
        aggregator_receivers: Vec<oneshot::Receiver<Result<KeygenOutput, TofndError>>>,
        stream_out_sender: &mut mpsc::UnboundedSender<Result<proto::MessageOut, Status>>,
        key_uid_reservation: KeyReservation,
        keygen_init: KeygenInitSanitized,
    ) -> Result<(), TofndError> {
        //  wait all keygen threads and aggregate secret key shares
        let keygen_outputs = aggregate_keygen_outputs(aggregator_receivers).await;
        if keygen_outputs.is_err() {
            self.shares_kv.unreserve_key(key_uid_reservation).await;
            return Err(From::from(
                "Error at Keygen output aggregation. Unreserving key",
            ));
        }
        let keygen_outputs = keygen_outputs.unwrap();

        // clone for later
        let party_uids = keygen_init.party_uids.clone();
        let party_share_counts = keygen_init.party_share_counts.clone();

        // create a hashmap to store pub keys of all shares to make it easier to assert uniqueness
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
                        &party_uids,
                        &party_share_counts,
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
            keygen_init.party_uids,
            keygen_init.party_share_counts,
            keygen_init.my_index,
        );

        // try to put data inside kv store
        self.shares_kv.put(key_uid_reservation, kv_data).await?;

        // serialize generated public key and send to client
        stream_out_sender.send(Ok(proto::MessageOut::new_keygen_result(
            &party_uids,
            &party_share_counts,
            Ok(keygen_result::KeygenOutput {
                pub_key,
                share_recovery_infos,
            }),
        )))?;

        Ok(())
    }
}

// TODO: This is essentially a waiting group. Since what we are doing is trivial
// for now, we can keep as such but consider using a library in the future.
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
