use futures_util::StreamExt;
use tracing::{error, info, span, warn, Level, Span};

use tofn::protocol::gg20::keygen::{crimes::Crime, validate_params, KeygenOutput};

use super::{
    proto::{self, message_out::keygen_result},
    protocol::{self, map_tofnd_to_tofn_idx},
    route_messages, Gg20Service, KeygenInitSanitized, PartyInfo, ProtocolCommunication,
};
use crate::{kv_manager::KeyReservation, TofndError};

use tonic::Status;

// tonic cruft
use tokio::sync::{
    mpsc,
    oneshot::{self, Receiver},
};

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
        // 2. Reserve the key in kv store
        // 3. Spawn N keygen threads to execute the protocol in parallel; one of each of our shares to
        // 4. Spawn 1 router thread to route messages from axelar core to the respective keygen thread
        // 5. Wait for all keygen threads to finish and aggregate all SecretKeyShares
        // 6. Create a struct that contains all common and share-spacific information for out party and add it into the KV store

        // get KeygenInit message from stream, sanitize arguments and reserve key
        let (keygen_init, key_uid_reservation) = self.handle_keygen_init(&mut stream_in).await?;

        // Set log prefix
        let log_prefix = format!(
            "[{}] [uid:{}] with (t,n)=({},{})",
            keygen_init.new_key_uid,
            keygen_init.party_uids[keygen_init.my_index],
            keygen_init.threshold,
            keygen_init.party_uids.len(),
        );
        let state = log_prefix.as_str();
        let execute_span = span!(parent: &keygen_span, Level::INFO, "execute", state);
        let _enter = execute_span.enter();

        // find my share count
        let my_share_count = keygen_init.my_shares_count();

        // create in and out channels for each share, and spawn as many threads
        let mut keygen_senders = Vec::new();
        let mut aggregator_receivers = Vec::new();
        let my_starting_tofn_index =
            map_tofnd_to_tofn_idx(keygen_init.my_index, 0, &keygen_init.party_share_counts);

        for my_tofnd_subindex in 0..my_share_count {
            let (keygen_sender, keygen_receiver) = mpsc::unbounded_channel();
            let (aggregator_sender, aggregator_receiver) = oneshot::channel();
            keygen_senders.push(keygen_sender);
            aggregator_receivers.push(aggregator_receiver);

            // make copies to pass to execute keygen thread
            let stream_out = stream_out_sender.clone();
            let uids = keygen_init.party_uids.clone();
            let shares = keygen_init.party_share_counts.clone();
            let threshold = keygen_init.threshold;
            let nonce = keygen_init.new_key_uid.clone();
            let my_tofn_index = my_starting_tofn_index + my_tofnd_subindex;
            let span = execute_span.clone();

            let gg20 = self.clone();

            // spawn keygen threads
            tokio::spawn(async move {
                // get result of keygen
                let secret_key_share = gg20
                    .execute_keygen(
                        ProtocolCommunication {
                            receiver: keygen_receiver,
                            sender: stream_out,
                        },
                        &uids,
                        &shares,
                        threshold,
                        my_tofn_index,
                        span,
                        &nonce.as_bytes(),
                    )
                    .await;
                let _ = aggregator_sender.send(secret_key_share);
            });
        }

        let span = execute_span.clone();
        tokio::spawn(async move {
            if let Err(e) = route_messages(&mut stream_in, keygen_senders, span).await {
                error!("Error at Keygen message router: {}", e);
            }
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

    // This function is pub(super) because it is also needed in handle_recover
    // sanitize arguments of incoming message.
    // Example:
    // input for party 'a':
    //   args.party_uids = [c, b, a]
    //   args.party_share_counts = [1, 2, 3]
    //   args.my_party_index = 2
    //   args.threshold = 1
    // output for party 'a':
    //   keygen_init.party_uids = [a, b, c]           <- sorted array
    //   keygen_init.party_share_counts = [3, 2, 1] . <- sorted with respect to party_uids
    //   keygen_init.my_party_index = 0 .             <- index inside sorted array
    //   keygen_init.threshold = 1                    <- same as in input
    pub(crate) fn keygen_sanitize_args(
        args: proto::KeygenInit,
    ) -> Result<KeygenInitSanitized, TofndError> {
        // convert `u32`s to `usize`s
        use std::convert::TryFrom;
        let my_index = usize::try_from(args.my_party_index)?;
        let threshold = usize::try_from(args.threshold)?;
        let mut party_share_counts = args
            .party_share_counts
            .iter()
            .map(|i| usize::try_from(*i))
            .collect::<Result<Vec<usize>, _>>()?;

        // keep backwards compatibility with axelar-core that doesn't use multiple shares
        if party_share_counts.is_empty() {
            party_share_counts = vec![1; args.party_uids.len()];
        }

        // store total number of shares of all parties
        let total_shares = party_share_counts.iter().sum();

        // assert that uids and party shares are alligned
        if args.party_uids.len() != party_share_counts.len() {
            return Err(From::from(format!(
                "uid vector and share counts vector not alligned: {:?}, {:?}",
                args.party_uids, party_share_counts,
            )));
        }

        // sort uids and share counts
        // we need to sort uids and shares because the caller (axelar-core) does not
        // necessarily send the same vectors (in terms of order) to all tofnd instances.
        let (my_new_index, sorted_uids, sorted_share_counts) =
            sort_uids_and_shares(my_index, args.party_uids, party_share_counts)?;

        // make tofn validation
        validate_params(total_shares, threshold, my_index)?;

        Ok(KeygenInitSanitized {
            new_key_uid: args.new_key_uid,
            party_uids: sorted_uids,
            party_share_counts: sorted_share_counts,
            my_index: my_new_index,
            threshold,
        })
    }

    // makes all needed assertions on incoming data, and create structures that are
    // needed to execute the protocol
    async fn handle_keygen_init(
        &mut self,
        stream: &mut tonic::Streaming<proto::MessageIn>,
    ) -> Result<(KeygenInitSanitized, KeyReservation), TofndError> {
        // receive message
        let msg_type = stream
            .next()
            .await
            .ok_or("keygen: stream closed by client without sending a message")??
            .data
            .ok_or("keygen: missing `data` field in client message")?;

        // check if message is of expected type
        let keygen_init = match msg_type {
            proto::message_in::Data::KeygenInit(k) => k,
            _ => return Err(From::from("Expected keygen init message")),
        };

        // sanitize arguments and reserve key
        let keygen_init = Self::keygen_sanitize_args(keygen_init)?;
        let key_uid_reservation = self
            .shares_kv
            .reserve_key(keygen_init.new_key_uid.clone())
            .await?;

        info!(
            "Starting Keygen with uids: {:?}, party_shares: {:?}",
            keygen_init.party_uids, keygen_init.party_share_counts
        );

        Ok((keygen_init, key_uid_reservation))
    }

    // execute keygen protocol and write the result into the internal channel
    #[allow(clippy::too_many_arguments)]
    async fn execute_keygen(
        &self,
        chan: ProtocolCommunication<
            Option<proto::TrafficIn>,
            Result<proto::MessageOut, tonic::Status>,
        >,
        party_uids: &[String],
        party_share_counts: &[usize],
        threshold: usize,
        my_index: usize,
        keygen_span: Span,
        nonce: &[u8],
    ) -> Result<KeygenOutput, TofndError> {
        let seed = self.seed().await?;
        let keygen = self.get_keygen(
            party_share_counts.iter().sum(),
            threshold,
            my_index,
            &seed,
            &nonce,
        );
        let mut keygen = keygen.unwrap();

        // execute protocol
        let res = protocol::execute_protocol(
            &mut keygen,
            chan,
            &party_uids,
            &party_share_counts,
            keygen_span.clone(),
        )
        .await;

        let result_span = span!(parent: &keygen_span, Level::INFO, "result");
        let _enter = result_span.enter();

        let res = match res {
            Ok(()) => {
                info!("Keygen completed successfully");
                keygen.clone_output().ok_or("keygen output is `None`")?
            }
            Err(err) => match keygen.found_disrupting() {
                true => {
                    warn!("Party failed due to deserialization error: {}", err);
                    keygen.clone_output().ok_or("keygen output is `None`")?
                }
                false => {
                    warn!("Connection closed by client: {}", err);
                    Err(keygen.waiting_on())
                }
            },
        };
        Ok(res)
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

// co-sort uids and shares with respect to uids an find new index
fn sort_uids_and_shares(
    my_index: usize,
    uids: Vec<String>,
    share_counts: Vec<usize>,
) -> Result<(usize, Vec<String>, Vec<usize>), TofndError> {
    // save my uid
    let my_uid = uids[my_index].clone();

    // create a vec of (uid, share_count) and sort it
    let mut pairs: Vec<(String, usize)> = uids.into_iter().zip(share_counts.into_iter()).collect();
    pairs.sort();

    // unzip vec and search for duplicates in uids
    let (mut sorted_uids, sorted_share_counts): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    let old_len = sorted_uids.len();
    sorted_uids.dedup();
    if old_len != sorted_uids.len() {
        return Err(From::from("Error: party_uid vector contained a duplicate"));
    }

    // find my new index
    let my_index = sorted_uids
        .iter()
        .position(|x| x == &my_uid)
        .ok_or("Lost my uid after sorting uids")?;

    Ok((my_index, sorted_uids, sorted_share_counts))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_uids_and_shares() {
        let in_pairs = vec![
            ("c".to_owned(), 1),
            ("b".to_owned(), 2),
            ("a".to_owned(), 3),
        ];
        let out_pairs = vec![
            ("a".to_owned(), 3),
            ("b".to_owned(), 2),
            ("c".to_owned(), 1),
        ];

        let (in_keys, in_values): (Vec<String>, Vec<usize>) = in_pairs.into_iter().unzip();
        let (out_keys, out_values): (Vec<String>, Vec<usize>) = out_pairs.into_iter().unzip();

        let res = sort_uids_and_shares(0, in_keys.clone(), in_values.clone()).unwrap();
        assert_eq!((2, out_keys.clone(), out_values.clone()), res);
        let res = sort_uids_and_shares(1, in_keys.clone(), in_values.clone()).unwrap();
        assert_eq!((1, out_keys.clone(), out_values.clone()), res);
        let res = sort_uids_and_shares(2, in_keys, in_values).unwrap();
        assert_eq!((0, out_keys, out_values), res);

        let err_pairs = vec![("a".to_owned(), 1), ("a".to_owned(), 2)];
        let (err_keys, err_values): (Vec<String>, Vec<usize>) = err_pairs.into_iter().unzip();
        assert!(sort_uids_and_shares(0, err_keys.clone(), err_values.clone()).is_err());
        assert!(sort_uids_and_shares(1, err_keys, err_values).is_err());
    }
}
