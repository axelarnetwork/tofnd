use tofn::protocol::gg20::keygen::ECPoint;
use tofn::protocol::gg20::keygen::{
    validate_params, CommonInfo, Keygen, SecretKeyShare, ShareInfo,
};

use protocol::map_tofnd_to_tofn_idx;

use super::{
    proto, protocol, route_messages, KeygenInitSanitized, PartyInfo, ProtocolCommunication,
    TofndInfo,
};
use crate::{kv_manager::KeyReservation, kv_manager::Kv, TofndError};

use tokio::sync::oneshot;
use tonic::Status;

// tonic cruft
use tokio::sync::{mpsc, oneshot::Receiver};

use futures_util::StreamExt;

use tracing::{error, span, Level, Span};

// we wrap the functionality of keygen gRPC here because we can't handle errors
// conveniently when spawning theads.
pub async fn handle_keygen(
    mut kv: Kv<PartyInfo>,
    mut stream_in: tonic::Streaming<proto::MessageIn>,
    mut stream_out_sender: mpsc::Sender<Result<proto::MessageOut, Status>>,
    keygen_span: Span,
) -> Result<(), TofndError> {
    // 1. Receive KeygenInit, open message, sanitize arguments
    // 2. Reserve the key in kv store
    // 3. Spawn N keygen threads to execute the protocol in parallel; one of each of our shares to
    // 4. Spawn 1 router thread to route messages from axelar core to the respective keygen thread
    // 5. Wait for all keygen threads to finish and aggregate all SecretKeyShares
    // 6. Create a struct that contains all common and share-spacific information for out party and add it into the KV store

    // get KeygenInit message from stream, sanitize arguments and reserve key
    let (keygen_init, key_uid_reservation) = handle_keygen_init(&mut kv, &mut stream_in).await?;

    // Set log prefix
    let log_prefix = format!(
        "keygen [{}] party [{}] with (t,n)=({},{})",
        keygen_init.new_key_uid,
        keygen_init.party_uids[keygen_init.my_index],
        keygen_init.threshold,
        keygen_init.party_uids.len(),
    );
    let state = log_prefix.as_str();
    let handle_span = span!(parent: &keygen_span, Level::INFO, "", state);
    let _enter = handle_span.enter();

    // find my share count
    let my_share_count = keygen_init.my_shares_count();

    // create in and out channels for each share, and spawn as many threads
    let mut keygen_senders = Vec::new();
    let mut aggregator_receivers = Vec::new();
    let my_starting_tofn_index =
        map_tofnd_to_tofn_idx(keygen_init.my_index, 0, &keygen_init.party_share_counts);

    for my_tofnd_subindex in 0..my_share_count {
        let (keygen_sender, keygen_receiver) = mpsc::channel(4);
        let (aggregator_sender, aggregator_receiver) = oneshot::channel();
        keygen_senders.push(keygen_sender);
        aggregator_receivers.push(aggregator_receiver);

        // make copies to pass to execute keygen thread
        let stream_out = stream_out_sender.clone();
        let uids = keygen_init.party_uids.clone();
        let shares = keygen_init.party_share_counts.clone();
        let party_indices: Vec<usize> = (0..shares.iter().sum()).collect();
        let threshold = keygen_init.threshold;
        let my_tofn_index = my_starting_tofn_index + my_tofnd_subindex;
        let span = handle_span.clone();

        // spawn keygen threads
        tokio::spawn(async move {
            // get result of keygen
            let secret_key_share = execute_keygen(
                ProtocolCommunication {
                    receiver: keygen_receiver,
                    sender: stream_out,
                },
                &uids,
                &shares,
                &party_indices,
                threshold,
                my_tofn_index,
                span,
            )
            .await;
            let _ = aggregator_sender.send(secret_key_share);
        });
    }

    // spawn router thread
    let keygen_span = keygen_span.clone();
    tokio::spawn(async move {
        if let Err(e) = route_messages(&mut stream_in, keygen_senders, keygen_span).await {
            error!("Error at Keygen message router: {}", e);
        }
    });

    // wait for all keygen threads to end, aggregate their responses, and store data in KV store
    aggregate_messages(
        aggregator_receivers,
        &mut stream_out_sender,
        &mut kv,
        key_uid_reservation,
        keygen_init,
    )
    .await?;

    Ok(())
}

// makes all needed assertions on incoming data, and create structures that are
// needed to execute the protocol
async fn handle_keygen_init(
    kv: &mut Kv<PartyInfo>,
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
    let keygen_init = keygen_sanitize_args(keygen_init)?;
    let key_uid_reservation = kv.reserve_key(keygen_init.new_key_uid.clone()).await?;

    Ok((keygen_init, key_uid_reservation))
}

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
fn keygen_sanitize_args(args: proto::KeygenInit) -> Result<KeygenInitSanitized, TofndError> {
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

// execute keygen protocol and write the result into the internal channel
async fn execute_keygen(
    chan: ProtocolCommunication<Option<proto::TrafficIn>, Result<proto::MessageOut, tonic::Status>>,
    party_uids: &[String],
    party_share_counts: &[usize],
    party_indices: &[usize],
    threshold: usize,
    my_index: usize,
    keygen_span: Span,
) -> Result<SecretKeyShare, TofndError> {
    let mut keygen = Keygen::new(party_share_counts.iter().sum(), threshold, my_index)?;
    let secret_key_share = protocol::execute_protocol(
        &mut keygen,
        chan,
        &party_uids,
        &party_share_counts,
        &party_indices,
        keygen_span,
    )
    .await
    .and_then(|_| {
        keygen
            .get_result()
            .ok_or_else(|| From::from("keygen output is `None`"))
    });

    if let Err(e) = secret_key_share {
        return Err(e);
    }
    return Ok(secret_key_share.unwrap().clone());
}

// aggregate messages from all keygen workers, create a single record and insert it in the KVStore
async fn aggregate_messages(
    aggregator_receivers: Vec<oneshot::Receiver<Result<SecretKeyShare, TofndError>>>,
    stream_out_sender: &mut mpsc::Sender<Result<proto::MessageOut, Status>>,
    kv: &mut Kv<PartyInfo>,
    key_uid_reservation: KeyReservation,
    keygen_init: KeygenInitSanitized,
) -> Result<(), TofndError> {
    //  wait all keygen threads and aggregate secret key shares
    let secret_key_shares = aggregate_secret_key_shares(aggregator_receivers).await;
    if secret_key_shares.is_err() {
        kv.unreserve_key(key_uid_reservation).await;
        return Err(From::from(
            "Error at Keygen secret key aggregation. Unreserving key",
        ));
    }
    let secret_key_shares = secret_key_shares.unwrap();

    // get public key and put all secret key shares inside kv store
    let secret_key_share = secret_key_shares[0].clone();
    let pubkey = secret_key_share.ecdsa_public_key.get_element().serialize(); // bitcoin-style serialization

    // compine all keygen threads responses to a single struct
    let kv_data = get_party_info(
        secret_key_shares,
        keygen_init.party_uids,
        keygen_init.party_share_counts,
        keygen_init.my_index,
    );

    // try to put data inside kv store
    kv.put(key_uid_reservation, kv_data).await?;

    // serialize generated public key and send to client
    stream_out_sender
        .send(Ok(proto::MessageOut::new_keygen_result(&pubkey)))
        .await?;

    Ok(())
}

// TODO: This is essentially a waiting group. Since what we are doing is trivial
// for now, we can keep as such but consider using a library in the future.
async fn aggregate_secret_key_shares(
    aggregator_receivers: Vec<Receiver<Result<SecretKeyShare, TofndError>>>,
) -> Result<Vec<SecretKeyShare>, TofndError> {
    let mut secret_key_shares = Vec::with_capacity(aggregator_receivers.len());
    for aggregator in aggregator_receivers {
        let res = aggregator.await??;
        secret_key_shares.push(res);
    }
    Ok(secret_key_shares)
}

// TODO: Use CommonInfo and ShareInfo instead of SecretKeyShare in tofn.
// When this is done, we will not have to manually create PartyInfo.
fn get_party_info(
    secret_key_shares: Vec<SecretKeyShare>,
    uids: Vec<String>,
    share_counts: Vec<usize>,
    tofnd_index: usize,
) -> PartyInfo {
    // grap the first share to acquire common data
    let s = secret_key_shares[0].clone();
    let common = CommonInfo {
        threshold: s.threshold,
        ecdsa_public_key: s.ecdsa_public_key,
        all_ecdsa_public_key_shares: s.all_ecdsa_public_key_shares,
        all_eks: s.all_eks,
        all_zkps: s.all_zkps,
        share_count: s.share_count,
    };
    // aggregate share data into a vector
    let mut shares = Vec::new();
    for share in secret_key_shares {
        shares.push(ShareInfo {
            my_index: share.my_index,
            my_dk: share.my_dk,
            my_ek: share.my_ek,
            my_zkp: share.my_zkp,
            my_ecdsa_secret_key_share: share.my_ecdsa_secret_key_share,
        });
    }
    // add tofnd data
    let tofnd = TofndInfo {
        party_uids: uids,
        share_counts,
        index: tofnd_index,
    };
    PartyInfo {
        common,
        shares,
        tofnd,
    }
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
