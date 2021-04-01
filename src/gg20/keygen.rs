use tofn::protocol::gg20::keygen::ECPoint;
use tofn::protocol::gg20::keygen::{
    validate_params, CommonInfo, Keygen, SecretKeyShare, ShareInfo,
};

use protocol::{map_tofnd_to_tofn_idx, TofndP2pMsg};

use super::{proto, protocol, KeygenInitSanitized, PartyInfo};
use crate::{kv_manager::KeyReservation, kv_manager::Kv, TofndError};

use tokio::sync::oneshot;
use tonic::Status;

// tonic cruft
use tokio::sync::{mpsc, oneshot::Receiver};

use futures_util::StreamExt;

pub async fn handle_keygen(
    mut kv: Kv<PartyInfo>,
    mut stream_in: tonic::Streaming<proto::MessageIn>,
    mut stream_out_sender: mpsc::Sender<Result<proto::MessageOut, Status>>,
) -> Result<(), TofndError> {
    // spawn a master thread to immediately return from gRPC
    // Inside this master thread, we do the following:
    // 1. Receive KeygenInit, open message, sanitize arguments
    // 2. Reserve the key in kv store
    // 3. Spawn N keygen threads to execute the protocol in parallel; one of each of our shares to
    // 4. Spawn 1 router thread to route messages from axelar core to the respective keygen thread
    // 5. Wait for all keygen threads to finish and aggregate all SecretKeyShares
    // 6. Create a struct that contains all common and share-spacific information for out party and add it into the KV store

    // get KeygenInit message from stream, sanitize arguments and reserve key
    let (keygen_init, key_uid_reservation) = handle_keygen_init(&mut kv, &mut stream_in).await?;

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
        let threshold = keygen_init.threshold;
        let my_tofn_index = my_starting_tofn_index + my_tofnd_subindex;

        // spawn keygen threads
        tokio::spawn(async move {
            // get result of keygen
            let secret_key_share = execute_keygen(
                keygen_receiver,
                stream_out,
                &uids,
                &shares,
                threshold,
                my_tofn_index,
                "log:".to_owned(),
            )
            .await;
            let _ = aggregator_sender.send(secret_key_share);
        });
    }

    // spawn router thread
    tokio::spawn(async move {
        if let Err(e) = route_messages(&mut stream_in, keygen_senders).await {
            println!("Error at Keygen message router: {}", e);
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

pub(super) async fn handle_keygen_init(
    kv: &mut Kv<PartyInfo>,
    stream: &mut tonic::Streaming<proto::MessageIn>,
) -> Result<(KeygenInitSanitized, KeyReservation), TofndError> {
    let msg_type = stream
        .next()
        .await
        .ok_or("keygen: stream closed by client without sending a message")??
        .data
        .ok_or("keygen: missing `data` field in client message")?;

    let keygen_init = match msg_type {
        proto::message_in::Data::KeygenInit(k) => k,
        _ => return Err(From::from("Expected keygen init message")),
    };

    let keygen_init = keygen_sanitize_args(keygen_init)?;
    let key_uid_reservation = kv.reserve_key(keygen_init.new_key_uid.clone()).await?;

    Ok((keygen_init, key_uid_reservation))
}

pub fn keygen_sanitize_args(args: proto::KeygenInit) -> Result<KeygenInitSanitized, TofndError> {
    use std::convert::TryFrom;
    let my_index = usize::try_from(args.my_party_index)?;
    let threshold = usize::try_from(args.threshold)?;
    let party_share_counts = args
        .party_share_counts
        .iter()
        .map(|i| usize::try_from(*i))
        .collect::<Result<Vec<usize>, _>>()?;
    let total_shares = party_share_counts.iter().sum();

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
        sort_uids_and_shares(my_index, &args.party_uids, &party_share_counts)?;

    validate_params(total_shares, threshold, my_index)?;

    Ok(KeygenInitSanitized {
        new_key_uid: args.new_key_uid,
        party_uids: sorted_uids,
        party_share_counts: sorted_share_counts,
        my_index: my_new_index,
        threshold,
    })
}

fn sort_uids_and_shares(
    my_index: usize,
    uids: &[String],
    share_counts: &[usize],
) -> Result<(usize, Vec<String>, Vec<usize>), TofndError> {
    // save my uid
    let my_uid = uids[my_index].clone();

    // create a vec of (uid, share_count) and sort it
    let mut pairs: Vec<(String, usize)> = uids
        .iter()
        .cloned()
        .zip(share_counts.iter().cloned())
        .collect();
    pairs.sort();

    // unzip vec and search for duplicates in uids
    let (mut sorted_uids, sorted_share_counts): (Vec<_>, Vec<_>) = pairs.iter().cloned().unzip();
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

pub(super) async fn execute_keygen(
    channel: mpsc::Receiver<Option<proto::TrafficIn>>,
    mut msg_sender: mpsc::Sender<Result<proto::MessageOut, tonic::Status>>,
    party_uids: &[String],
    party_share_counts: &[usize],
    threshold: usize,
    my_index: usize,
    log_prefix: String,
) -> Result<SecretKeyShare, TofndError> {
    // keygen execute
    let mut keygen = Keygen::new(party_share_counts.iter().sum(), threshold, my_index)?;
    // unreserve new_key_uid on failure
    // too bad try blocks are not yet stable in Rust https://doc.rust-lang.org/nightly/unstable-book/language-features/try-blocks.html
    // instead I'll use the less-readable `and_then` https://doc.rust-lang.org/std/result/enum.Result.html#method.and_then
    let secret_key_share = protocol::execute_protocol(
        &mut keygen,
        channel,
        &mut msg_sender,
        &party_uids,
        &party_share_counts,
        &log_prefix,
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

pub(super) async fn route_messages(
    in_stream: &mut tonic::Streaming<proto::MessageIn>,
    mut out_channels: Vec<mpsc::Sender<Option<proto::TrafficIn>>>,
) -> Result<(), TofndError> {
    loop {
        let msg_data = in_stream.next().await;

        if msg_data.is_none() {
            println!("Stream closed");
            break;
        }

        let msg_data = msg_data.unwrap()?.data;

        // I wish I could do `if !let` https://github.com/rust-lang/rfcs/pull/1303
        if msg_data.is_none() {
            println!("WARNING: ignore incoming msg: missing `data` field");
            continue;
        }
        let traffic = match msg_data.unwrap() {
            proto::message_in::Data::Traffic(t) => t,
            _ => {
                println!("WARNING: ignore incoming msg: expect `data` to be TrafficIn type");
                continue;
            }
        };
        // if message is broadcast, send it to all keygen threads.
        // if it's a p2p message, send it only to the corresponding keygen. In
        // case of p2p we have to also wrap the share we are refering to, so we
        // unwrap the message and read the 'subindex' field.
        if traffic.is_broadcast {
            for out_channel in &mut out_channels {
                let _ = out_channel.send(Some(traffic.clone())).await;
            }
        } else {
            let tofnd_msg: TofndP2pMsg = bincode::deserialize(&traffic.payload)?;
            let my_share_index: usize = tofnd_msg.subindex;
            let _ = out_channels[my_share_index].send(Some(traffic)).await;
        }
    }
    Ok(())
}

pub async fn aggregate_messages(
    aggregator_receivers: Vec<oneshot::Receiver<Result<SecretKeyShare, TofndError>>>,
    stream_out_sender: &mut mpsc::Sender<Result<proto::MessageOut, Status>>,
    kv: &mut Kv<PartyInfo>,
    key_uid_reservation: KeyReservation,
    keygen_init: KeygenInitSanitized,
) -> Result<(), TofndError> {
    //  wait all keygen threads and aggregare secret key shares
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
    let kv_data = get_party_info(secret_key_shares, keygen_init.party_uids);

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
pub(super) async fn aggregate_secret_key_shares(
    aggregator_receivers: Vec<Receiver<Result<SecretKeyShare, TofndError>>>,
) -> Result<Vec<SecretKeyShare>, TofndError> {
    // let mut secret_key_shares = new_vec_none(my_share_count);
    let mut secret_key_shares = Vec::with_capacity(aggregator_receivers.len());
    for aggregator in aggregator_receivers {
        let res = aggregator.await??;
        secret_key_shares.push(res);
    }
    Ok(secret_key_shares)
}

pub(super) fn get_party_info(
    secret_key_shares: Vec<SecretKeyShare>,
    uids: Vec<String>,
) -> PartyInfo {
    let s = secret_key_shares[0].clone();
    let common = CommonInfo {
        threshold: s.threshold,
        ecdsa_public_key: s.ecdsa_public_key,
        all_ecdsa_public_key_shares: s.all_ecdsa_public_key_shares,
        all_eks: s.all_eks,
        all_zkps: s.all_zkps,
        my_index: s.my_index,
        share_count: s.share_count,
    };
    let mut shares = Vec::new();
    for share in secret_key_shares {
        shares.push(ShareInfo {
            my_dk: share.my_dk,
            my_ek: share.my_ek,
            my_zkp: share.my_zkp,
            my_ecdsa_secret_key_share: share.my_ecdsa_secret_key_share,
        });
    }
    PartyInfo {
        common,
        shares,
        uids,
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

        let res = sort_uids_and_shares(0, &in_keys, &in_values).unwrap();
        assert_eq!((2, out_keys.clone(), out_values.clone()), res);
        let res = sort_uids_and_shares(1, &in_keys, &in_values).unwrap();
        assert_eq!((1, out_keys.clone(), out_values.clone()), res);
        let res = sort_uids_and_shares(2, &in_keys, &in_values).unwrap();
        assert_eq!((0, out_keys, out_values), res);

        let err_pairs = vec![("a".to_owned(), 1), ("a".to_owned(), 2)];
        let (err_keys, err_values): (Vec<String>, Vec<usize>) = err_pairs.into_iter().unzip();
        assert!(sort_uids_and_shares(0, &err_keys, &err_values).is_err());
        assert!(sort_uids_and_shares(1, &err_keys, &err_values).is_err());
    }
}
