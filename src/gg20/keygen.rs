use tofn::protocol::gg20::keygen::{
    validate_params, CommonInfo, Keygen, SecretKeyShare, ShareInfo,
};

use protocol::TofndP2pMsg;

use super::{proto, protocol, KeygenInitSanitized, PartyInfo};
use crate::TofndError;

// tonic cruft
use tokio::sync::{mpsc, oneshot::Receiver};

use futures_util::StreamExt;

pub(super) fn get_party_info(
    secret_key_shares: Vec<SecretKeyShare>,
    uids: Vec<String>,
) -> Result<PartyInfo, TofndError> {
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
    Ok(PartyInfo {
        common,
        shares,
        uids,
    })
}

pub(super) async fn handle_keygen_init(
    stream: &mut tonic::Streaming<proto::MessageIn>,
) -> Result<KeygenInitSanitized, TofndError> {
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

    keygen_sanitize_args(keygen_init)
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
