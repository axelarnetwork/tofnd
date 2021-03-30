use tofn::protocol::gg20::keygen::{
    validate_params, CommonInfo, Keygen, SecretKeyShare, ShareInfo,
};

use protocol::TofndP2pMsg;

use super::{proto, protocol, PartyInfo};
use crate::TofndError;

use tofn::fillvec::new_vec_none;
// tonic cruft
use tokio::sync::{mpsc, oneshot::Receiver};

use futures_util::StreamExt;

pub(super) fn get_party_info(
    secret_key_shares: Vec<Option<SecretKeyShare>>,
    uids: Vec<String>,
) -> Result<PartyInfo, TofndError> {
    let s = secret_key_shares[0].clone().unwrap();
    let common = CommonInfo {
        threshold: s.threshold,
        ecdsa_public_key: s.ecdsa_public_key,
        all_ecdsa_public_key_shares: s.all_ecdsa_public_key_shares,
        all_eks: s.all_eks,
        all_zkps: s.all_zkps,
        my_index: s.my_index,
        uids,
        share_count: s.share_count,
    };
    let mut shares = Vec::new();
    for share in secret_key_shares {
        let s = share.ok_or(format!("A secret key share was None"))?;
        shares.push(ShareInfo {
            my_dk: s.my_dk,
            my_ek: s.my_ek,
            my_zkp: s.my_zkp,
            my_ecdsa_secret_key_share: s.my_ecdsa_secret_key_share,
        });
    }
    Ok(PartyInfo { common, shares })
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
    my_share_count: usize,
) -> Result<Vec<Option<SecretKeyShare>>, TofndError> {
    let mut secret_key_shares = new_vec_none(my_share_count);
    for (i, aggregator) in aggregator_receivers.into_iter().enumerate() {
        let res = aggregator.await??;
        secret_key_shares[i] = Some(res);
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
            for i in 0..out_channels.len() {
                let _ = out_channels[i].send(Some(traffic.clone())).await;
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

pub struct KeygenInitSanitized {
    pub new_key_uid: String,
    pub party_uids: Vec<String>,
    pub party_share_counts: Vec<usize>,
    pub my_index: usize,
    pub threshold: usize,
}

impl KeygenInitSanitized {
    pub fn my_shares_count(&self) -> usize {
        self.party_share_counts[self.my_index] as usize
    }
}

pub fn keygen_sanitize_args(args: proto::KeygenInit) -> Result<KeygenInitSanitized, TofndError> {
    use std::convert::TryFrom;
    let my_index = usize::try_from(args.my_party_index)?;
    let threshold = usize::try_from(args.threshold)?;

    // Because usize::try_from(i) may fail and we want to treat this error, we
    // use `Iterator::collect()`'s implementation that returns a
    // Iterator<Result<T,E>> into a Result<Vec<T>,E>.
    // https://doc.rust-lang.org/stable/rust-by-example/error/iter_result.html#fail-the-entire-operation-with-collect
    let party_share_counts: Result<Vec<usize>, _> = args
        .party_share_counts
        .into_iter()
        // Question: try_from returns a result but can't be handled inside map()
        .map(|i| usize::try_from(i))
        .collect();
    let party_share_counts = party_share_counts?;
    let uids_len = args.party_uids.len();
    let shares_len = party_share_counts.len();
    let shares_count = party_share_counts.iter().sum();

    validate_params(uids_len, shares_len, shares_count, threshold, my_index)?;

    /*
    // TODO: decide how (and when) to handle potential faulty data.
    // Commenting out for now

    // sort party ids to get a deterministic ordering
    // find my_index in the newly sorted list
    // check for duplicate party ids
    let old_len = args.party_uids.len();
    let my_uid = args.party_uids[my_index].clone();
    args.party_uids.sort_unstable();
    args.party_uids.dedup();
    if args.party_uids.len() != old_len {
        return Err(From::from("duplicate party ids detected"));
    }
    let my_index = args
        .party_uids
        .iter()
        .enumerate()
        .find(|(_index, id)| **id == my_uid)
        .ok_or("lost my uid after sorting uids")?
        .0;
    */

    Ok(KeygenInitSanitized {
        new_key_uid: args.new_key_uid,
        party_uids: args.party_uids,
        party_share_counts,
        my_index,
        threshold,
    })
}
