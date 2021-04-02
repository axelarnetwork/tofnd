use tofn::protocol::gg20::{keygen::SecretKeyShare, sign::Sign};

use super::{proto, protocol, route_messages, PartyInfo};
use crate::{kv_manager::Kv, TofndError};

use protocol::map_tofnd_to_tofn_idx;
use tokio::sync::oneshot;

// tonic cruft
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tonic::Status;

pub async fn handle_sign(
    mut kv: Kv<PartyInfo>,
    mut stream_in: tonic::Streaming<proto::MessageIn>,
    mut stream_out_sender: mpsc::Sender<Result<proto::MessageOut, Status>>,
) -> Result<(), TofndError> {
    // 1. Receive SignInit, open message, sanitize arguments
    // 2. Spawn N sign threads to execute the protocol in parallel; one of each of our shares
    // 3. Spawn 1 router thread to route messages from axelar core to the respective sign thread
    // 4. Wait for all sign threads to finish and aggregate all responses

    // get SignInit message from stream and sanitize arguments
    let (sign_init, party_info) = handle_sign_init(&mut kv, &mut stream_in).await?;

    // quit now if I'm not a participant
    if sign_init
        .participant_indices
        .iter()
        .find(|&&i| i == party_info.tofnd.index)
        .is_none()
    {
        println!("abort i'm not a participant");
        return Ok(());
    }

    // find my share count
    let my_share_count = party_info.shares.len();
    // create in and out channels for each share, and spawn as many threads
    let mut sign_senders = Vec::new();
    let mut aggregator_receivers = Vec::new();

    for my_tofnd_subindex in 0..my_share_count {
        let (sign_sender, sign_receiver) = mpsc::channel(4);
        let (aggregator_sender, aggregator_receiver) = oneshot::channel();
        sign_senders.push(sign_sender);
        aggregator_receivers.push(aggregator_receiver);

        // make copies to pass to execute sign thread
        let stream_out = stream_out_sender.clone();
        // let participant_uids = sign_init.participant_uids.clone();
        let all_party_uids = party_info.tofnd.party_uids.clone();
        let all_share_counts = party_info.tofnd.share_counts.clone();
        let participant_tofn_indices: Vec<usize> = get_party_tofn_indices(
            &party_info.tofnd.share_counts,
            &sign_init.participant_indices,
        );
        let secret_key_share = get_secret_key_share(&party_info, my_tofnd_subindex)?;
        let message_to_sign = sign_init.message_to_sign.clone();

        // spawn keygen threads
        tokio::spawn(async move {
            // get result of keygen
            let signature = execute_sign(
                sign_receiver,
                stream_out,
                &all_party_uids,
                &all_share_counts,
                &participant_tofn_indices,
                secret_key_share,
                message_to_sign,
            )
            .await;
            let _ = aggregator_sender.send(signature);
        });
    }
    // spawn router thread
    tokio::spawn(async move {
        if let Err(e) = route_messages(&mut stream_in, sign_senders).await {
            println!("Error at Keygen message router: {}", e);
        }
    });

    // wait for all sign threads to end, get their responses, and return signature
    wait_threads_and_send_sign(aggregator_receivers, &mut stream_out_sender).await?;

    Ok(())
}

async fn handle_sign_init(
    kv: &mut Kv<PartyInfo>,
    stream: &mut tonic::Streaming<proto::MessageIn>,
) -> Result<(SignInitSanitized, PartyInfo), TofndError> {
    let msg_type = stream
        .next()
        .await
        .ok_or("sign: stream closed by client without sending a message")??
        .data
        .ok_or("sign: missing `data` field in client message")?;

    let sign_init = match msg_type {
        proto::message_in::Data::SignInit(k) => k,
        _ => return Err(From::from("Expected sign init message")),
    };

    let party_info = kv.get(&sign_init.key_uid).await?;
    let sign_init = sign_sanitize_args(sign_init, &party_info.tofnd.party_uids)?;

    Ok((sign_init, party_info))
}

fn sign_sanitize_args(
    sign_init: proto::SignInit,
    all_party_uids: &[String],
) -> Result<SignInitSanitized, TofndError> {
    let participant_indices = sign_init
        .party_uids
        .iter()
        .map(|s| {
            all_party_uids.iter().position(|k| k == s).ok_or(format!(
                "participant [{}] not found in key [{}]",
                s, sign_init.key_uid
            ))
        })
        .collect::<Result<Vec<usize>, _>>()?;

    // Question: this only reconstructs sign_init.party_uids; do we need it?
    let participant_uids: Vec<String> = participant_indices
        .iter()
        .map(|&i| all_party_uids[i].clone())
        .collect();

    // TODO assume message_to_sign is already raw bytes of a field element

    Ok(SignInitSanitized {
        new_sig_uid: sign_init.new_sig_uid,
        // key_uid: sign_init.key_uid,
        participant_uids,
        participant_indices,
        message_to_sign: sign_init.message_to_sign,
    })
}

// TODO: Use CommonInfo and ShareInfo instead of SecretKeyShare in tofn.
// When this is done, we will not have to manually create PartyInfo
pub(super) fn get_secret_key_share(
    party_info: &PartyInfo,
    share_index: usize,
) -> Result<SecretKeyShare, TofndError> {
    if share_index >= party_info.shares.len() {
        return Err(From::from(format!(
            "Requested share {} is out of bounds {}",
            share_index,
            party_info.shares.len(),
        )));
    }
    Ok(SecretKeyShare {
        share_count: party_info.common.share_count,
        threshold: party_info.common.threshold,
        my_index: party_info.shares[share_index].my_index,
        my_dk: party_info.shares[share_index].my_dk.clone(),
        my_ek: party_info.shares[share_index].my_ek.clone(),
        my_zkp: party_info.shares[share_index].my_zkp.clone(),
        ecdsa_public_key: party_info.common.ecdsa_public_key,
        my_ecdsa_secret_key_share: party_info.shares[share_index].my_ecdsa_secret_key_share,
        all_ecdsa_public_key_shares: party_info.common.all_ecdsa_public_key_shares.clone(),
        all_eks: party_info.common.all_eks.clone(),
        all_zkps: party_info.common.all_zkps.clone(),
    })
}

pub(super) async fn execute_sign(
    channel: mpsc::Receiver<Option<proto::TrafficIn>>,
    mut msg_sender: mpsc::Sender<Result<proto::MessageOut, tonic::Status>>,
    party_uids: &[String],
    party_share_counts: &[usize],
    participant_tofn_indices: &[usize],
    secret_key_share: SecretKeyShare,
    message_to_sign: Vec<u8>,
) -> Result<Vec<u8>, TofndError> {
    // Sign::new() needs 'tofn' information:
    // if
    // * from tofnd: party_uids: [a, b, c]
    // * from tofnd: party_share_counts: [2, 1, 1]
    // * from tofn:  participant_uids: [a, c]
    // then
    // * for tofn: party_uids: [a, a, b, c]
    // * for tofn: participant_indices: [0, 1, 3]
    let mut sign = Sign::new(
        &secret_key_share,
        &participant_tofn_indices,
        &message_to_sign,
    )?;

    protocol::execute_protocol(
        &mut sign,
        channel,
        &mut msg_sender,
        &party_uids,
        &party_share_counts,
        &participant_tofn_indices,
        "log",
    )
    .await?;
    let signature = sign.get_result().ok_or("sign output is `None`")?;

    // serialize generated signature and send to client
    // TODO how do I serialize in proper bitcoin format?
    Ok(signature.as_bytes().to_owned())
}

pub async fn wait_threads_and_send_sign(
    aggregator_receivers: Vec<oneshot::Receiver<Result<Vec<u8>, TofndError>>>,
    stream_out_sender: &mut mpsc::Sender<Result<proto::MessageOut, Status>>,
) -> Result<(), TofndError> {
    //  wait all sign threads and get signature
    let mut signature = Vec::new();
    for aggregator in aggregator_receivers {
        signature = aggregator.await??;
    }

    // send signature to client
    stream_out_sender
        .send(Ok(proto::MessageOut::new_sign_result(&signature)))
        .await?;

    Ok(())
}

struct SignInitSanitized {
    new_sig_uid: String,
    // key_uid: String,
    participant_uids: Vec<String>,
    participant_indices: Vec<usize>,
    message_to_sign: Vec<u8>,
}

fn get_party_tofn_indices(share_counts: &[usize], signing_indices: &[usize]) -> Vec<usize> {
    let mut party_tofn_indices = Vec::new();

    for signing_index in signing_indices {
        let tofn_index = map_tofnd_to_tofn_idx(*signing_index, 0, share_counts);
        for share_count in 0..share_counts[*signing_index] {
            party_tofn_indices.push(tofn_index + share_count);
        }
    }

    party_tofn_indices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tofn_indices() {
        struct Test {
            share_counts: Vec<usize>,
            signing_indices: Vec<usize>,
            result: Vec<usize>,
        }

        let tests = vec![
            Test {
                share_counts: vec![1, 1, 1, 1],
                signing_indices: vec![0, 2],
                result: vec![0, 2],
            },
            Test {
                share_counts: vec![1, 1, 1, 2],
                signing_indices: vec![0, 3],
                result: vec![0, 3, 4],
            },
            Test {
                share_counts: vec![2, 1, 4, 1],
                signing_indices: vec![0, 2],
                result: vec![0, 1, 3, 4, 5, 6],
            },
        ];

        for t in tests {
            assert_eq!(
                get_party_tofn_indices(&t.share_counts, &t.signing_indices),
                t.result
            );
        }
    }
}
