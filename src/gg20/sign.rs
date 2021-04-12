use tofn::protocol::gg20::{
    keygen::SecretKeyShare,
    sign::{Sign, SignOutput},
};

use super::{proto, protocol, route_messages, PartyInfo, ProtocolCommunication};
use crate::{kv_manager::Kv, TofndError};

use protocol::map_tofnd_to_tofn_idx;
use tokio::sync::oneshot;

// tonic cruft
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tonic::Status;

use tracing::{error, info, span, Level, Span};

#[allow(dead_code)] // allow dead code because participant_uids is not used
struct SignInitSanitized {
    new_sig_uid: String, // this is only used for logging
    // key_uid: String,
    participant_uids: Vec<String>,
    participant_indices: Vec<usize>,
    message_to_sign: Vec<u8>,
}

// we wrap the functionality of sign gRPC here because we can't handle errors
// conveniently when spawning theads.
pub async fn handle_sign(
    mut kv: Kv<PartyInfo>,
    mut stream_in: tonic::Streaming<proto::MessageIn>,
    mut stream_out_sender: mpsc::Sender<Result<proto::MessageOut, Status>>,
    sign_span: Span,
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
        info!("abort i'm not a participant");
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
        let all_party_uids = party_info.tofnd.party_uids.clone();
        let all_share_counts = party_info.tofnd.share_counts.clone();
        let participant_tofn_indices: Vec<usize> = get_signer_tofn_indices(
            &party_info.tofnd.share_counts,
            &sign_init.participant_indices,
        );
        let secret_key_share = get_secret_key_share(&party_info, my_tofnd_subindex)?;
        let message_to_sign = sign_init.message_to_sign.clone();

        // TODO better logging
        let log_prefix = format!(
            "sign [{}] party [uid:{}, share:{}/{}]",
            sign_init.new_sig_uid,
            party_info.tofnd.party_uids[party_info.tofnd.index],
            party_info.shares[my_tofnd_subindex].my_index + 1,
            party_info.common.share_count
        );
        let log_prefix = log_prefix.as_str();
        let handle_span = span!(parent: &sign_span, Level::INFO, "Handle", log = log_prefix);
        info!(
            "with (t,n)=({},{}), participant indices: {:?}",
            party_info.common.threshold,
            party_info.common.share_count,
            sign_init.participant_indices
        );

        // spawn keygen threads
        tokio::spawn(async move {
            // get result of sign
            let signature = execute_sign(
                ProtocolCommunication {
                    receiver: sign_receiver,
                    sender: stream_out,
                },
                &all_party_uids,
                &all_share_counts,
                &participant_tofn_indices,
                secret_key_share,
                message_to_sign,
                handle_span,
            )
            .await;
            let _ = aggregator_sender.send(signature);
        });
    }
    // spawn router thread
    let span = sign_span.clone();
    tokio::spawn(async move {
        if let Err(e) = route_messages(&mut stream_in, sign_senders, span).await {
            error!("Error at Sign message router: {}", e);
        }
    });

    // wait for all sign threads to end, get their responses, and return signature
    wait_threads_and_send_sign(aggregator_receivers, &mut stream_out_sender).await?;

    Ok(())
}

// makes all needed assertions on incoming data, and create structures that are
// needed to execute the protocol
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

// sanitize arguments of incoming message.
// Example:
// input for party 'a':
//   (from keygen) party_uids = [a, b, c]
//   (from keygen) party_share_counts = [3, 2, 1]
//   proto::SignInit.party_uids = [c, a]
// output for party 'a':
//   SignInitSanitized.party_uids = [2, 0]  <- index of c, a in party_uids
fn sign_sanitize_args(
    sign_init: proto::SignInit,
    all_party_uids: &[String],
) -> Result<SignInitSanitized, TofndError> {
    // create a vector of the tofnd indices of the participant uids
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

    // TODO assume message_to_sign is already raw bytes of a field element

    Ok(SignInitSanitized {
        new_sig_uid: sign_init.new_sig_uid,
        participant_uids: sign_init.party_uids,
        participant_indices,
        message_to_sign: sign_init.message_to_sign,
    })
}

// TODO: Use CommonInfo and ShareInfo instead of SecretKeyShare in tofn.
// When this is done, we will not have to manually create SecretKeyShare.
fn get_secret_key_share(
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

// execute sign protocol and write the result into the internal channel
async fn execute_sign(
    chan: ProtocolCommunication<Option<proto::TrafficIn>, Result<proto::MessageOut, tonic::Status>>,
    party_uids: &[String],
    party_share_counts: &[usize],
    participant_tofn_indices: &[usize],
    secret_key_share: SecretKeyShare,
    message_to_sign: Vec<u8>,
    handle_span: Span,
) -> Result<SignOutput, TofndError> {
    // Sign::new() needs 'tofn' information:
    let mut sign = Sign::new(
        &secret_key_share,
        &participant_tofn_indices,
        &message_to_sign,
    )?;

    protocol::execute_protocol(
        &mut sign,
        chan,
        &party_uids,
        &party_share_counts,
        &participant_tofn_indices,
        handle_span,
    )
    .await?;

    Ok(sign.clone_output().ok_or("sign output is `None`")?)
}

// waiting group for all sign workers
async fn wait_threads_and_send_sign(
    aggregator_receivers: Vec<oneshot::Receiver<Result<SignOutput, TofndError>>>,
    stream_out_sender: &mut mpsc::Sender<Result<proto::MessageOut, Status>>,
) -> Result<(), TofndError> {
    //  wait all sign threads and get signature
    let mut sign_output = None;
    for aggregator in aggregator_receivers {
        sign_output = Some(aggregator.await??);
    }
    let sign_output = sign_output.ok_or("no output returned from waitgroup")?;

    // send signature to client
    stream_out_sender
        .send(Ok(proto::MessageOut::new_sign_result(sign_output)))
        .await?;

    Ok(())
}

// get all tofn indices of a party
// Example:
// input:
//   sign_uids = [a, c]
//   share_counts = [3, 2, 1]
// output:
//   all_party_tofn_indices: [0, 1, 2, 3, 4, 5]
//                            ^  ^  ^  ^  ^  ^
//                            a  a  a  b  b  c
//   signing_tofn_indices: [0, 1, 2, 5] <- index of a's 3 shares + c's 2 shares
fn get_signer_tofn_indices(share_counts: &[usize], signing_indices: &[usize]) -> Vec<usize> {
    let mut signer_tofn_indices = Vec::new();

    for signing_index in signing_indices {
        let tofn_index = map_tofnd_to_tofn_idx(*signing_index, 0, share_counts);
        for share_count in 0..share_counts[*signing_index] {
            signer_tofn_indices.push(tofn_index + share_count);
        }
    }

    signer_tofn_indices
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
                get_signer_tofn_indices(&t.share_counts, &t.signing_indices),
                t.result
            );
        }
    }
}
