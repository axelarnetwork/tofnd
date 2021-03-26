use tofn::protocol::gg20::{keygen::SecretKeyShare, sign::Sign};

use super::{proto, protocol, KeySharesKv};
use crate::TofndError;

// tonic cruft
use futures_util::StreamExt;
use tokio::sync::mpsc;

pub(super) async fn execute_sign(
    stream: &mut tonic::Streaming<proto::MessageIn>,
    mut msg_sender: mpsc::Sender<Result<proto::MessageOut, tonic::Status>>,
    mut kv: KeySharesKv,
) -> Result<(), TofndError> {
    // sign init
    let msg_type = stream
        .next()
        .await
        .ok_or("sign: stream closed by client without sending a message")??
        .data
        .ok_or("sign: missing `data` field in client messge")?;
    let sign_init = match msg_type {
        proto::message_in::Data::SignInit(s) => s,
        _ => {
            return Err(From::from("sign: first client message must be sign init"));
        }
    };
    let (secret_key_share, all_party_uids) = kv.get(&sign_init.key_uid).await?;
    let sign_init = sign_sanitize_args(sign_init, &secret_key_share, &all_party_uids)?;

    // TODO better logging
    let log_prefix = format!(
        "sign [{}] party [{}]",
        sign_init.new_sig_uid, all_party_uids[secret_key_share.my_index]
    );
    println!(
        "begin {} with (t,n)=({},{}), participant indices: {:?}",
        log_prefix,
        secret_key_share.threshold,
        secret_key_share.share_count,
        sign_init.participant_indices
    );

    // quit now if I'm not a participant
    if sign_init
        .participant_indices
        .iter()
        .find(|&&i| i == secret_key_share.my_index)
        .is_none()
    {
        println!("abort {} i'm not a participant", log_prefix,);
        return Ok(());
    }

    // sign execute
    let mut sign = Sign::new(
        &secret_key_share,
        &sign_init.participant_indices,
        &sign_init.message_to_sign,
    )?;
    protocol::execute_protocol(
        &mut sign,
        stream,
        &mut msg_sender,
        &sign_init.participant_uids,
        &log_prefix,
    )
    .await?;
    let signature = sign.get_result().ok_or("sign output is `None`")?;

    // serialize generated signature and send to client
    // TODO how do I serialize in proper bitcoin format?
    msg_sender
        .send(Ok(proto::MessageOut::new_sign_result(signature.as_bytes())))
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

fn sign_sanitize_args(
    sign_init: proto::SignInit,
    _secret_key_share: &SecretKeyShare,
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
