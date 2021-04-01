use tofn::protocol::gg20::{keygen::SecretKeyShare, sign::Sign};

use super::{proto, protocol, KeySharesKv, PartyInfo};
use crate::TofndError;

// tonic cruft
use futures_util::StreamExt;
use tokio::sync::mpsc;

// TODO: Use CommonInfo and ShareInfo instead of SecretKeyShare in tofn.
// When this is done, we will not have to manually create PartyInfo
pub(super) fn get_secret_key_share(
    party_info: PartyInfo,
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
        my_index: party_info.common.my_index,
        my_dk: party_info.shares[share_index].my_dk.clone(),
        my_ek: party_info.shares[share_index].my_ek.clone(),
        my_zkp: party_info.shares[share_index].my_zkp.clone(),
        ecdsa_public_key: party_info.common.ecdsa_public_key,
        my_ecdsa_secret_key_share: party_info.shares[share_index].my_ecdsa_secret_key_share,
        all_ecdsa_public_key_shares: party_info.common.all_ecdsa_public_key_shares,
        all_eks: party_info.common.all_eks,
        all_zkps: party_info.common.all_zkps,
    })
}

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
    // let (secret_key_share, all_party_uids) = kv.get(&sign_init.key_uid).await?;
    let party_info = kv.get(&sign_init.key_uid).await?.clone();
    let all_party_uids = party_info.uids.clone();

    // TODO: pass and use the correct share index
    let secret_key_share = get_secret_key_share(party_info, 0)?;

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

    protocol::execute_protocol_sign(
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
