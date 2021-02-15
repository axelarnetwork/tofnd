use tofn::protocol::{
    gg20::{
        keygen::{self, ECPoint, Keygen, SecretKeyShare},
        sign::Sign,
    },
    Protocol,
};

use super::proto;
use crate::{kv_manager::KV, TofndError};

// tonic cruft
use futures_util::StreamExt;
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};
// use std::pin::Pin;
// use futures_core::Stream;

struct GG20Service {
    kv: KV<(SecretKeyShare, Vec<String>)>, // TODO don't store party_uids in this daemon!
}

pub fn new_service() -> impl proto::gg20_server::Gg20 {
    GG20Service { kv: KV::new() }
}

#[tonic::async_trait]
impl proto::gg20_server::Gg20 for GG20Service {
    // type KeygenStream = Pin<Box<dyn Stream<Item = Result<proto::MessageOut, Status>> + Send + Sync + 'static>>;
    type KeygenStream = mpsc::Receiver<Result<proto::MessageOut, Status>>;
    type SignStream = Self::KeygenStream;

    // TODO delete get_key, get_sign?
    async fn get_key(
        &self,
        request: Request<proto::Uid>,
    ) -> Result<Response<proto::Bytes>, Status> {
        println!("get_key uid {:?}", request.get_ref());
        Ok(Response::new(proto::Bytes {
            payload: vec![1, 2, 3],
        }))
    }

    async fn get_sig(
        &self,
        request: Request<proto::Uid>,
    ) -> Result<Response<proto::Bytes>, Status> {
        println!("get_sig uid {:?}", request.get_ref());
        Ok(Response::new(proto::Bytes {
            payload: vec![3, 2, 1],
        }))
    }

    async fn keygen(
        &self,
        request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::KeygenStream>, Status> {
        let mut stream = request.into_inner();
        let (msg_sender, rx) = mpsc::channel(4);
        let kv = self.kv.clone();

        tokio::spawn(async move {
            // can't return an error from a spawned thread
            if let Err(e) = execute_keygen(&mut stream, msg_sender, kv).await {
                println!("keygen failure: {:?}", e);
                return;
            }
        });
        Ok(Response::new(rx))
    }

    async fn sign(
        &self,
        request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::KeygenStream>, Status> {
        let mut stream = request.into_inner();
        let (msg_sender, rx) = mpsc::channel(4);
        let kv = self.kv.clone();

        tokio::spawn(async move {
            // can't return an error from a spawned thread
            if let Err(e) = execute_sign(&mut stream, msg_sender, kv).await {
                println!("sign failure: {:?}", e);
                return;
            }
        });
        Ok(Response::new(rx))
    }
}

async fn execute_protocol(
    protocol: &mut impl Protocol,
    stream: &mut tonic::Streaming<proto::MessageIn>,
    mut msg_sender: mpsc::Sender<Result<proto::MessageOut, tonic::Status>>,
    party_uids: &[String],
) -> Result<(), TofndError> {
    // TODO runs an extra iteration!
    while !protocol.done() {
        protocol.next_round()?;

        // send outgoing messages
        let bcast = protocol.get_bcast_out();
        if let Some(bcast) = bcast {
            msg_sender
                .send(Ok(proto::MessageOut::new_bcast(bcast)))
                .await?;
        }
        let p2ps = protocol.get_p2p_out();
        if let Some(p2ps) = p2ps {
            for (i, p2p) in p2ps.iter().enumerate() {
                if let Some(p2p) = p2p {
                    msg_sender
                        .send(Ok(proto::MessageOut::new_p2p(&party_uids[i], p2p)))
                        .await?;
                }
            }
        }

        // collect incoming messages
        while protocol.expecting_more_msgs_this_round() {
            let msg_data = stream
                .next()
                .await
                .ok_or("stream closed by client before protocol has completed")??
                .data;
            // I wish I could do `if !let` https://github.com/rust-lang/rfcs/pull/1303
            if msg_data.is_none() {
                println!("WARN: ignore client message: missing `data` field");
                continue;
            }
            let traffic = match msg_data.unwrap() {
                proto::message_in::Data::Traffic(t) => t,
                _ => {
                    println!("WARN: ignore client message: expected `data` to be TrafficIn type");
                    continue;
                }
            };
            protocol.set_msg_in(&traffic.payload)?;
        }
    }
    Ok(())
}

async fn execute_sign(
    stream: &mut tonic::Streaming<proto::MessageIn>,
    mut msg_sender: mpsc::Sender<Result<proto::MessageOut, tonic::Status>>,
    mut kv: KV<(SecretKeyShare, Vec<String>)>,
) -> Result<(), TofndError> {
    // sign init
    let msg_type = stream
        .next()
        .await
        .ok_or("stream closed by client without sending a message")??
        .data
        .ok_or("missing `data` field in client messge")?;
    let sign_init = match msg_type {
        proto::message_in::Data::SignInit(s) => s,
        _ => {
            return Err(From::from("first client message must be sign init"));
        }
    };
    let (secret_key_share, all_party_uids) = kv.get(&sign_init.key_uid).await?;
    let sign_init = sign_sanitize_args(sign_init, &secret_key_share, &all_party_uids)?;

    // quit now if I'm not a participant
    if sign_init
        .participant_indices
        .iter()
        .find(|&&i| i == secret_key_share.my_index)
        .is_none()
    {
        println!(
            "party [{}] is not a sign participant",
            all_party_uids[secret_key_share.my_index]
        );
        return Ok(());
    }

    // sign execute
    let mut sign = Sign::new(
        &secret_key_share,
        &sign_init.participant_indices,
        &sign_init.message_to_sign,
    )?;
    execute_protocol(
        &mut sign,
        stream,
        msg_sender.clone(),
        &sign_init.participant_uids,
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
    key_uid: String,
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
        key_uid: sign_init.key_uid,
        participant_uids,
        participant_indices,
        message_to_sign: sign_init.message_to_sign,
    })
}

async fn execute_keygen(
    stream: &mut tonic::Streaming<proto::MessageIn>,
    mut msg_sender: mpsc::Sender<Result<proto::MessageOut, tonic::Status>>,
    mut kv: KV<(SecretKeyShare, Vec<String>)>,
) -> Result<(), TofndError> {
    // keygen init
    let msg_type = stream
        .next()
        .await
        .ok_or("stream closed by client without sending a message")??
        .data
        .ok_or("missing `data` field in client message")?;
    let keygen_init = match msg_type {
        proto::message_in::Data::KeygenInit(k) => k,
        _ => {
            return Err(From::from("first client message must be keygen init"));
        }
    };
    let keygen_init = keygen_sanitize_args(keygen_init)?;
    // println!("server received keygen init {:?}", keygen_init);

    // reserve new_key_uid in the KV store
    let key_uid_reservation = kv.reserve_key(keygen_init.new_key_uid).await?;

    // keygen execute
    let mut keygen = Keygen::new(
        keygen_init.party_uids.len(),
        keygen_init.threshold,
        keygen_init.my_index,
    )?;
    // unreserve new_key_uid on failure
    // too bad try blocks are not yet stable in Rust: https://doc.rust-lang.org/nightly/unstable-book/language-features/try-blocks.html
    // instead I need to wrap two lines inside `execute_keygen_unreserve_on_err`
    let secret_key_share = execute_keygen_unreserve_on_err(
        &mut keygen,
        stream,
        msg_sender.clone(),
        &keygen_init.party_uids,
    )
    .await;
    if let Err(e) = secret_key_share {
        kv.unreserve_key(key_uid_reservation).await;
        return Err(e);
    }
    let secret_key_share = secret_key_share.unwrap();

    // store output in KV store
    let kv_data: (SecretKeyShare, Vec<String>) = (secret_key_share.clone(), keygen_init.party_uids);
    kv.put(key_uid_reservation, kv_data).await?;

    // serialize generated public key and send to client
    let pubkey = secret_key_share.ecdsa_public_key.get_element();
    let pubkey = pubkey.serialize(); // bitcoin-style serialization
    msg_sender
        .send(Ok(proto::MessageOut::new_keygen_result(&pubkey)))
        .await?;
    Ok(())
}

async fn execute_keygen_unreserve_on_err<'a>(
    keygen: &'a mut Keygen,
    stream: &mut tonic::Streaming<proto::MessageIn>,
    msg_sender: mpsc::Sender<Result<proto::MessageOut, tonic::Status>>,
    party_uids: &[String],
) -> Result<&'a SecretKeyShare, TofndError> {
    // too bad try blocks are not yet in stable Rust: https://doc.rust-lang.org/nightly/unstable-book/language-features/try-blocks.html
    // alternatives:
    // * closure: https://stackoverflow.com/questions/55755552/what-is-the-rust-equivalent-to-a-try-catch-statement/55756926#55756926
    //   * however async closures are not yet in stable Rust: https://github.com/rust-lang/rust/issues/62290
    // * `and_then` but that's unreadable: https://doc.rust-lang.org/std/result/enum.Result.html#method.and_then
    // * another async fn to wrap these to lines: execute_protocol, keygen.get_result
    execute_protocol(keygen, stream, msg_sender, party_uids).await?;
    Ok(keygen.get_result().ok_or("keygen output is `None`")?)
}

struct KeygenInitSanitized {
    new_key_uid: String,
    party_uids: Vec<String>,
    my_index: usize,
    threshold: usize,
}

fn keygen_sanitize_args(mut args: proto::KeygenInit) -> Result<KeygenInitSanitized, TofndError> {
    use std::convert::TryFrom;
    let my_index = usize::try_from(args.my_party_index)?;
    let threshold = usize::try_from(args.threshold)?;
    keygen::validate_params(args.party_uids.len(), threshold, my_index)?;

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
    Ok(KeygenInitSanitized {
        new_key_uid: args.new_key_uid,
        party_uids: args.party_uids,
        my_index,
        threshold,
    })
}

// convenience constructors
impl proto::MessageOut {
    fn new_bcast(bcast: &[u8]) -> Self {
        Self::new_traffic("", bcast, true)
    }
    fn new_p2p(receiver_id: &str, p2p: &[u8]) -> Self {
        Self::new_traffic(receiver_id, p2p, false)
    }
    fn new_traffic(receiver_id: &str, msg: &[u8], is_broadcast: bool) -> Self {
        proto::MessageOut {
            data: Some(proto::message_out::Data::Traffic(proto::TrafficOut {
                to_party_uid: receiver_id.to_string(),
                payload: msg.to_vec(),
                is_broadcast,
            })),
        }
    }
    fn new_keygen_result(result: &[u8]) -> Self {
        proto::MessageOut {
            data: Some(proto::message_out::Data::KeygenResult(result.to_vec())),
        }
    }
    fn new_sign_result(result: &[u8]) -> Self {
        proto::MessageOut {
            data: Some(proto::message_out::Data::SignResult(result.to_vec())),
        }
    }
}
