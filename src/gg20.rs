// use crate::proto::{self, MessageOut};
// use super::proto::gg20_server::{Gg20, Gg20Server};
// use super::proto::{self, MessageOut};
use super::proto;
// use proto::message_out::Data;

// tonic cruft
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};
// use std::pin::Pin;
// use futures_core::Stream;
use tofn::protocol::{
    gg20::keygen::{validate_params, ECPoint, Keygen},
    Protocol,
};

#[derive(Debug)]
pub struct GG20Service;

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
        let (mut tx, rx) = mpsc::channel(4);

        // can't return an error from a spawned thread
        tokio::spawn(async move {
            let (party_uids, mut keygen) = match keygen_init(stream.next().await) {
                Ok(k) => k,
                Err(e) => {
                    println!("failure to initialize keygen: {:?}", e);
                    return;
                }
            };

            // TODO this is generic protocol code---refactor it!  Need a `Protocol` interface minus `get_result` method
            while !keygen.done() {
                // TODO runs an extra iteration!
                // TODO bad error handling
                if let Err(e) = keygen.next_round() {
                    println!("next() failure: {:?}", e);
                    return;
                }

                // send outgoing messages
                let bcast = keygen.get_bcast_out();
                if let Some(bcast) = bcast {
                    tx.send(Ok(wrap_bcast(bcast))).await.unwrap(); // TODO panic
                }
                let p2ps = keygen.get_p2p_out();
                if let Some(p2ps) = p2ps {
                    for (i, p2p) in p2ps.iter().enumerate() {
                        if let Some(p2p) = p2p {
                            tx.send(Ok(wrap_p2p(&party_uids[i], p2p))).await.unwrap();
                            // TODO panic
                        }
                    }
                }

                // collect incoming messages
                while keygen.expecting_more_msgs_this_round() {
                    let msg_in = stream.next().await;
                    if msg_in.is_none() {
                        println!("abort: stream closed by client before protocol has completed");
                        return;
                    }
                    let msg_in = msg_in.unwrap();
                    if msg_in.is_err() {
                        println!("abort: stream failure to receive {:?}", msg_in.unwrap_err());
                        return;
                    }
                    let msg_in = msg_in.unwrap().data;
                    if msg_in.is_none() {
                        println!("missing data in client message");
                        continue;
                    }
                    let msg_in = match msg_in.unwrap() {
                        proto::message_in::Data::Traffic(t) => t,
                        _ => {
                            println!("all messages after the first must be traffic in");
                            continue;
                        }
                    };

                    keygen
                        .set_msg_in(&msg_in.payload)
                        .expect("failure to set_msg_in"); // TODO panic
                }
            }

            // send final result, serialized; DO NOT SEND SECRET DATA
            let pubkey = keygen.get_result().unwrap().ecdsa_public_key.get_element(); // TODO panic
            let pubkey = pubkey.serialize(); // bitcoin-style serialization
            tx.send(Ok(wrap_result(&pubkey))).await.unwrap(); // TODO panic
        });

        Ok(Response::new(rx))
    }

    async fn sign(
        &self,
        _request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::KeygenStream>, Status> {
        let (mut _tx, rx) = mpsc::channel(4);
        Ok(Response::new(rx))
    }
}

fn keygen_init(
    stream_msg: Option<Result<proto::MessageIn, Status>>,
) -> Result<(Vec<String>, Keygen), Box<dyn std::error::Error>> {
    let msg_type = stream_msg
        .ok_or("stream closed by client without sending a message")??
        .data
        .ok_or("missing `data` field in client message")?;
    let keygen_init = match msg_type {
        proto::message_in::Data::KeygenInit(k) => k,
        _ => {
            return Err(From::from("first client message must be keygen init"));
        }
    };
    // println!("server received keygen init {:?}", keygen_init);
    let (party_uids, my_index, threshold) = keygen_check_args(keygen_init)?;
    let share_count = party_uids.len();
    Ok((party_uids, Keygen::new(share_count, threshold, my_index)?))
}

fn keygen_check_args(
    mut args: proto::KeygenInit,
) -> Result<(Vec<String>, usize, usize), Box<dyn std::error::Error>> {
    use std::convert::TryFrom;
    let my_index = usize::try_from(args.my_party_index)?;
    let threshold = usize::try_from(args.threshold)?;
    validate_params(args.party_uids.len(), threshold, my_index)?;

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
    Ok((args.party_uids, my_index, threshold))
}

// TODO these wrappers are ugly
fn wrap_bcast(bcast: &[u8]) -> proto::MessageOut {
    wrap_msg("", bcast, true)
}

fn wrap_p2p(receiver_id: &str, p2p: &[u8]) -> proto::MessageOut {
    wrap_msg(receiver_id, p2p, false)
}

fn wrap_msg(receiver_id: &str, msg: &[u8], is_broadcast: bool) -> proto::MessageOut {
    proto::MessageOut {
        data: Some(proto::message_out::Data::Traffic(proto::TrafficOut {
            to_party_uid: receiver_id.to_string(),
            payload: msg.to_vec(),
            is_broadcast,
        })),
    }
}

fn wrap_result(result: &[u8]) -> proto::MessageOut {
    proto::MessageOut {
        data: Some(proto::message_out::Data::KeygenResult(result.to_vec())),
    }
}
