use std::{error::Error, fmt::Debug};

// use crate::proto::{self, MessageOut};
// use super::proto::gg20_server::{Gg20, Gg20Server};
// use super::proto::{self, MessageOut};
use super::proto;
// use proto::message_out::Data;

// tonic cruft
use futures_util::StreamExt;
use mpsc::Sender;
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

        tokio::spawn(async move {
            // can't return an error from a spawned thread
            if let Err(e) = execute_keygen(&mut stream, &mut tx).await {
                println!("keygen failure: {:?}", e);
                return;
            }
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

async fn execute_protocol(
    protocol: &mut impl Protocol,
    stream: &mut tonic::Streaming<proto::MessageIn>,
    tx: &mut Sender<Result<proto::MessageOut, tonic::Status>>,
    party_uids: &[String],
) -> Result<(), Box<dyn Error>> {
    // TODO runs an extra iteration!
    while !protocol.done() {
        protocol.next_round()?;

        // send outgoing messages
        let bcast = protocol.get_bcast_out();
        if let Some(bcast) = bcast {
            tx.send(Ok(proto::MessageOut::new_bcast(bcast))).await?;
        }
        let p2ps = protocol.get_p2p_out();
        if let Some(p2ps) = p2ps {
            for (i, p2p) in p2ps.iter().enumerate() {
                if let Some(p2p) = p2p {
                    tx.send(Ok(proto::MessageOut::new_p2p(&party_uids[i], p2p)))
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

async fn execute_keygen(
    stream: &mut tonic::Streaming<proto::MessageIn>,
    tx: &mut Sender<Result<proto::MessageOut, tonic::Status>>,
) -> Result<(), Box<dyn Error>> {
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
    // println!("server received keygen init {:?}", keygen_init);
    let (party_uids, my_index, threshold) = keygen_check_args(keygen_init)?;
    let mut keygen = Keygen::new(party_uids.len(), threshold, my_index)?;

    // keygen execute
    execute_protocol(&mut keygen, stream, tx, &party_uids).await?;

    // keygen output
    let pubkey = keygen
        .get_result()
        .ok_or("keygen output is `None`")?
        .ecdsa_public_key
        .get_element();
    let pubkey = pubkey.serialize(); // bitcoin-style serialization
    tx.send(Ok(proto::MessageOut::new_result(&pubkey))).await?;
    Ok(())
}

fn keygen_check_args(
    mut args: proto::KeygenInit,
) -> Result<(Vec<String>, usize, usize), Box<dyn Error>> {
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
    fn new_result(result: &[u8]) -> Self {
        proto::MessageOut {
            data: Some(proto::message_out::Data::KeygenResult(result.to_vec())),
        }
    }
}
