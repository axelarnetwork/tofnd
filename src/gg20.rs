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
use std::convert::TryFrom;
use thrush::protocol::gg20::keygen;

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

        // TODO we can only return errors outside of tokio::spawn---for consistency, perhaps we should never return an error?

        // the first message in the stream contains init data
        // block on this message; we can't proceed without it
        let msg_init = stream
            .next()
            .await
            .ok_or_else(|| {
                Status::invalid_argument("stream closed by client before sending any messages")
            })??
            .data
            .ok_or_else(|| Status::invalid_argument("missing data for stream message"))?;
        let init = match msg_init {
            proto::message_in::Data::KeygenInit(k) => k,
            _ => {
                return Err(Status::invalid_argument(
                    "first message must be keygen init data",
                ))
            }
        };
        println!("received keygen init {:?}", init);
        let (my_id_index, threshold) = keygen_check_args(&init)?;

        let (mut tx, rx) = mpsc::channel(4);

        // rust complains if I don't send messages inside a tokio::spawn
        // can't return an error from a spawned thread
        tokio::spawn(async move {
            // TODO this is generic protocol code---refactor it!  Need a `Protocol` interface minus `get_result` method
            // keep everything single-threaded for now
            // TODO switch to multi-threaded?
            let mut keygen = keygen::new_protocol(&init.party_uids, my_id_index, threshold);
            while !keygen.done() {
                // send outgoing messages
                // TODO we send lots of messages before receiving any---is that bad?
                let (bcast, p2ps) = keygen.get_messages_out();
                if let Some(bcast) = bcast {
                    tx.send(Ok(wrap_bcast(bcast))).await.unwrap(); // TODO panic
                }
                for (receiver_id, p2p) in p2ps {
                    tx.send(Ok(wrap_p2p(receiver_id, p2p))).await.unwrap(); // TODO panic
                }

                // collect incoming messages
                while !keygen.can_proceed() {
                    let msg_in = stream.next().await;
                    if msg_in.is_none() {
                        println!("stream closed by client before protocol has completed");
                        return;
                    }
                    let msg_in = msg_in.unwrap();
                    if msg_in.is_err() {
                        println!("stream failure to receive {:?}", msg_in.unwrap_err());
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

                    // TODO add_message_in does not yet return an error
                    // TODO add_message_in does not yet accept a `is_broadcast` arg
                    keygen.add_message_in(&msg_in.from_party_uid, &msg_in.payload);
                }
                keygen.next();
            }

            // send final result, serialized
            let result = keygen.get_result().unwrap(); // TODO panic
            let result = bincode::serialize(&result).unwrap(); // TODO panic
            tx.send(Ok(wrap_result(result))).await.unwrap(); // TODO panic
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

// TODO move me somewhere better
pub fn keygen_check_args(args: &proto::KeygenInit) -> Result<(usize, usize), Status> {
    let my_index = usize::try_from(args.my_party_index)
        .map_err(|_| Status::invalid_argument("my_party_index can't convert to usize"))?;
    let threshold = usize::try_from(args.threshold)
        .map_err(|_| Status::invalid_argument("threshold can't convert to usize"))?;
    if my_index >= args.party_uids.len() {
        return Err(Status::invalid_argument(format!(
            "my_party_index {} out of range for {} parties",
            my_index,
            args.party_uids.len()
        )));
    }
    if threshold >= args.party_uids.len() {
        return Err(Status::invalid_argument(format!(
            "threshold {} out of range for {} parties",
            threshold,
            args.party_uids.len()
        )));
    }
    Ok((my_index, threshold))
}

fn wrap_bcast(bcast: Vec<u8>) -> proto::MessageOut {
    wrap_msg(String::new(), bcast, true)
}

fn wrap_p2p(receiver_id: String, p2p: Vec<u8>) -> proto::MessageOut {
    wrap_msg(receiver_id, p2p, false)
}

fn wrap_msg(receiver_id: String, msg: Vec<u8>, is_broadcast: bool) -> proto::MessageOut {
    proto::MessageOut {
        data: Some(proto::message_out::Data::Traffic(proto::TrafficOut {
            to_party_uid: receiver_id,
            payload: msg,
            is_broadcast,
        })),
    }
}

fn wrap_result(result: Vec<u8>) -> proto::MessageOut {
    proto::MessageOut {
        data: Some(proto::message_out::Data::KeygenResult(result)),
    }
}
