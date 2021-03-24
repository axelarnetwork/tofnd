use std::sync::mpsc::channel;

use tofn::protocol::gg20::keygen::SecretKeyShare;

use super::proto;
use crate::kv_manager::Kv;

// tonic cruft
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};
// use std::pin::Pin;
// use futures_core::Stream;
// use futures_util::StreamExt;
use futures_util::StreamExt;

// TODO don't store party_uids in this daemon!
type KeySharesKv = Kv<(SecretKeyShare, Vec<String>)>; // (secret_key_share, all_party_uids)

struct Gg20Service {
    kv: KeySharesKv,
}

// // TODO: these are duplicates of tofn's private structs; need to make them public
// use serde::{Deserialize, Serialize};
// pub type MsgBytes = Vec<u8>;
// #[derive(Serialize, Deserialize)]
// enum MsgType {
//     R1Bcast,
//     R2Bcast,
//     R2P2p,
//     R3Bcast,
// }
// #[derive(Serialize, Deserialize)]
// struct MsgMeta {
//     msg_type: MsgType,
//     from: usize,
//     payload: MsgBytes,
// }

pub fn new_service() -> impl proto::gg20_server::Gg20 {
    Gg20Service {
        kv: KeySharesKv::new(),
    }
}

#[tonic::async_trait]
impl proto::gg20_server::Gg20 for Gg20Service {
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
        let mut external_in_stream = request.into_inner();
        let (external_out_stream_writer, external_out_stream_reader) = mpsc::channel(4);

        let kv = self.kv.clone();

        tokio::spawn(async move {
            // get KeygenInit message from stream
            // the first message of the stream is expected to be a KeygenInit message
            // get the message, check if it is of the expected type, and sanitize its data
            let msg_type = external_in_stream
                .next()
                .await
                .ok_or(Status::aborted(
                    "keygen: stream closed by client without sending a message",
                ))
                .unwrap()
                .unwrap()
                .data
                .ok_or(Status::aborted(
                    "keygen: missing `data` field in client message",
                ))
                .unwrap();
            let keygen_init = match msg_type {
                proto::message_in::Data::KeygenInit(k) => k,
                // _ => return Err(Status::aborted("Expected keygen init message"))
                _ => {
                    println!("Expected keygen init message");
                    return;
                }
            };
            let keygen_init = match keygen::keygen_sanitize_args(keygen_init) {
                Ok(k) => k,
                // _ => return Err(Status::aborted("Keygen init failed"))
                _ => {
                    println!("Keygen init failed");
                    return;
                }
            };

            // TODO better logging
            let log_prefix = format!(
                "keygen [{}] party [{}]",
                keygen_init.new_key_uid, keygen_init.party_uids[keygen_init.my_index],
            );
            println!(
                "begin {} with (t,n)=({},{})",
                log_prefix,
                keygen_init.threshold,
                keygen_init.party_uids.len(),
            );

            // find my shares
            let my_share_count = keygen_init.my_shares();

            // create my_share_count channels, and spawn my_share_count threads
            // providing the respective channel's reader and the out stream
            let mut internal_writers = Vec::new();
            for _ in 0..my_share_count {
                let (internal_writer, internal_reader) = mpsc::channel(4);
                internal_writers.push(internal_writer);
                let external_out_stream_writer_copy = external_out_stream_writer.clone();
                let keygen_copy = keygen_init.clone();
                let kv_copy = kv.clone();
                let log_prefix_copy = log_prefix.clone();
                tokio::spawn(async move {
                    // can't return an error from a spawned thread
                    if let Err(e) = keygen::execute_keygen(
                        internal_reader,
                        external_out_stream_writer_copy,
                        keygen_copy,
                        kv_copy,
                        log_prefix_copy,
                    )
                    .await
                    {
                        println!("keygen failure: {:?}", e);
                        return;
                    }
                });
            }

            tokio::spawn(async move {
                let error = false;
                while !error {
                    let msg_data = external_in_stream.next().await;

                    if msg_data.is_none() {
                        println!("Error at receiving external in stream: None");
                        break;
                    }

                    let msg_data = msg_data.unwrap();
                    if msg_data.is_err() {
                        println!("Error at receiving external in stream: Error");
                        break;
                    }

                    let msg_data = msg_data.unwrap().data;
                    // I wish I could do `if !let` https://github.com/rust-lang/rfcs/pull/1303
                    if msg_data.is_none() {
                        println!("WARNING: ignore incoming msg: missing `data` field");
                        continue;
                    }
                    let traffic = match msg_data.unwrap() {
                        proto::message_in::Data::Traffic(t) => t,
                        _ => {
                            println!(
                                "WARNING: ignore incoming msg: expect `data` to be TrafficIn type"
                            );
                            continue;
                        }
                    };
                    // TODO: find out which one of my shares is addressed in this message and its tofn index
                    // let payload: MsgMeta = bincode::deserialize(&traffic.payload).unwrap();
                    let my_share_index: usize = 0;
                    let _ = internal_writers[my_share_index].send(Some(traffic)).await;
                }
            });
        });

        Ok(Response::new(external_out_stream_reader))
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
            if let Err(e) = sign::execute_sign(&mut stream, msg_sender, kv).await {
                println!("sign failure: {:?}", e);
                return;
            }
        });
        Ok(Response::new(rx))
    }
}

mod keygen;
mod protocol;
mod sign;

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

#[cfg(test)]
pub(super) mod tests {
    use super::{Gg20Service, KeySharesKv};
    use crate::proto;

    #[cfg(test)]
    pub fn with_db_name(db_name: &str) -> impl proto::gg20_server::Gg20 {
        Gg20Service {
            kv: KeySharesKv::with_db_name(db_name),
        }
    }

    #[cfg(test)]
    pub fn get_db_path(name: &str) -> std::path::PathBuf {
        KeySharesKv::get_db_path(name)
    }
}
