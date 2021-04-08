use tofn::protocol::gg20::keygen::{CommonInfo, ShareInfo};

use super::proto;
use crate::kv_manager::Kv;

// tonic cruft
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

use serde::{Deserialize, Serialize};

// for routing messages
use crate::TofndError;
use futures_util::StreamExt;
use protocol::TofndP2pMsg;

// Struct to hold `tonfd` info. This consists of information we need to
// store in the KV store that is not relevant to `tofn`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TofndInfo {
    pub party_uids: Vec<String>,
    pub share_counts: Vec<usize>,
    pub index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyInfo {
    pub common: CommonInfo,
    pub shares: Vec<ShareInfo>,
    pub tofnd: TofndInfo,
}
// use std::pin::Pin;
// use futures_core::Stream;
// use futures_util::StreamExt;

// TODO don't store party_uids in this daemon!
type KeySharesKv = Kv<PartyInfo>;

struct Gg20Service {
    kv: KeySharesKv,
}

pub fn new_service() -> impl proto::gg20_server::Gg20 {
    Gg20Service {
        kv: KeySharesKv::new(),
    }
}

pub struct KeygenInitSanitized {
    new_key_uid: String,
    party_uids: Vec<String>,
    party_share_counts: Vec<usize>,
    my_index: usize,
    threshold: usize,
}

impl KeygenInitSanitized {
    pub fn my_shares_count(&self) -> usize {
        self.party_share_counts[self.my_index] as usize
    }
}

// Here, we define the input and output channels of generic execute_protocol worker.
// This helps for grouping similar variables and keeping the number of variables
// passed to functions under rust's analyser threshold (7).
struct ProtocolCommunication<InMsg, OutMsg> {
    receiver: mpsc::Receiver<InMsg>,
    sender: mpsc::Sender<OutMsg>,
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
        let stream_in = request.into_inner();
        let (msg_sender, rx) = mpsc::channel(4);
        let kv = self.kv.clone();

        tokio::spawn(async move {
            // can't return an error from a spawned thread
            if let Err(e) = keygen::handle_keygen(kv, stream_in, msg_sender).await {
                println!("keygen failure: {:?}", e);
                return;
            }
        });
        Ok(Response::new(rx))
    }

    async fn sign(
        &self,
        request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::SignStream>, Status> {
        let stream = request.into_inner();
        let (msg_sender, rx) = mpsc::channel(4);
        let kv = self.kv.clone();

        tokio::spawn(async move {
            // can't return an error from a spawned thread
            if let Err(e) = sign::handle_sign(kv, stream, msg_sender).await {
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
        let msg_data = msg_data.unwrap();

        // TODO: handle error if channel is closed prematurely.
        // The router needs to determine whether the protocol is completed.
        // In this case it should stop gracefully. If channel closes before the
        // protocol was completed, then we should throw an error.
        // Note: When axelar-core closes the channel at the end of the protocol, msg_data returns an error
        if msg_data.is_err() {
            println!("Stream closed");
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
                println!("WARNING: ignore incoming msg: expect `data` to be TrafficIn type");
                continue;
            }
        };
        // if message is broadcast, send it to all keygen threads.
        // if it's a p2p message, send it only to the corresponding keygen. In
        // case of p2p we have to also wrap the share we are refering to, so we
        // unwrap the message and read the 'subindex' field.
        if traffic.is_broadcast {
            for out_channel in &mut out_channels {
                let _ = out_channel.send(Some(traffic.clone())).await;
            }
        } else {
            let tofnd_msg: TofndP2pMsg = bincode::deserialize(&traffic.payload)?;
            let my_share_index: usize = tofnd_msg.subindex;
            let _ = out_channels[my_share_index].send(Some(traffic)).await;
        }
    }
    Ok(())
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
