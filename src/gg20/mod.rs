use tofn::protocol::gg20::{
    keygen::{CommonInfo, ShareInfo},
    sign::SignOutput,
};

#[cfg(not(feature = "malicious"))]
use tofn::protocol::gg20::sign::Sign;

#[cfg(feature = "malicious")]
use tofn::protocol::gg20::sign::malicious::MaliciousType;

use super::proto;
use crate::kv_manager::Kv;

// tonic cruft
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

use serde::{Deserialize, Serialize};

// for routing messages
use crate::TofndError;
use futures_util::StreamExt;

use tracing::{error, info, span, warn, Level, Span};

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
#[derive(Clone)]
struct Gg20Service {
    kv: KeySharesKv,
    #[cfg(feature = "malicious")]
    malicious_type: MaliciousType,
}

#[cfg(not(feature = "malicious"))]
pub fn new_service() -> impl proto::gg20_server::Gg20 {
    Gg20Service {
        kv: KeySharesKv::new(),
    }
}

#[cfg(feature = "malicious")]
pub fn new_service(malicious_type: MaliciousType) -> impl proto::gg20_server::Gg20 {
    Gg20Service {
        kv: KeySharesKv::new(),
        malicious_type,
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
    receiver: mpsc::UnboundedReceiver<InMsg>,
    sender: mpsc::UnboundedSender<OutMsg>,
}

#[tonic::async_trait]
impl proto::gg20_server::Gg20 for Gg20Service {
    // type KeygenStream = Pin<Box<dyn Stream<Item = Result<proto::MessageOut, Status>> + Send + Sync + 'static>>;
    type KeygenStream = mpsc::UnboundedReceiver<Result<proto::MessageOut, Status>>;
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
        let (msg_sender, rx) = mpsc::unbounded_channel();
        let kv = self.kv.clone();

        let span = span!(Level::INFO, "Keygen");
        let _enter = span.enter();
        let s = span.clone();
        tokio::spawn(async move {
            // can't return an error from a spawned thread
            if let Err(e) = keygen::handle_keygen(kv, stream_in, msg_sender, s).await {
                error!("keygen failure: {:?}", e);
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
        let (msg_sender, rx) = mpsc::unbounded_channel();

        // span logs for sign
        let span = span!(Level::INFO, "Sign");
        let _enter = span.enter();
        let s = span.clone();
        let gg20 = self.clone();
        tokio::spawn(async move {
            // can't return an error from a spawned thread
            if let Err(e) = gg20.handle_sign(stream, msg_sender, s).await {
                error!("sign failure: {:?}", e);
                return;
            }
        });
        Ok(Response::new(rx))
    }
}

#[cfg(feature = "malicious")]
use tofn::protocol::gg20::sign::malicious::BadSign;
use tofn::protocol::gg20::{keygen::SecretKeyShare, sign::ParamsError};
impl Gg20Service {
    // get regular sign
    #[cfg(not(feature = "malicious"))]
    fn get_sign(
        &self,
        my_secret_key_share: &SecretKeyShare,
        participant_indices: &[usize],
        msg_to_sign: &[u8],
    ) -> Result<Sign, ParamsError> {
        Sign::new(my_secret_key_share, participant_indices, msg_to_sign)
    }

    #[cfg(feature = "malicious")]
    fn get_sign(
        &self,
        my_secret_key_share: &SecretKeyShare,
        participant_indices: &[usize],
        msg_to_sign: &[u8],
    ) -> Result<BadSign, ParamsError> {
        let behaviour = self.malicious_type.clone();
        BadSign::new(
            my_secret_key_share,
            participant_indices,
            msg_to_sign,
            behaviour,
        )
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
    fn new_sign_result(result: SignOutput) -> Self {
        let response: Vec<u8>;
        if let Err(criminals) = result {
            warn!("Criminals detected! {:?}", criminals);
            // TODO temporarily use a dummy Vec<u8> if the result is a Criminal vector
            // when Criminal struct is incorporated to protobuf, this will have to change
            response = vec![42; criminals.len()];
        } else {
            response = result.unwrap();
        }
        // TODO TEMPORARY assume success
        proto::MessageOut {
            data: Some(proto::message_out::Data::SignResult(response)),
        }
    }
}

pub(super) async fn route_messages(
    in_stream: &mut tonic::Streaming<proto::MessageIn>,
    mut out_channels: Vec<mpsc::UnboundedSender<Option<proto::TrafficIn>>>,
    span: Span,
) -> Result<(), TofndError> {
    loop {
        let msg_data = in_stream.next().await;

        let route_span = span!(parent: &span, Level::INFO, "");
        let start = route_span.enter();
        if msg_data.is_none() {
            info!("Stream closed");
            break;
        }
        let msg_data = msg_data.unwrap();

        // TODO: handle error if channel is closed prematurely.
        // The router needs to determine whether the protocol is completed.
        // In this case it should stop gracefully. If channel closes before the
        // protocol was completed, then we should throw an error.
        // Note: When axelar-core closes the channel at the end of the protocol, msg_data returns an error
        if msg_data.is_err() {
            info!("Stream closed");
            break;
        }

        let msg_data = msg_data.unwrap().data;

        // I wish I could do `if !let` https://github.com/rust-lang/rfcs/pull/1303
        if msg_data.is_none() {
            warn!("ignore incoming msg: missing `data` field");
            continue;
        }
        let traffic = match msg_data.unwrap() {
            proto::message_in::Data::Traffic(t) => t,
            _ => {
                warn!("ignore incoming msg: expect `data` to be TrafficIn type");
                continue;
            }
        };

        // need to drop span before entering async code or we have log conflicts
        // with protocol execution https://github.com/tokio-rs/tracing#in-asynchronous-code
        drop(start);

        // send the message to all of my shares. This applies to p2p and bcast messages.
        // We also broadcast p2p messages to facilitate fault attribution
        for out_channel in &mut out_channels {
            let _ = out_channel.send(Some(traffic.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::{Gg20Service, KeySharesKv};
    use crate::proto;
    use tofn::protocol::gg20::sign::malicious::MaliciousType::{self, *};

    #[cfg(test)]
    #[cfg(not(feature = "malicious"))]
    pub fn with_db_name(db_name: &str) -> impl proto::gg20_server::Gg20 {
        Gg20Service {
            kv: KeySharesKv::with_db_name(db_name),
        }
    }

    #[cfg(test)]
    #[cfg(feature = "malicious")]
    pub fn with_db_name_malicious(
        db_name: &str,
        malicious_type: MaliciousType,
    ) -> impl proto::gg20_server::Gg20 {
        Gg20Service {
            kv: KeySharesKv::with_db_name(db_name),
            malicious_type,
        }
    }

    #[cfg(test)]
    pub fn get_db_path(name: &str) -> std::path::PathBuf {
        KeySharesKv::get_db_path(name)
    }
}
