use std::path::PathBuf;

use tofn::protocol::gg20::{GroupPublicInfo, MessageDigest, SecretKeyShare, ShareSecretInfo};

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

pub mod mnemonic;
use mnemonic::{file_io::FileIo, Cmd};

const DEFAULT_SHARE_KV_NAME: &str = "shares";
const DEFAULT_MNEMONIC_KV_NAME: &str = "mnemonic";

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
    pub common: GroupPublicInfo,
    pub shares: Vec<ShareSecretInfo>,
    pub tofnd: TofndInfo,
}

impl PartyInfo {
    // Get GroupPublicInfo and ShareSecretInfo from tofn to create PartyInfo
    // Also needed in recovery
    pub(crate) fn get_party_info(
        secret_key_shares: Vec<SecretKeyShare>,
        uids: Vec<String>,
        share_counts: Vec<usize>,
        tofnd_index: usize,
    ) -> Self {
        // grap the first share to acquire common data
        let s = secret_key_shares[0].clone();
        let common = s.group;
        // aggregate share data into a vector
        let mut shares = Vec::new();
        for share in secret_key_shares {
            shares.push(share.share);
        }
        // add tofnd data
        let tofnd = TofndInfo {
            party_uids: uids,
            share_counts,
            index: tofnd_index,
        };
        PartyInfo {
            common,
            shares,
            tofnd,
        }
    }
}

// TODO don't store party_uids in this daemon!
type KeySharesKv = Kv<PartyInfo>;
type MnemonicKv = Kv<mnemonic::Entropy>;
#[derive(Clone)]
struct Gg20Service {
    shares_kv: KeySharesKv,
    mnemonic_kv: MnemonicKv,
    io: FileIo,
    #[cfg(feature = "malicious")]
    keygen_behaviour: KeygenBehaviour,
    #[cfg(feature = "malicious")]
    sign_behaviour: SignBehaviour,
}

#[cfg(not(feature = "malicious"))]
pub async fn new_service(mnemonic_cmd: Cmd) -> impl proto::gg20_server::Gg20 {
    let mut gg20 = Gg20Service {
        shares_kv: KeySharesKv::new(DEFAULT_SHARE_KV_NAME),
        mnemonic_kv: MnemonicKv::new(DEFAULT_MNEMONIC_KV_NAME),
        io: FileIo::new(PathBuf::new()),
    };

    gg20.handle_mnemonic(mnemonic_cmd)
        .await
        .expect("Unable to complete mnemonic command.");
    gg20
}

#[cfg(feature = "malicious")]
pub async fn new_service(
    mnemonic_cmd: Cmd,
    keygen_behaviour: KeygenBehaviour,
    sign_behaviour: SignBehaviour,
) -> impl proto::gg20_server::Gg20 {
    let mut gg20 = Gg20Service {
        shares_kv: KeySharesKv::new(DEFAULT_SHARE_KV_NAME),
        mnemonic_kv: MnemonicKv::new(DEFAULT_MNEMONIC_KV_NAME),
        io: FileIo::new(PathBuf::new()),
        keygen_behaviour,
        sign_behaviour,
    };

    gg20.handle_mnemonic(mnemonic_cmd)
        .await
        .expect("Unable to complete mnemonic command.");
    gg20
}

pub struct KeygenInitSanitized {
    new_key_uid: String,
    party_uids: Vec<String>,
    party_share_counts: Vec<usize>,
    my_index: usize,
    threshold: usize,
}

impl KeygenInitSanitized {
    fn my_shares_count(&self) -> usize {
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

    async fn keygen(
        &self,
        request: Request<tonic::Streaming<proto::MessageIn>>,
    ) -> Result<Response<Self::KeygenStream>, Status> {
        let stream_in = request.into_inner();
        let (msg_sender, rx) = mpsc::unbounded_channel();

        let span = span!(Level::INFO, "Keygen");
        let _enter = span.enter();
        let s = span.clone();
        let mut gg20 = self.clone();
        tokio::spawn(async move {
            // can't return an error from a spawned thread
            if let Err(e) = gg20.handle_keygen(stream_in, msg_sender, s).await {
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
        let mut gg20 = self.clone();
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
use tofn::protocol::gg20::keygen::malicious::Behaviour as KeygenBehaviour;
use tofn::protocol::gg20::keygen::{Keygen, SecretRecoveryKey};

#[cfg(feature = "malicious")]
use tofn::protocol::gg20::sign::malicious::BadSign;
#[cfg(feature = "malicious")]
use tofn::protocol::gg20::sign::malicious::Behaviour as SignBehaviour;
#[cfg(not(feature = "malicious"))]
use tofn::protocol::gg20::sign::Sign;
use tofn::protocol::gg20::{keygen::ParamsError as KeygenErr, sign::ParamsError as SignErr};
impl Gg20Service {
    // get regular keygen
    #[cfg(not(feature = "malicious"))]
    fn get_keygen(
        &self,
        party_share_counts: usize,
        threshold: usize,
        my_index: usize,
        seed: &SecretRecoveryKey,
        nonce: &[u8],
    ) -> Result<Keygen, KeygenErr> {
        Keygen::new(party_share_counts, threshold, my_index, &seed, &nonce)
    }

    // get malicious keygen
    #[cfg(feature = "malicious")]
    fn get_keygen(
        &self,
        party_share_counts: usize,
        threshold: usize,
        my_index: usize,
        seed: &SecretRecoveryKey,
        nonce: &[u8],
    ) -> Result<Keygen, KeygenErr> {
        let mut k = Keygen::new(party_share_counts, threshold, my_index, &seed, &nonce)?;
        k.set_behaviour(self.keygen_behaviour.clone());
        Ok(k)
    }

    // get regular sign
    #[cfg(not(feature = "malicious"))]
    fn get_sign(
        &self,
        my_secret_key_share: &SecretKeyShare,
        participant_indices: &[usize],
        msg_to_sign: &MessageDigest,
    ) -> Result<Sign, SignErr> {
        Sign::new(
            &my_secret_key_share.group,
            &my_secret_key_share.share,
            participant_indices,
            msg_to_sign,
        )
    }

    // get malicious sign
    #[cfg(feature = "malicious")]
    fn get_sign(
        &self,
        my_secret_key_share: &SecretKeyShare,
        participant_indices: &[usize],
        msg_to_sign: &MessageDigest,
    ) -> Result<BadSign, SignErr> {
        let behaviour = self.sign_behaviour.clone();
        BadSign::new(
            &my_secret_key_share.group,
            &my_secret_key_share.share,
            participant_indices,
            msg_to_sign,
            behaviour,
        )
    }
}

mod keygen;
// TODO remove pub after API changes are incorporated by axelar-core
// until then we need to_crimes for tests
pub mod proto_helpers;
mod protocol;
mod sign;

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
            proto::message_in::Data::Abort(_) => {
                warn!("received abort message");
                break;
            }
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
    use super::{FileIo, Gg20Service, KeySharesKv, MnemonicKv};
    use crate::proto;
    use std::path::PathBuf;

    #[cfg(feature = "malicious")]
    use tofn::protocol::gg20::keygen::malicious::Behaviour as KeygenBehaviour;
    #[cfg(feature = "malicious")]
    use tofn::protocol::gg20::sign::malicious::Behaviour as SignBehaviour;

    // append a subfolder name to db path.
    // this will allows the creaton of two distict kv stores under 'dp_path'
    fn create_db_names(db_path: &str) -> (String, String) {
        (
            db_path.to_owned() + "/shares",
            db_path.to_owned() + "/mnemonic",
        )
    }

    #[cfg(not(feature = "malicious"))]
    pub async fn with_db_name(
        db_path: &str,
        mnemonic_cmd: super::mnemonic::Cmd,
    ) -> impl proto::gg20_server::Gg20 {
        let (shares_db_name, mnemonic_db_name) = create_db_names(db_path);

        let mut path = PathBuf::new();
        path.push(db_path);

        let mut gg20 = Gg20Service {
            shares_kv: KeySharesKv::with_db_name(&shares_db_name),
            mnemonic_kv: MnemonicKv::with_db_name(&mnemonic_db_name),
            io: FileIo::new(path),
        };

        gg20.handle_mnemonic(mnemonic_cmd)
            .await
            .expect("Unable to complete mnemonic command.");
        gg20
    }

    #[cfg(feature = "malicious")]
    pub async fn with_db_name_malicious(
        db_path: &str,
        mnemonic_cmd: super::mnemonic::Cmd,
        keygen_behaviour: KeygenBehaviour,
        sign_behaviour: SignBehaviour,
    ) -> impl proto::gg20_server::Gg20 {
        let (shares_db_name, mnemonic_db_name) = create_db_names(db_path);
        let mut path = PathBuf::new();
        path.push(db_path);

        let mut gg20 = Gg20Service {
            shares_kv: KeySharesKv::with_db_name(&shares_db_name),
            mnemonic_kv: MnemonicKv::with_db_name(&mnemonic_db_name),
            io: FileIo::new(path),
            keygen_behaviour,
            sign_behaviour,
        };

        gg20.handle_mnemonic(mnemonic_cmd)
            .await
            .expect("Unable to complete mnemonic command.");
        gg20
    }

    pub fn get_db_path(name: &str) -> std::path::PathBuf {
        KeySharesKv::get_db_path(name)
    }
}
