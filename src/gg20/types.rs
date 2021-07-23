//! Helper structs and implementations for [crate::gg20].

// zeroize Entropy and Password
use zeroize::Zeroize;

use tracing::{info, span, Level, Span};

use crate::kv_manager::Kv;

pub(super) type MessageDigest = tofn::gg20::sign::MessageDigest;

// default KV store names
pub(super) const DEFAULT_SHARE_KV_NAME: &str = "shares";
pub(super) const DEFAULT_MNEMONIC_KV_NAME: &str = "mnemonic";

pub(super) type KeySharesKv = Kv<PartyInfo>;
pub(super) type MnemonicKv = Kv<Entropy>;

/// Mnemonic type needs to be known globaly to create/access the mnemonic kv store
#[derive(Zeroize, Debug, Clone, Serialize, Deserialize)]
pub struct Entropy(pub Vec<u8>);

#[derive(Zeroize, Clone)]
pub struct Password(pub String);

use tokio::sync::mpsc;
/// define the input and output channels of generic execute_protocol worker
pub(super) struct ProtocolCommunication<InMsg, OutMsg> {
    pub(super) receiver: mpsc::UnboundedReceiver<InMsg>,
    pub(super) sender: mpsc::UnboundedSender<OutMsg>,
}
impl<InMsg, OutMsg> ProtocolCommunication<InMsg, OutMsg> {
    pub fn new(
        receiver: mpsc::UnboundedReceiver<InMsg>,
        sender: mpsc::UnboundedSender<OutMsg>,
    ) -> Self {
        Self { receiver, sender }
    }
}

use serde::{Deserialize, Serialize};
use tofn::gg20::keygen::{GroupPublicInfo, SecretKeyShare, ShareSecretInfo};

/// Struct to hold `tonfd` info. This consists of information we need to
/// store in the KV store that is not relevant to `tofn`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct TofndInfo {
    pub(super) party_uids: Vec<String>,
    pub(super) share_counts: Vec<usize>,
    pub(super) index: usize,
}

/// `KeyShareKv` record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PartyInfo {
    pub(super) common: GroupPublicInfo,
    pub(super) shares: Vec<ShareSecretInfo>,
    pub(super) tofnd: TofndInfo,
}

impl PartyInfo {
    /// Get GroupPublicInfo and ShareSecretInfo from tofn to create PartyInfo
    /// Also needed in recovery
    pub(super) fn get_party_info(
        secret_key_shares: Vec<SecretKeyShare>,
        uids: Vec<String>,
        share_counts: Vec<usize>,
        tofnd_index: usize,
    ) -> Self {
        // grap the first share to acquire common data
        let s = secret_key_shares[0].clone();
        let common = s.group().clone();
        // aggregate share data into a vector
        let mut shares = Vec::new();
        for share in secret_key_shares {
            shares.push(share.share().clone());
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

    /// log PartyInfo state
    pub(super) fn log_info(&self, session_id: &str, sign_span: Span) {
        let init_span = span!(parent: &sign_span, Level::INFO, "init");
        let _enter = init_span.enter();

        info!(
            "[uid:{}, shares:{}] starting Sign with [key: {}, (t,n)=({},{}), participants:{:?}",
            self.tofnd.party_uids[self.tofnd.index],
            self.tofnd.share_counts[self.tofnd.index],
            session_id,
            self.common.threshold(),
            self.tofnd.share_counts.iter().sum::<usize>(),
            self.tofnd.party_uids,
        );
    }
}
