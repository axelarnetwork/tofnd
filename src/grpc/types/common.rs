//! Helper structs and implementations for [crate::grpc].

use std::convert::TryFrom;

// zeroize Entropy and Password
use zeroize::Zeroize;

use crate::{
    grpc::types::{gg20, multisig},
    kv_manager::{error::KvError, kv::Kv},
};

pub type MessageDigest = tofn::gg20::sign::MessageDigest;

// default KV store names
pub const DEFAULT_KV_NAME: &str = "kv";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KvValue {
    Gg20PartyInfo(gg20::PartyInfo),
    MultisigPartyInfo(multisig::PartyInfo),
    Entropy(Entropy),
}

/// Create KvValue from gg20 PartyInfo
impl From<gg20::PartyInfo> for KvValue {
    fn from(v: gg20::PartyInfo) -> KvValue {
        KvValue::Gg20PartyInfo(v)
    }
}

/// Create KvValue from multisig PartyInfo
impl From<multisig::PartyInfo> for KvValue {
    fn from(v: multisig::PartyInfo) -> KvValue {
        KvValue::MultisigPartyInfo(v)
    }
}

/// Create KvValue from Entropy
impl From<Entropy> for KvValue {
    fn from(v: Entropy) -> KvValue {
        KvValue::Entropy(v)
    }
}

/// Create gg20 PartyInfo from KvValue
impl TryFrom<KvValue> for gg20::PartyInfo {
    type Error = KvError;
    fn try_from(v: KvValue) -> Result<Self, Self::Error> {
        match v {
            KvValue::Gg20PartyInfo(party_info) => Ok(party_info),
            KvValue::MultisigPartyInfo(_) => Err(Self::Error::ValueTypeErr(
                "Expecting gg20 PartyInfo, got multisig PartyInfo".to_string(),
            )),
            KvValue::Entropy(_) => Err(Self::Error::ValueTypeErr(
                "Expecting gg20 PartyInfo, got Entropy".to_string(),
            )),
        }
    }
}

/// Create multisig PartyInfo from KvValue
impl TryFrom<KvValue> for multisig::PartyInfo {
    type Error = KvError;
    fn try_from(v: KvValue) -> Result<Self, Self::Error> {
        match v {
            KvValue::Gg20PartyInfo(_) => Err(Self::Error::ValueTypeErr(
                "Expecting multisig PartyInfo, got gg20 PartyInfo".to_string(),
            )),
            KvValue::MultisigPartyInfo(party_info) => Ok(party_info),
            KvValue::Entropy(_) => Err(Self::Error::ValueTypeErr(
                "Expecting multisig PartyInfo, got Entropy".to_string(),
            )),
        }
    }
}

/// Create Entropy from KvValue
impl TryFrom<KvValue> for Entropy {
    type Error = KvError;
    fn try_from(v: KvValue) -> Result<Self, Self::Error> {
        match v {
            KvValue::Gg20PartyInfo(_) => Err(Self::Error::ValueTypeErr(
                "Expecting Entropy, got gg20 PartyInfo".to_string(),
            )),
            KvValue::MultisigPartyInfo(_) => Err(Self::Error::ValueTypeErr(
                "Expecting Entropy, got multisig PartyInfo".to_string(),
            )),
            KvValue::Entropy(entropy) => Ok(entropy),
        }
    }
}

/// Kv store for grpc service
pub type ServiceKv = Kv<KvValue>;

/// Mnemonic type needs to be known globaly to create/access the mnemonic kv store
#[derive(Zeroize, Debug, Clone, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct Entropy(pub Vec<u8>);

#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct Password(pub String);

use tokio::sync::mpsc;
/// define the input and output channels of generic execute_protocol worker
pub struct ProtocolCommunication<InMsg, OutMsg> {
    pub receiver: mpsc::UnboundedReceiver<InMsg>,
    pub sender: mpsc::UnboundedSender<OutMsg>,
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

/// Struct to hold `tonfd` info. This consists of information we need to
/// store in the KV store that is not relevant to `tofn`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TofndInfo {
    pub party_uids: Vec<String>,
    pub share_counts: Vec<usize>,
    pub index: usize,
}
