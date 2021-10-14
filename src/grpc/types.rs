//! Helper structs and implementations for [crate::grpc].

use std::convert::TryFrom;

// zeroize Entropy and Password
use zeroize::Zeroize;

use crate::kv_manager::{error::KvError, kv::Kv};

pub(super) type MessageDigest = tofn::gg20::sign::MessageDigest;

// default KV store names
pub(super) const DEFAULT_KV_NAME: &str = "kv";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(super) enum KvValue {
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
pub(super) type ServiceKv = Kv<KvValue>;

/// Mnemonic type needs to be known globaly to create/access the mnemonic kv store
#[derive(Zeroize, Debug, Clone, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct Entropy(pub Vec<u8>);

#[derive(Zeroize, Clone)]
#[zeroize(drop)]
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

/// Struct to hold `tonfd` info. This consists of information we need to
/// store in the KV store that is not relevant to `tofn`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct TofndInfo {
    pub(super) party_uids: Vec<String>,
    pub(super) share_counts: Vec<usize>,
    pub(super) index: usize,
}

pub(super) mod gg20 {
    use super::TofndInfo;
    use tofn::gg20::keygen::{GroupPublicInfo, SecretKeyShare, ShareSecretInfo};

    use serde::{Deserialize, Serialize};
    use tracing::{info, span, Level, Span};

    /// `KeyShareKv` record
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub(in super::super) struct PartyInfo {
        pub(in super::super) common: GroupPublicInfo,
        pub(in super::super) shares: Vec<ShareSecretInfo>,
        pub(in super::super) tofnd: TofndInfo,
    }

    impl PartyInfo {
        /// Get GroupPublicInfo and ShareSecretInfo from tofn to create PartyInfo
        /// Also needed in recovery
        pub(in super::super) fn get_party_info(
            secret_key_shares: Vec<SecretKeyShare>,
            uids: Vec<String>,
            share_counts: Vec<usize>,
            tofnd_index: usize,
        ) -> Self {
            // grap the first share to acquire common data
            let common = secret_key_shares[0].group().clone();

            // aggregate share data into a vector
            let shares = secret_key_shares
                .into_iter()
                .map(|share| share.share().clone())
                .collect();

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
        pub(in super::super) fn log_info(&self, session_id: &str, sign_span: Span) {
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
}

pub(super) mod multisig {
    use super::TofndInfo;
    use tofn::multisig::keygen::{GroupPublicInfo, SecretKeyShare, ShareSecretInfo};

    use serde::{Deserialize, Serialize};
    use tracing::{info, span, Level, Span};

    /// `KeyShareKv` record
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub(in super::super) struct PartyInfo {
        pub(in super::super) common: GroupPublicInfo,
        pub(in super::super) shares: Vec<ShareSecretInfo>,
        pub(in super::super) tofnd: TofndInfo,
    }

    impl PartyInfo {
        /// Get GroupPublicInfo and ShareSecretInfo from tofn to create PartyInfo
        /// Also needed in recovery
        pub(in super::super) fn get_party_info(
            secret_key_shares: Vec<SecretKeyShare>,
            uids: Vec<String>,
            share_counts: Vec<usize>,
            tofnd_index: usize,
        ) -> Self {
            // grap the first share to acquire common data
            let common = secret_key_shares[0].group().clone();

            // aggregate share data into a vector
            let shares = secret_key_shares
                .into_iter()
                .map(|share| share.share().clone())
                .collect();

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
        pub(in super::super) fn log_info(&self, session_id: &str, sign_span: Span) {
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
}
