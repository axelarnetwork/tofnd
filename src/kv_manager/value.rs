use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use crate::gg20::types::{Entropy, PartyInfo};

use super::{error::KvError, kv::Kv};

/// Kv manager for grpc services
pub type KvManager = Kv<KvValue>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KvValue {
    PartyInfo(PartyInfo),
    Entropy(Entropy),
}

/// Create KvValue from PartyInfo
impl From<PartyInfo> for KvValue {
    fn from(v: PartyInfo) -> KvValue {
        KvValue::PartyInfo(v)
    }
}

/// Create KvValue from Entropy
impl From<Entropy> for KvValue {
    fn from(v: Entropy) -> KvValue {
        KvValue::Entropy(v)
    }
}

/// Create PartyInfo from KvValue
impl TryFrom<KvValue> for PartyInfo {
    type Error = KvError;
    fn try_from(v: KvValue) -> Result<Self, Self::Error> {
        match v {
            KvValue::PartyInfo(party_info) => Ok(party_info),
            KvValue::Entropy(_) => Err(Self::Error::ValueTypeErr(
                "Expecting PartyInfo, got Entropy".to_string(),
            )),
        }
    }
}

/// Create Entropy from KvValue
impl TryFrom<KvValue> for Entropy {
    type Error = KvError;
    fn try_from(v: KvValue) -> Result<Self, Self::Error> {
        match v {
            KvValue::PartyInfo(_) => Err(Self::Error::ValueTypeErr(
                "Expecting Entropy, got PartyInfo".to_string(),
            )),
            KvValue::Entropy(entropy) => Ok(entropy),
        }
    }
}
