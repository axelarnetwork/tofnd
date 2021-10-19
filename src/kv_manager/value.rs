use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, path::PathBuf};

use crate::{
    encrypted_sled::Password,
    gg20::types::{Entropy, PartyInfo},
    mnemonic::FileIo,
};

use super::{
    error::{KvError, KvResult},
    kv::Kv,
};

/// Kv manager for grpc services
// pub type KvManager = Kv<KvValue>;
#[derive(Clone)]
pub struct KvManager {
    kv: Kv<KvValue>,
    io: FileIo,
}

impl KvManager {
    pub fn new(root: &str, password: Password) -> KvResult<Self> {
        Ok(KvManager {
            kv: Kv::<KvValue>::new(root, password)?,
            io: FileIo::new(PathBuf::from(root)),
        })
    }
    pub fn kv(&self) -> &Kv<KvValue> {
        &self.kv
    }
    pub fn io(&self) -> &FileIo {
        &self.io
    }
}

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
