use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, path::PathBuf};

use crate::{
    encrypted_sled::Password,
    gg20::types::{Entropy, PartyInfo},
    mnemonic::FileIo,
};
type SigningKey = Vec<u8>;

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

/// Enumerate the possible value types of the kv store
// TODO: this is starting to get out of hand. Use better ways to address different types in the kv store
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KvValue {
    PartyInfo(PartyInfo),   // gg20
    Entropy(Entropy),       // mnemonic
    SigningKey(SigningKey), // multisig
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

/// Create KvValue from SigningKey
impl From<SigningKey> for KvValue {
    fn from(v: SigningKey) -> KvValue {
        KvValue::SigningKey(v)
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
            KvValue::SigningKey(_) => Err(Self::Error::ValueTypeErr(
                "Expecting PartyInfo, got SigningKey".to_string(),
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
            KvValue::SigningKey(_) => Err(Self::Error::ValueTypeErr(
                "Expecting Entropy, got SigningKey".to_string(),
            )),
        }
    }
}

/// Create SigningKey from KvValue
impl TryFrom<KvValue> for SigningKey {
    type Error = KvError;
    fn try_from(v: KvValue) -> Result<Self, Self::Error> {
        match v {
            KvValue::PartyInfo(_) => Err(Self::Error::ValueTypeErr(
                "Expecting SigningKey, got PartyInfo".to_string(),
            )),
            KvValue::Entropy(_) => Err(Self::Error::ValueTypeErr(
                "Expecting SigningKey, got Entroy".to_string(),
            )),
            KvValue::SigningKey(sk) => Ok(sk),
        }
    }
}
