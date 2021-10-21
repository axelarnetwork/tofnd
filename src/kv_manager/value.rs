use std::{convert::TryFrom, path::PathBuf};
use tofn::sdk::api::{deserialize, serialize};

use crate::{
    encrypted_sled::Password,
    gg20::types::{Entropy, PartyInfo},
    mnemonic::FileIo,
};

use super::{
    error::{InnerKvError, KvResult},
    kv::Kv,
};

/// Kv manager for grpc services
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

/// Value type stored in the kv-store
type KvValue = Vec<u8>;

/// Create PartyInfo from KvValue
impl TryFrom<KvValue> for PartyInfo {
    type Error = InnerKvError;
    fn try_from(v: KvValue) -> Result<Self, Self::Error> {
        deserialize(&v).ok_or_else(|| InnerKvError::DeserializationErr)
    }
}

/// Create KvValue from PartyInfo
impl TryFrom<PartyInfo> for KvValue {
    type Error = InnerKvError;
    fn try_from(v: PartyInfo) -> Result<Self, Self::Error> {
        serialize(&v).map_err(|_| InnerKvError::SerializationErr)
    }
}

/// Create Entropy from KvValue
impl TryFrom<KvValue> for Entropy {
    type Error = InnerKvError;
    fn try_from(v: KvValue) -> Result<Self, Self::Error> {
        deserialize(&v).ok_or_else(|| InnerKvError::DeserializationErr)
    }
}

/// Create KvValue from Entropy
impl TryFrom<Entropy> for KvValue {
    type Error = InnerKvError;
    fn try_from(v: Entropy) -> Result<Self, Self::Error> {
        serialize(&v).map_err(|_| InnerKvError::SerializationErr)
    }
}
