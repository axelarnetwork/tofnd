use super::{BytesArray, XNonceArray};
use serde::{Deserialize, Serialize};
use sled::IVec;

#[derive(Serialize, Deserialize, Debug)]
pub(super) struct Record {
    pub(super) encrypted_value: Vec<u8>,
    pub(super) nonce: XNonceArray,
}
impl Record {
    pub(super) fn new(encrypted_value: Vec<u8>, nonce: XNonceArray) -> Self {
        Record {
            encrypted_value,
            nonce,
        }
    }
    pub(super) fn as_bytes(&self) -> bincode::Result<BytesArray> {
        bincode::serialize(&self)
    }
    pub(super) fn from_bytes(bytes: &IVec) -> bincode::Result<Record> {
        bincode::deserialize(bytes)
    }
}
