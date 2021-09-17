use serde::{Deserialize, Serialize};
use sled::IVec;

#[derive(Serialize, Deserialize, Debug)]
pub(super) struct Record {
    pub(super) encrypted_value: Vec<u8>,
    pub(super) nonce: [u8; 12],
}
impl Record {
    pub(super) fn new(encrypted_value: Vec<u8>, nonce: [u8; 12]) -> Self {
        Record {
            encrypted_value,
            nonce,
        }
    }
    pub(super) fn as_bytes(&self) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&self)
    }
    pub(super) fn from_bytes(bytes: &IVec) -> bincode::Result<Record> {
        bincode::deserialize(bytes)
    }
}
