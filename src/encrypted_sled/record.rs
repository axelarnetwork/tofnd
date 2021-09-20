//! The value of [super::Db].

use super::types::{BytesArray, XChaCha20Nonce};
use chacha20poly1305::XNonce;
use serde::{Deserialize, Serialize};
use sled::IVec;

/// The value of [super::Db].
#[derive(Serialize, Deserialize, Debug)]
pub(super) struct Record {
    pub(super) encrypted_value: Vec<u8>,
    pub(super) nonce: XChaCha20Nonce,
}
impl Record {
    pub(super) fn new(encrypted_value: Vec<u8>, nonce: XNonce) -> Self {
        Record {
            encrypted_value,
            nonce: nonce.into(),
        }
    }
    /// Convert a [Record] to bytes using serde.
    pub(super) fn as_bytes(&self) -> bincode::Result<BytesArray> {
        bincode::serialize(&self)
    }
    /// Convert bytes to a [Record] using serde.
    pub(super) fn from_bytes(bytes: &IVec) -> bincode::Result<Record> {
        bincode::deserialize(bytes)
    }
}
