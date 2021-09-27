//! The value of [super::Db].

use chacha20poly1305::XNonce;
use serde::{Deserialize, Serialize};
use sled::IVec;

/// The value of [super::Db].
#[derive(Serialize, Deserialize, Debug)]
pub(super) struct EncryptedRecord {
    encrypted_value: Vec<u8>,
    nonce: [u8; 24],
}
impl EncryptedRecord {
    pub(super) fn new(encrypted_value: Vec<u8>, nonce: XNonce) -> Self {
        EncryptedRecord {
            encrypted_value,
            nonce: nonce.into(),
        }
    }
    /// Convert a [EncryptedRecord] to bytes using serde.
    pub(super) fn as_bytes(&self) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&self)
    }
    /// Convert bytes to a [EncryptedRecord] using serde.
    pub(super) fn from_bytes(bytes: &IVec) -> bincode::Result<EncryptedRecord> {
        bincode::deserialize(bytes)
    }
}

impl From<EncryptedRecord> for (Vec<u8>, XNonce) {
    fn from(record: EncryptedRecord) -> Self {
        (record.encrypted_value, record.nonce.into())
    }
}
