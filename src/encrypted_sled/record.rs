//! The value of [super::Db].

use chacha20poly1305::XNonce;
use serde::{Deserialize, Serialize};
use sled::IVec;

use tofn::sdk::api::{deserialize, serialize};

use super::result::{
    EncryptedDbError::{Deserialization, Serialization},
    EncryptedDbResult,
};

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
    pub(super) fn to_bytes(&self) -> EncryptedDbResult<Vec<u8>> {
        serialize(&self).map_err(|_| Serialization)
    }

    /// Convert bytes to a [EncryptedRecord] using serde.
    pub(super) fn from_bytes(bytes: &IVec) -> EncryptedDbResult<EncryptedRecord> {
        deserialize(bytes).ok_or(Deserialization)
    }
}

impl From<EncryptedRecord> for (Vec<u8>, XNonce) {
    fn from(record: EncryptedRecord) -> Self {
        (record.encrypted_value, record.nonce.into())
    }
}
