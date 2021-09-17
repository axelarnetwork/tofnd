use chacha20poly1305::aead::{AeadInPlace, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use sled::IVec;

use super::record::Record;
use super::{
    constants::*,
    result::{
        EncryptedDbError::{CorruptionError, Decryption, Encryption, WrongPassword},
        EncryptedDbResult,
    },
};
use super::{BytesArray, XNonceArray};

use crate::password::Entropy;

/// create a new [EncryptedDb]
/// wraps sled::open(db_name) and passes password from a key derivation function
pub fn open<P>(db_name: P, password: &Entropy) -> EncryptedDbResult<EncryptedDb>
where
    P: AsRef<std::path::Path>,
{
    let key = Key::from_slice(password.0[0..32].as_ref());
    let cipher = XChaCha20Poly1305::new(key);

    let kv = sled::open(db_name).map_err(CorruptionError)?;
    EncryptedDb { kv, cipher }.with_handle_password_verification()
}

pub struct EncryptedDb {
    kv: sled::Db,
    cipher: XChaCha20Poly1305,
}

impl EncryptedDb {
    fn get_random_nonce() -> XNonceArray {
        use rand::Rng;
        rand::thread_rng().gen::<XNonceArray>()
    }

    fn encrypt(&self, value: &[u8]) -> EncryptedDbResult<Record> {
        let random_nonce = Self::get_random_nonce();
        let nonce = XNonce::from_slice(&random_nonce);

        let mut buffer: BytesArray = Vec::with_capacity(128);
        buffer.extend_from_slice(value.as_ref());

        // Q: need to fill accossiated data?
        self.cipher
            .encrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|e| Encryption(e.to_string()))?;

        Ok(Record::new(buffer, random_nonce))
    }

    fn decrypt_record_value(&self, record: &Record) -> EncryptedDbResult<BytesArray> {
        let nonce = XNonce::from_slice(&record.nonce);

        let mut buffer: BytesArray = Vec::with_capacity(128);
        buffer.extend_from_slice(record.encrypted_value.as_ref());

        self.cipher
            .decrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|e| Decryption(e.to_string()))?;

        Ok(buffer)
    }

    fn decrypt(&self, record_bytes: Option<IVec>) -> EncryptedDbResult<Option<IVec>> {
        let res = match record_bytes {
            Some(record_bytes) => {
                let record = Record::from_bytes(&record_bytes)?;
                let decrypted_value_bytes = self.decrypt_record_value(&record)?.into();
                Some(decrypted_value_bytes)
            }
            None => None,
        };
        Ok(res)
    }

    pub fn insert<K, V>(&self, key: K, encrypted_value: V) -> EncryptedDbResult<Option<IVec>>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let record = self.encrypt(encrypted_value.as_ref())?;
        let prev_record_bytes_opt = self.kv.insert(&key, record.as_bytes()?)?;
        self.decrypt(prev_record_bytes_opt)
    }

    pub fn get<K>(&self, key: K) -> EncryptedDbResult<Option<IVec>>
    where
        K: AsRef<[u8]>,
    {
        let bytes_opt = self.kv.get(&key)?;
        self.decrypt(bytes_opt)
    }

    pub fn contains_key<K>(&self, key: K) -> EncryptedDbResult<bool>
    where
        K: AsRef<[u8]>,
    {
        Ok(self.kv.contains_key(&key)?)
    }

    pub fn remove<K>(&self, key: K) -> EncryptedDbResult<Option<IVec>>
    where
        K: AsRef<[u8]>,
    {
        let prev_val = self.kv.remove(&key)?;
        self.decrypt(prev_val)
    }

    pub fn was_recovered(&self) -> bool {
        self.kv.was_recovered()
    }

    pub fn with_handle_password_verification(self) -> EncryptedDbResult<Self> {
        match self.kv.was_recovered() {
            true => {
                let _ = self.get(VERIFICATION_KEY).map_err(|_| WrongPassword)?;
            }
            false => {
                let _ = self.insert(VERIFICATION_KEY, VERIFICATION_VALUE)?;
            }
        }
        Ok(self)
    }

    #[cfg(test)]
    pub fn flush(&self) -> EncryptedDbResult<usize> {
        Ok(self.kv.flush()?)
    }
}
