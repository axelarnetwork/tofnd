//! Wrap [sled] with [chacha20poly1305] encryption. An [XChaCha20Entropy] is
//! used as [XChaCha20Poly1305] cipher key to create an [EncryptedDb].
//! A new random [XChaCha20Nonce] is created everytime a new value needs to be
//! inserted, forming a [Record]:<encrypted value, nonce>. The nonce is later
//! used to decrypt and retrieve the originally inserted value.

use chacha20poly1305::aead::{AeadInPlace, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use sled::IVec;

use super::record::Record;
use super::types::{EncryptedDbKey, XChaCha20Nonce};
use super::{
    constants::*,
    result::{
        EncryptedDbError::{CorruptionError, Decryption, Encryption, WrongPassword},
        EncryptedDbResult,
    },
};

/// create a new [EncryptedDb] that wraps sled::open(db_name).
/// Retrieves [XChaCha20Entropy] from a password-based-key-derivation-function and
/// verifies that the password is valid.
/// See [crate::password] for more info on pdkdf.
pub fn open<P>(db_name: P, entropy: &EncryptedDbKey) -> EncryptedDbResult<EncryptedDb>
where
    P: AsRef<std::path::Path>,
{
    let key = Key::from_slice(entropy.0.as_ref());
    let cipher = XChaCha20Poly1305::new(key);

    let kv = sled::open(db_name).map_err(CorruptionError)?;
    EncryptedDb::new(kv, cipher)
}

/// A [sled] kv store with [XChaCha20Poly1305] value encryption.
pub struct EncryptedDb {
    kv: sled::Db,
    cipher: XChaCha20Poly1305,
}

impl EncryptedDb {
    fn new(kv: sled::Db, cipher: XChaCha20Poly1305) -> EncryptedDbResult<Self> {
        Self { kv, cipher }.with_handle_password_verification()
    }

    /// get a new random nonce to use for value encryption using [rand::thread_rng]
    fn get_random_nonce() -> XNonce {
        use rand::Rng;
        rand::thread_rng().gen::<XChaCha20Nonce>().into()
    }

    /// create a new [Record] containing an encrypted value and a newly derived random nonce
    fn encrypt<V>(&self, value: V) -> EncryptedDbResult<Record>
    where
        V: Into<IVec>,
    {
        let nonce = Self::get_random_nonce();

        let mut value = value.into().to_vec();

        // encrypt value
        self.cipher
            .encrypt_in_place(&nonce, b"", &mut value)
            .map_err(|e| Encryption(e.to_string()))?;

        // return record
        Ok(Record::new(value, nonce))
    }

    /// derive a decrypted value from a [Record] containing an encrypted value and a random nonce
    fn decrypt_record_value(&self, record: Record) -> EncryptedDbResult<IVec> {
        // get nonce
        let nonce = XNonce::from_slice(&record.nonce);

        let mut value = record.encrypted_value;

        // decrypt value
        self.cipher
            .decrypt_in_place(nonce, b"", &mut value)
            .map_err(|e| Decryption(e.to_string()))?;

        // return decrypted value
        Ok(value.into())
    }

    /// derive a decrypted value from [Record] bytes
    fn decrypt(&self, record_bytes: Option<IVec>) -> EncryptedDbResult<Option<IVec>> {
        let res = match record_bytes {
            Some(record_bytes) => {
                let record = Record::from_bytes(&record_bytes)?;
                let decrypted_value_bytes = self.decrypt_record_value(record)?.into();
                Some(decrypted_value_bytes)
            }
            None => None,
        };
        Ok(res)
    }

    /// Insert a key to a new encrypted value, returning and decrypting the last value if it was set.
    pub fn insert<K, V>(&self, key: K, value: V) -> EncryptedDbResult<Option<IVec>>
    where
        K: AsRef<[u8]>,
        V: Into<IVec>,
    {
        let record = self.encrypt(value)?;
        let prev_record_bytes_opt = self.kv.insert(&key, record.as_bytes()?)?;
        self.decrypt(prev_record_bytes_opt)
    }

    /// Retrieve and decrypt a value from the `Tree` if it exists.
    pub fn get<K>(&self, key: K) -> EncryptedDbResult<Option<IVec>>
    where
        K: AsRef<[u8]>,
    {
        let bytes_opt = self.kv.get(&key)?;
        self.decrypt(bytes_opt)
    }

    /// Returns `true` if the `Tree` contains a value for the specified key.
    pub fn contains_key<K>(&self, key: K) -> EncryptedDbResult<bool>
    where
        K: AsRef<[u8]>,
    {
        Ok(self.kv.contains_key(&key)?)
    }

    /// Delete a value, decrypting and returning the old value if it existed.
    pub fn remove<K>(&self, key: K) -> EncryptedDbResult<Option<IVec>>
    where
        K: AsRef<[u8]>,
    {
        let prev_val = self.kv.remove(&key)?;
        self.decrypt(prev_val)
    }

    /// Returns true if the database was recovered from a previous process.
    pub fn was_recovered(&self) -> bool {
        self.kv.was_recovered()
    }

    /// Checks if the kv store is created using the correct password.
    pub fn with_handle_password_verification(self) -> EncryptedDbResult<Self> {
        // check if re recovered
        match self.kv.was_recovered() {
            true => {
                // if we recovered, check if we can get the verification correctly
                let _ = self.get(VERIFICATION_KEY).map_err(|_| WrongPassword)?;
            }
            false => {
                // if opened for the first time, insert a default record to enable verification
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
