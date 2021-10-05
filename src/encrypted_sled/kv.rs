//! Wrap [sled] with [chacha20poly1305] encryption. An [XChaCha20Entropy] is
//! used as [XChaCha20Poly1305] cipher key to create an [EncryptedDb].
//! A new random [XChaCha20Nonce] is created every time a new value needs to be
//! inserted, forming a [EncryptedRecord]:<encrypted value, nonce>. The nonce is later
//! used to decrypt and retrieve the originally inserted value.

use std::convert::TryInto;

use chacha20poly1305::aead::{AeadInPlace, NewAead};
use chacha20poly1305::{self, XChaCha20Poly1305};
use rand::RngCore;

use sled::IVec;
use zeroize::Zeroize;

use super::constants::*;
use super::password::{Password, PasswordSalt};
use super::record::EncryptedRecord;
use super::result::{EncryptedDbError::*, EncryptedDbResult};

/// A [sled] kv store with [XChaCha20Poly1305] value encryption.
pub struct EncryptedDb {
    kv: sled::Db,
    cipher: XChaCha20Poly1305,
}

impl EncryptedDb {
    /// create a new [EncryptedDb] that wraps sled::open(db_name).
    /// Retrieves [XChaCha20Entropy] from a password-based-key-derivation-function and
    /// verifies that the password is valid.
    /// See [crate::password] for more info on pdkdf.
    pub fn open<P>(db_name: P, password: Password) -> EncryptedDbResult<Self>
    where
        P: AsRef<std::path::Path>,
    {
        let kv = sled::open(db_name).map_err(CorruptedKv)?;

        let password_salt: PasswordSalt = if kv.was_recovered() {
            // existing kv: get the existing password salt
            kv.get(PASSWORD_SALT_KEY)?
                .ok_or(MissingPasswordSalt)?
                .try_into()?
        } else {
            // new kv: choose a new password salt and store it
            let mut password_salt = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut password_salt);
            kv.insert(PASSWORD_SALT_KEY, &password_salt)?;
            password_salt.into()
        };

        // zeroize key since we are no longer using it after creating cipher
        let mut key = Self::chacha20poly1305_kdf(password, password_salt)?;
        let cipher = XChaCha20Poly1305::new(&key);
        key.zeroize();

        let encrypted_db = EncryptedDb { kv, cipher };

        // verify that [password] is correct
        if encrypted_db.kv.was_recovered() {
            // existing kv: can we decrypt the verification value?
            encrypted_db
                .get(PASSWORD_VERIFICATION_KEY)
                .map_err(|_| WrongPassword)?;
        } else {
            // new kv: encrypt the verification value
            encrypted_db.insert(PASSWORD_VERIFICATION_KEY, PASSWORD_VERIFICATION_VALUE)?;
        }

        Ok(encrypted_db)
    }

    fn chacha20poly1305_kdf(
        password: Password,
        salt: PasswordSalt,
    ) -> EncryptedDbResult<chacha20poly1305::Key> {
        let mut output = chacha20poly1305::Key::default();

        // default params: log_n = 15, r = 8, p = 1
        scrypt::scrypt(
            password.as_ref(),
            salt.as_ref(),
            &scrypt::Params::default(),
            output.as_mut_slice(),
        )?;

        Ok(output)
    }

    /// get a new random nonce to use for value encryption using [rand::thread_rng]
    fn generate_nonce() -> chacha20poly1305::XNonce {
        let mut bytes = chacha20poly1305::XNonce::default();
        rand::thread_rng().fill_bytes(bytes.as_mut_slice());
        bytes
    }

    /// create a new [EncryptedRecord] containing an encrypted value and a newly derived random nonce
    fn encrypt<V>(&self, value: V) -> EncryptedDbResult<EncryptedRecord>
    where
        V: Into<IVec>,
    {
        let nonce = Self::generate_nonce();

        let mut value = value.into().to_vec();

        // encrypt value
        self.cipher
            .encrypt_in_place(&nonce, b"", &mut value)
            .map_err(|e| Encryption(e.to_string()))?;

        // return record
        Ok(EncryptedRecord::new(value, nonce))
    }

    /// derive a decrypted value from a [EncryptedRecord] containing an encrypted value and a random nonce
    fn decrypt_record_value(&self, record: EncryptedRecord) -> EncryptedDbResult<IVec> {
        let (mut value, nonce) = record.into();

        // decrypt value
        self.cipher
            .decrypt_in_place(&nonce, b"", &mut value)
            .map_err(|e| Decryption(e.to_string()))?;

        // return decrypted value
        Ok(value.into())
    }

    /// derive a decrypted value from [EncryptedRecord] bytes
    fn decrypt(&self, record_bytes: Option<IVec>) -> EncryptedDbResult<Option<IVec>> {
        let res = match record_bytes {
            Some(record_bytes) => {
                let record = EncryptedRecord::from_bytes(&record_bytes)?;
                let decrypted_value_bytes = self.decrypt_record_value(record)?;
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
        let prev_record_bytes_opt = self.kv.insert(&key, record.to_bytes()?)?;
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

    #[cfg(test)]
    pub fn flush(&self) -> EncryptedDbResult<usize> {
        Ok(self.kv.flush()?)
    }
}
