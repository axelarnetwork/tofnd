//! This module provides wrappers for mnemonic creation, validation and seed
//! extraction using the tiny-bip39 https://crates.io/crates/tiny-bip39 library.
//!
//! Default (and only) language is English. More languages to be added in the future.
//!
//! Zeroization:
//!   All functions that accept and/or return structs that implement zeroization:
//!   [crate::gg20::Password], [crate::gg20::Entropy], [bip39::Mnemonic], [bip39::Seed]

use super::results::bip39::{Bip39Error::*, Bip39Result};
use super::types::{Entropy, Password};
use bip39::{Language, Mnemonic, Seed};

// TODO: we can enrich the API so that users can decide which language they want to use
const DEFAUT_LANG: Language = Language::English;

/// create a new 24 word mnemonic
pub(super) fn bip39_new_w24() -> Entropy {
    let mnemonic = Mnemonic::new(bip39::MnemonicType::Words24, DEFAUT_LANG);
    Entropy(mnemonic.entropy().to_owned())
}

/// create a [Mnemonic] from [Entropy]; takes ownership of entropy and zeroizes it before exit
pub(super) fn bip39_from_entropy(entropy: Entropy) -> Bip39Result<Mnemonic> {
    // try to get mnemonic from entropy
    Mnemonic::from_entropy(&entropy.0, DEFAUT_LANG).map_err(|_| FromEntropy)
}

/// create an [Entropy] from [Mnemonic]; takes ownership of phrase and zeroizes it before exit
pub(super) fn bip39_from_phrase(phrase: Password) -> Bip39Result<Entropy> {
    // matching feels better than map_err() here
    match Mnemonic::from_phrase(&phrase.0, DEFAUT_LANG) {
        Ok(mnemonic) => Ok(Entropy(mnemonic.entropy().to_owned())),
        Err(_) => Err(FromPhrase),
    }
}

/// extract [Seed] from [Mnemonic]; takes ownership of entropy and password and zeroizes them before exit
pub(super) fn bip39_seed(entropy: Entropy, password: Password) -> Bip39Result<Seed> {
    // matching feels better than map_err() here
    match bip39_from_entropy(entropy) {
        Ok(mnemonic) => Ok(Seed::new(&mnemonic, &password.0)),
        Err(_) => Err(FromEntropy),
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use tracing::info;
    use tracing_test::traced_test;

    /// create a mnemonic from entropy; takes ownership of entropy and zeroizes it after
    pub fn bip39_to_phrase(entropy: Entropy) -> Bip39Result<Password> {
        match Mnemonic::from_entropy(&entropy.0, DEFAUT_LANG) {
            Ok(mnemonic) => Ok(Password(mnemonic.phrase().to_owned())),
            Err(_) => Err(FromEntropy),
        }
    }

    #[traced_test]
    #[test]
    fn create() {
        let entropy = bip39_new_w24();
        let mnemonic = Mnemonic::from_entropy(&entropy.0, DEFAUT_LANG).unwrap();
        let passphrase = mnemonic.phrase();
        info!(
            "created passphrase [{}] from entropy [{:?}]",
            passphrase, &entropy
        );
    }

    #[traced_test]
    #[test]
    fn from_entropy() {
        let ok_entropy = Entropy(vec![42; 16]);
        let err_entropy = Entropy(vec![42; 15]);

        assert!(bip39_from_entropy(ok_entropy).is_ok());
        assert!(bip39_from_entropy(err_entropy).is_err());
    }

    #[traced_test]
    #[test]
    fn seed_known_vector() {
        // Expected output: https://github.com/maciejhirsz/tiny-bip39/blob/master/src/seed.rs#L102
        let entropy = vec![
            0x33, 0xE4, 0x6B, 0xB1, 0x3A, 0x74, 0x6E, 0xA4, 0x1C, 0xDD, 0xE4, 0x5C, 0x90, 0x84,
            0x6A, 0x79,
        ];

        let output =
            hex::encode(bip39_seed(Entropy(entropy), Password("password".to_owned())).unwrap());

        goldie::assert_json!(output);
    }
}
