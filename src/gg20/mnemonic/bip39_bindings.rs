//! This module provides wrappers for mnemonic creation, validation and seed
//! extraction using the tiny-bip39 https://crates.io/crates/tiny-bip39 library.
//!
//! Default (and only) language is English. More languages to be added in the future.
//!
//! Zeroization:
//!   All functions that accept entropy or passphrase, take ownership of these
//!   variables and zeroize sensitive info before exiting.

use super::Entropy;
use crate::TofndError;
use bip39::{Language, Mnemonic, Seed};
use zeroize::Zeroize;

// TODO: we can enrich the API so that users can decide which language they want to use
const DEFAUT_LANG: Language = Language::English;

/// create a new 24 word mnemonic
pub(crate) fn bip39_new_w24() -> Vec<u8> {
    let mnemonic = Mnemonic::new(bip39::MnemonicType::Words24, DEFAUT_LANG);
    mnemonic.entropy().to_owned()
}

/// create a mnemonic from entropy; takes ownership of entropy and zeroizes it afterwards
pub(super) fn bip39_from_entropy(mut entropy: Entropy) -> Result<Mnemonic, TofndError> {
    let res = Mnemonic::from_entropy(&entropy, DEFAUT_LANG);
    entropy.zeroize();
    match res {
        Ok(mnemonic) => Ok(mnemonic),
        Err(err) => Err(From::from(format!("Invalid entropy: {:?}", err))),
    }
}

/// create a mnemonic from entropy
/// takes ownership of phrase and zeroizes it
pub(super) fn bip39_from_phrase(mut phrase: String) -> Result<Entropy, TofndError> {
    let res = Mnemonic::from_phrase(&phrase, DEFAUT_LANG);
    phrase.zeroize();
    match res {
        Ok(mnemonic) => Ok(mnemonic.entropy().to_owned()),
        Err(err) => Err(From::from(format!("Invalid entropy: {:?}", err))),
    }
}

/// extract seed from mnemonic; takes ownership of entropy and password and zeroizes them before exit
pub(super) fn bip39_seed(entropy: Vec<u8>, mut password: String) -> Result<Seed, TofndError> {
    // pass ownership of entropy and delegate zeroization
    let res = match bip39_from_entropy(entropy) {
        Ok(mnemonic) => Ok(Seed::new(&mnemonic, &password)),
        Err(err) => Err(From::from(format!(
            "could not create bip39 from entropy: {}",
            err
        ))),
    };
    password.zeroize();
    res
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use tracing::info;
    use tracing_test::traced_test;

    /// create a mnemonic from entropy; takes ownership of entropy and zeroizes it after
    pub(crate) fn bip39_to_phrase(mut entropy: Vec<u8>) -> Result<String, TofndError> {
        let res = match Mnemonic::from_entropy(&entropy, DEFAUT_LANG) {
            Ok(mnemonic) => Ok(mnemonic.phrase().to_owned()),
            Err(err) => Err(From::from(format!("Invalid entropy: {:?}", err))),
        };
        entropy.zeroize();
        res
    }

    #[traced_test]
    #[test]
    fn test_create() {
        let entropy = bip39_new_w24();
        let mnemonic = Mnemonic::from_entropy(&entropy, DEFAUT_LANG).unwrap();
        let passphrase = mnemonic.phrase();
        info!(
            "created passphrase [{}] from entropy [{:?}]",
            passphrase, &entropy
        );
    }

    #[traced_test]
    #[test]
    fn test_from_entropy() {
        let ok_entropy = vec![42; 16];
        let err_entropy = vec![42; 15];

        assert!(bip39_from_entropy(ok_entropy).is_ok());
        assert!(bip39_from_entropy(err_entropy).is_err());
    }

    #[traced_test]
    #[test]
    fn test_seed() {
        let entropy = vec![
            0x33, 0xE4, 0x6B, 0xB1, 0x3A, 0x74, 0x6E, 0xA4, 0x1C, 0xDD, 0xE4, 0x5C, 0x90, 0x84,
            0x6A, 0x79,
        ];
        // expected output as per https://github.com/maciejhirsz/tiny-bip39/blob/master/src/seed.rs#L102
        let expected_output = "0bde96f14c35a66235478e0c16c152fcaf6301e4d9a81d3febc50879fe7e5438e6a8dd3e39bdf3ab7b12d6b44218710e17d7a2844ee9633fab0e03d9a6c8569b";
        let actual_output = format!("{:x}", bip39_seed(entropy, "password".to_owned()).unwrap());
        assert_eq!(expected_output, &actual_output);
    }
}
