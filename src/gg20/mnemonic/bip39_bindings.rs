//! This module provides wrappers for mnemonic creation, validation and seed
//! extraction using the tiny-bip39 https://crates.io/crates/tiny-bip39 library.
//! Default language is English

use super::Entropy;
use crate::TofndError;
use bip39::{Language, Mnemonic, Seed};

// TODO: we can enrich the API so that users can decide which language they want to use
const DEFAUT_LANG: Language = Language::English;

/// create a new 24 word mnemonic
pub(crate) fn bip39_new_w24() -> Vec<u8> {
    let mnemonic = Mnemonic::new(bip39::MnemonicType::Words24, DEFAUT_LANG);
    mnemonic.entropy().to_owned()
}

/// create a mnemonic from entropy
pub(super) fn bip39_from_entropy(entropy: &[u8]) -> Result<Mnemonic, TofndError> {
    let res = Mnemonic::from_entropy(&entropy, DEFAUT_LANG);
    match res {
        Ok(mnemonic) => Ok(mnemonic),
        Err(err) => Err(From::from(format!("Invalid entropy: {:?}", err))),
    }
}

/// create a mnemonic from entropy
pub(super) fn bip39_from_phrase(phrase: &str) -> Result<Entropy, TofndError> {
    let res = Mnemonic::from_phrase(&phrase, DEFAUT_LANG);
    match res {
        Ok(mnemonic) => Ok(mnemonic.entropy().to_owned()),
        Err(err) => Err(From::from(format!("Invalid entropy: {:?}", err))),
    }
}

/// extrace seed from mnemonic
pub(super) fn bip39_seed(entropy: &[u8], password: &str) -> Result<Seed, TofndError> {
    let mnemonic = bip39_from_entropy(entropy)?;
    Ok(Seed::new(&mnemonic, password))
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use tracing::info;
    use tracing_test::traced_test;

    /// create a mnemonic from entropy
    pub(crate) fn bip39_to_phrase(entropy: &[u8]) -> Result<String, TofndError> {
        let res = Mnemonic::from_entropy(&entropy, DEFAUT_LANG);
        match res {
            Ok(mnemonic) => Ok(mnemonic.phrase().to_owned()),
            Err(err) => Err(From::from(format!("Invalid entropy: {:?}", err))),
        }
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

        assert!(bip39_from_entropy(&ok_entropy).is_ok());
        assert!(bip39_from_entropy(&err_entropy).is_err());
    }

    #[traced_test]
    #[test]
    fn test_seed() {
        let entropy = &[
            0x33, 0xE4, 0x6B, 0xB1, 0x3A, 0x74, 0x6E, 0xA4, 0x1C, 0xDD, 0xE4, 0x5C, 0x90, 0x84,
            0x6A, 0x79,
        ];
        // expected output as per https://github.com/maciejhirsz/tiny-bip39/blob/master/src/seed.rs#L102
        let expected_output = "0bde96f14c35a66235478e0c16c152fcaf6301e4d9a81d3febc50879fe7e5438e6a8dd3e39bdf3ab7b12d6b44218710e17d7a2844ee9633fab0e03d9a6c8569b";
        let actual_output = format!("{:x}", bip39_seed(entropy, "password").unwrap());
        assert_eq!(expected_output, &actual_output);
    }
}
