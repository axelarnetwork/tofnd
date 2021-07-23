//! This module handles IO to files. More specifically, writing and reading passphrases.

use std::{
    io::{Read, Write},
    path::PathBuf,
};

use tracing::info;

use super::super::mnemonic::bip39_bindings::bip39_from_entropy;
use crate::{
    gg20::types::{Entropy, Password},
    TofndError,
};

/// Standard names
const EXPORT_FILE: &str = "export";
pub(super) const IMPORT_FILE: &str = "import";

/// FileIO wraps all IO functionality
#[derive(Clone)]
pub(crate) struct FileIo {
    path: PathBuf,
}

impl FileIo {
    /// FileIO constructor
    pub fn new(path: PathBuf) -> FileIo {
        FileIo { path }
    }

    /// Get the next available "export" filename in self.path
    /// If "export" exists, "export_2" is created. Then "export_3" etc.
    fn next_filepath(&self) -> PathBuf {
        let mut filepath = self.path.clone();
        filepath.push(EXPORT_FILE);
        let mut id = 1;
        while filepath.exists() {
            filepath = self.path.clone();
            filepath.push(EXPORT_FILE.to_owned() + "_" + &id.to_string());
            id += 1;
        }
        filepath
    }

    /// Creates a file that contains an entropy in it's human-readable form
    pub(super) fn entropy_to_next_file(&self, entropy: Entropy) -> Result<(), TofndError> {
        // delegate zeroization for entropy; no need to worry about mnemonic, it is cleaned automatically
        let mnemonic = bip39_from_entropy(entropy)?;
        let phrase = mnemonic.phrase();
        info!("Phrase from entropy: {}", phrase);
        let filepath = self.next_filepath();
        let mut file = std::fs::File::create(filepath.clone())?;
        file.write_all(phrase.as_bytes())?;
        info!("Mnemonic written in file {:?}", filepath);
        Ok(())
    }

    /// Returns the phrase from a file
    pub(super) fn phrase_from_file(&self, filename: &str) -> Result<Password, TofndError> {
        let mut filepath = self.path.clone();
        filepath.push(filename);
        let mut file = std::fs::File::open(filepath)?;
        let mut mnemonic_phrase = String::new();
        // if read_to_string fails, we don't need to worry about zeroizing mnemonic phrase; we never got it
        file.read_to_string(&mut mnemonic_phrase)?;
        Ok(Password(mnemonic_phrase))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gg20::mnemonic::bip39_bindings::{bip39_new_w24, tests::bip39_to_phrase};
    use testdir::testdir;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_write_read() {
        let io = FileIo { path: testdir!() };
        let entropy = bip39_new_w24();
        let entropy_copy = entropy.clone();
        let filepath = io.next_filepath();
        io.entropy_to_next_file(entropy).unwrap();
        let filename = filepath.file_name().unwrap().to_str().unwrap();
        let file_content = io.phrase_from_file(filename).unwrap();
        let expected_content = bip39_to_phrase(entropy_copy).unwrap();
        assert_eq!(file_content.0, expected_content.0);
    }

    #[test]
    fn test_read() {
        let io = FileIo { path: testdir!() };
        let file_content = io.phrase_from_file("non-existing-file");
        assert!(file_content.is_err());
    }
}
