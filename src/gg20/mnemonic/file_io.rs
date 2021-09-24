//! This module handles IO to files. More specifically, writing and reading passphrases.

use std::{
    io::{Read, Write},
    path::PathBuf,
};

use tracing::info;

use super::{bip39_bindings::bip39_from_entropy, error::file_io::FileIoError::Exists};
use crate::gg20::types::{Entropy, Password};

/// Standard names
const EXPORT_FILE: &str = "export";
pub(super) const IMPORT_FILE: &str = "import";

use super::error::file_io::FileIoResult;

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

    /// Get the path of "export" filename
    fn filepath(&self) -> PathBuf {
        let mut filepath = self.path.clone();
        filepath.push(EXPORT_FILE);
        filepath
    }

    /// Creates a file that contains an entropy in it's human-readable form
    pub(super) fn entropy_to_file(&self, entropy: Entropy) -> FileIoResult<()> {
        // delegate zeroization for entropy; no need to worry about mnemonic, it is cleaned automatically
        let mnemonic = bip39_from_entropy(entropy)?;
        let phrase = mnemonic.phrase();
        let filepath = self.filepath();
        if std::path::Path::new(&filepath).exists() {
            return Err(Exists(filepath));
        }
        let mut file = std::fs::File::create(filepath.clone())?;
        file.write_all(phrase.as_bytes())?;
        info!("Mnemonic written in file {:?}", filepath);
        Ok(())
    }

    /// Returns the phrase from a file
    pub(super) fn phrase_from_file(&self, filename: &str) -> FileIoResult<Password> {
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
        let filepath = io.filepath();
        io.entropy_to_file(entropy).unwrap();
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
