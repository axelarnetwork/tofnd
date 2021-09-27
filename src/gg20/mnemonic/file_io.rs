//! This module handles IO to files. More specifically, reading passphrases.

use std::{io::Write, path::PathBuf};

use tracing::info;

use super::{bip39_bindings::bip39_from_entropy, error::file_io::FileIoError::Exists};
use crate::gg20::types::Entropy;

/// name of export file
const EXPORT_FILE: &str = "export";

use super::error::file_io::FileIoResult;

/// FileIO wraps all IO functionality
#[derive(Clone)]
pub struct FileIo {
    path: PathBuf,
}

impl FileIo {
    /// FileIO constructor
    pub fn new(mut path: PathBuf) -> FileIo {
        path.push(EXPORT_FILE);
        FileIo { path }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Creates a file that contains an entropy in it's human-readable form
    pub(super) fn entropy_to_file(&self, entropy: Entropy) -> FileIoResult<()> {
        // delegate zeroization for entropy; no need to worry about mnemonic, it is cleaned automatically
        let mnemonic = bip39_from_entropy(entropy)?;
        let phrase = mnemonic.phrase();
        if std::path::Path::new(&self.path()).exists() {
            return Err(Exists(self.path().clone()));
        }
        let mut file = std::fs::File::create(&self.path())?;
        file.write_all(phrase.as_bytes())?;
        info!("Mnemonic written in file {:?}", &self.path());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gg20::mnemonic::bip39_bindings::{bip39_new_w24, tests::bip39_to_phrase};
    use std::io::Read;
    use testdir::testdir;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_write() {
        let entropy = bip39_new_w24();

        let io = FileIo::new(testdir!());
        let filepath = io.path();
        io.entropy_to_file(entropy.clone()).unwrap();
        let expected_content = bip39_to_phrase(entropy).unwrap();

        let mut file = std::fs::File::open(filepath).unwrap();
        let mut file_phrase = String::new();
        file.read_to_string(&mut file_phrase).unwrap();
        let file_content = file_phrase;

        assert_eq!(file_content, expected_content.0);
    }
}
