//! This module handles file IO.

use std::{io::Write, path::PathBuf};

use tracing::info;

use super::{bip39_bindings::bip39_from_entropy, results::file_io::FileIoError::Exists};
use crate::grpc::types::Entropy;

/// name of export file
const EXPORT_FILE: &str = "export";

use super::results::file_io::FileIoResult;

/// FileIO wraps all IO functionality
#[derive(Clone)]
pub struct FileIo {
    export_path: PathBuf,
}

impl FileIo {
    /// FileIO constructor
    pub fn new(mut export_path: PathBuf) -> FileIo {
        export_path.push(EXPORT_FILE);
        FileIo { export_path }
    }

    /// Get the path of export file
    pub fn export_path(&self) -> &PathBuf {
        &self.export_path
    }

    /// Check if an exported file exists in the expected path
    /// Succeeds if no exported file exists, returns an error otherwise.
    pub fn check_if_not_exported(&self) -> FileIoResult<()> {
        if std::path::Path::new(&self.export_path()).exists() {
            return Err(Exists(self.export_path().clone()));
        }
        Ok(())
    }

    /// Creates a file that contains an entropy in it's human-readable form
    pub(super) fn entropy_to_file(&self, entropy: Entropy) -> FileIoResult<()> {
        // delegate zeroization for entropy; no need to worry about mnemonic, it is cleaned automatically
        let mnemonic = bip39_from_entropy(entropy)?;
        let phrase = mnemonic.phrase();
        // if there is an existing exported file raise an error
        self.check_if_not_exported()?;
        let mut file = std::fs::File::create(&self.export_path())?;
        file.write_all(phrase.as_bytes())?;
        info!("Mnemonic written in file {:?}", &self.export_path());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::mnemonic::bip39_bindings::{bip39_new_w24, tests::bip39_to_phrase};
    use std::io::Read;
    use testdir::testdir;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_write() {
        let entropy = bip39_new_w24();

        let io = FileIo::new(testdir!());
        let filepath = io.export_path();
        io.entropy_to_file(entropy.clone()).unwrap();
        let expected_content = bip39_to_phrase(entropy).unwrap();

        let mut file = std::fs::File::open(filepath).unwrap();
        let mut file_phrase = String::new();
        file.read_to_string(&mut file_phrase).unwrap();
        let file_content = file_phrase;

        assert_eq!(file_content, expected_content.0);
    }
}
