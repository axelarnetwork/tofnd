//! This module handles mnemonic-related commands. A kv-store is used to import, edit and export an [Entropy].
//!
//! Currently, the API supports the following [Cmd] commands:
//!     [Cmd::Noop]: does nothing; Always succeeds; useful when the container restarts with the same mnemonic.
//!     [Cmd::Create]: creates a new mnemonic; Creates a new mnemonic when none is already imported, otherwise does nothing.
//!     [Cmd::Import]: adds a new mnemonic from "import" file; Succeeds when there is no other mnemonic already imported, fails otherwise.
//!     [Cmd::Export]: writes the existing mnemonic to a file; Succeeds when there is an existing mnemonic, fails otherwise.
//!     [Cmd::Update]: updates existing mnemonic from file "import"; Succeeds when there is an existing mnemonic, fails otherwise.
//!     In [Cmd::Create], [Cmd::Export] commands, a new "export" file is created that contains the current phrase.
//!     In [Cmd::Update] command, a new "export" file is created that contains the replaced pasphrase.

pub mod bip39_bindings; // this also needed in tests
use bip39_bindings::{bip39_from_phrase, bip39_new_w24, bip39_seed};

pub(super) mod file_io;
use file_io::IMPORT_FILE;

mod error;
use error::mnemonic::{
    InnerMnemonicError::*, InnerMnemonicResult, MnemonicError::*, MnemonicResult, SeedResult,
};

use super::{
    service::Gg20Service,
    types::{Entropy, Password},
};
use tracing::{error, info};

// default key to store mnemonic
const MNEMONIC_KEY: &str = "mnemonic";

#[derive(Clone, Debug)]
pub enum Cmd {
    Noop,
    Create,
    Import,
    Update,
    Export,
}

impl Cmd {
    pub fn from_string(cmd_str: &str) -> MnemonicResult<Self> {
        let cmd = match cmd_str {
            "stored" => Self::Noop,
            "create" => Self::Create,
            "import" => Self::Import,
            "update" => Self::Update,
            "export" => Self::Export,
            _ => return Err(WrongCommand(cmd_str.to_string())),
        };
        Ok(cmd)
    }
}

/// implement mnemonic-specific functions for Gg20Service
impl Gg20Service {
    /// async function that handles all mnemonic commands
    pub async fn handle_mnemonic(&self) -> MnemonicResult<()> {
        match self.cfg.mnemonic_cmd {
            Cmd::Noop => Ok(()),
            Cmd::Create => self.handle_create().await.map_err(CreateErr),
            Cmd::Import => self.handle_import().await.map_err(ImportErr),
            Cmd::Update => self.handle_update().await.map_err(UpdateErr),
            Cmd::Export => self.handle_export().await.map_err(ExportErr),
        }
    }

    /// inserts entropy to the kv-store and writes inserted value to an "export" file.
    /// takes ownership of entropy to delegate zeroization.
    async fn handle_insert(&self, entropy: Entropy) -> InnerMnemonicResult<()> {
        // Don't use `map_err` to make it more readable.
        let reservation = self.mnemonic_kv.reserve_key(MNEMONIC_KEY.to_owned()).await;
        match reservation {
            // if we can reserve, try put
            Ok(reservation) => match self.mnemonic_kv.put(reservation, entropy.to_owned()).await {
                // if put is ok, write the phrase to a file
                Ok(()) => {
                    info!("Mnemonic successfully added in kv store");
                    Ok(self.io.entropy_to_next_file(entropy)?)
                }
                // else return failure
                Err(err) => {
                    error!("Cannot put mnemonic in kv store: {:?}", err);
                    Err(KvErr(err))
                }
            },
            // if we cannot reserve, return failure
            Err(err) => {
                error!("Cannot reserve mnemonic: {:?}", err);
                Err(KvErr(err))
            }
        }
    }

    /// Creates a new entropy and delegates 1) insertion to the kv-store, and 2) write to an "export" file
    /// If a mnemonic already exists in the kv store, fall back to that
    /// TODO: In the future we might want to throw an error here if mnemonic already exists.
    async fn handle_create(&self) -> InnerMnemonicResult<()> {
        info!("Creating mnemonic");
        // if we already have a mnemonic in kv-store, use that instead of creating a new one.
        // we do this to use "create mnemonic" as the default behaviour for now.
        if self.mnemonic_kv.get(MNEMONIC_KEY).await.is_ok() {
            info!("Existing menomonic was found.");
            return Ok(());
        }

        // create an entropy and zeroize after use
        let new_entropy = bip39_new_w24();
        Ok(self.handle_insert(new_entropy).await?)
    }

    // Inserts a new mnemonic to the kv-store, and writes the phrase to an "export" file
    // Fails if a mnemonic already exists in the kv store
    async fn handle_import(&self) -> InnerMnemonicResult<()> {
        info!("Importing mnemonic");
        let imported_phrase = self.io.phrase_from_file(IMPORT_FILE)?;
        let imported_entropy = bip39_from_phrase(imported_phrase)?;
        self.handle_insert(imported_entropy).await
    }

    /// Updates a mnemonic.
    // 1. deletes the existing one
    // 2. writes an "export" file with the deleted key
    // 3. reads a new mnemonic from "import" file
    // 4. delegates the insertions of the new mnemonics to the kv-store, and writes the phrase to an "export" file
    // Fails if a mnemonic already exists in the kv store, of if no "import" file exists
    async fn handle_update(&self) -> InnerMnemonicResult<()> {
        info!("Updating mnemonic");

        // try to delete the old mnemonic
        let deleted_entropy = self.mnemonic_kv.remove(MNEMONIC_KEY).await.map_err(|err| {
            error!("Delete error: {}", err);
            KvErr(err)
        })?;

        // try to write mnemonic to a new file
        self.io.entropy_to_next_file(deleted_entropy)?;

        // try to insert new mnemonic
        let new_phrase = self.io.phrase_from_file(IMPORT_FILE)?;

        // try to get entropy from passphrase
        let new_entropy = bip39_from_phrase(new_phrase)?;

        // try to insert entropy to kv store
        Ok(self.handle_insert(new_entropy).await?)
    }

    /// Exports the current mnemonic to an "export" file
    async fn handle_export(&self) -> InnerMnemonicResult<()> {
        info!("Exporting mnemonic");

        // try to get mnemonic from kv-store
        let entropy = self.mnemonic_kv.get(MNEMONIC_KEY).await.map_err(|err| {
            error!("Did not find mnemonic in kv store {:?}", err);
            err
        })?;

        // write to file
        info!("Mnemonic found in kv store");
        Ok(self.io.entropy_to_next_file(entropy)?)
    }
}

use tofn::gg20::keygen::SecretRecoveryKey;
/// ease tofn API
impl Gg20Service {
    pub async fn seed(&self) -> SeedResult<SecretRecoveryKey> {
        use std::convert::TryInto;
        let mnemonic = self.mnemonic_kv.get(MNEMONIC_KEY).await?;
        // A user may decide to protect their mnemonic with a passphrase. If not, pass an empty password
        // https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
        Ok(bip39_seed(mnemonic, Password("".to_owned()))?
            .as_bytes()
            .try_into()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::encrypted_sled;
    use crate::gg20::mnemonic::{bip39_bindings::tests::bip39_to_phrase, file_io::FileIo};
    use crate::gg20::{KeySharesKv, MnemonicKv};
    use std::io::Write;
    use std::path::PathBuf;
    use testdir::testdir;
    use tracing_test::traced_test; // logs for tests

    // create a service
    fn get_service(testdir: PathBuf) -> Gg20Service {
        // create test dirs for kvstores
        let shares_kv_path = testdir.join("shares");
        let shares_kv_path = shares_kv_path.to_str().unwrap();
        let mnemonic_kv_path = testdir.join("mnemonic");
        let mnemonic_kv_path = mnemonic_kv_path.to_str().unwrap();

        let password = encrypted_sled::get_test_password();
        Gg20Service {
            shares_kv: KeySharesKv::with_db_name(shares_kv_path.to_owned(), password.clone())
                .unwrap(),
            mnemonic_kv: MnemonicKv::with_db_name(mnemonic_kv_path.to_owned(), password).unwrap(),
            io: FileIo::new(testdir),
            cfg: Config::default(),
        }
    }

    fn create_import_file(mut path: PathBuf) {
        path.push(IMPORT_FILE);
        let create = std::fs::File::create(path);
        if create.is_err() {
            // file already exists. Don't do anything.
            return;
        }
        let mut file = create.unwrap();

        let entropy = bip39_new_w24();
        let phrase = bip39_to_phrase(entropy).unwrap();
        file.write_all(phrase.0.as_bytes()).unwrap();
    }

    #[traced_test]
    #[tokio::test]
    async fn test_create() {
        let testdir = testdir!();
        // create a service
        let gg20 = get_service(testdir);
        // first attempt should succeed
        assert!(gg20.handle_create().await.is_ok());
        // second attempt should also succeed
        assert!(gg20.handle_create().await.is_ok());
    }

    #[traced_test]
    #[tokio::test]
    async fn test_import() {
        let testdir = testdir!();
        // create a service
        let gg20 = get_service(testdir.clone());
        create_import_file(testdir);
        // first attempt should succeed
        assert!(gg20.handle_import().await.is_ok());
        // second attempt should fail
        assert!(gg20.handle_import().await.is_err())
    }

    #[traced_test]
    #[tokio::test]
    async fn test_update() {
        let testdir = testdir!();
        // create a service
        let gg20 = get_service(testdir.clone());
        // first attempt to update should fail
        assert!(gg20.handle_update().await.is_err());
        create_import_file(testdir);
        // import should succeed
        assert!(gg20.handle_import().await.is_ok());
        // second attempt to update should succeed
        assert!(gg20.handle_update().await.is_ok());
        // export should succeed
        assert!(gg20.handle_export().await.is_ok());
    }

    #[traced_test]
    #[tokio::test]
    async fn test_export() {
        let testdir = testdir!();
        // create a service
        let gg20 = get_service(testdir.clone());
        // export should fail
        assert!(gg20.handle_export().await.is_err());
        create_import_file(testdir);
        // import should succeed
        assert!(gg20.handle_import().await.is_ok());
        // export should now succeed
        assert!(gg20.handle_export().await.is_ok());
    }
}
