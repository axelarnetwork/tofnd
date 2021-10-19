use super::{
    bip39_bindings::{bip39_from_phrase, bip39_new_w24, bip39_seed},
    results::mnemonic::{
        InnerMnemonicError::*, InnerMnemonicResult, MnemonicError::*, MnemonicResult, SeedResult,
    },
};
use crate::{
    gg20::types::{Entropy, Password}, // TODO: move from gg200::types
    kv_manager::{
        error::{InnerKvError, KvError},
        KvManager,
    },
};
use tofn::gg20::keygen::SecretRecoveryKey;

use rpassword::read_password;
use std::convert::TryInto;
use tracing::{error, info};

// default key to store mnemonic
const MNEMONIC_KEY: &str = "mnemonic";

#[derive(Clone, Debug)]
pub enum Cmd {
    Existing,
    Create,
    Import,
    Export,
}

impl Cmd {
    pub fn from_string(cmd_str: &str) -> MnemonicResult<Self> {
        let cmd = match cmd_str {
            "existing" => Self::Existing,
            "create" => Self::Create,
            "import" => Self::Import,
            "export" => Self::Export,
            _ => return Err(WrongCommand(cmd_str.to_string())),
        };
        Ok(cmd)
    }
    /// On [Cmd::Existing], continue tofnd.
    /// On [Cmd::Create], [Cmd::Import] or [Cmd::Export], exit tofnd.
    pub fn exit_after_cmd(&self) -> bool {
        match &self {
            Cmd::Existing => false,
            Cmd::Create => true,
            Cmd::Import => true,
            Cmd::Export => true,
        }
    }
}

/// implement mnemonic-specific functions for Gg20Service
impl KvManager {
    /// get mnemonic seed from kv-store
    pub async fn seed(&self) -> SeedResult<SecretRecoveryKey> {
        let mnemonic = self.kv().get(MNEMONIC_KEY).await?.try_into()?;
        // A user may decide to protect their mnemonic with a passphrase. We pass an empty password for now.
        // https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
        Ok(bip39_seed(mnemonic, Password("".to_owned()))?
            .as_bytes()
            .try_into()?)
    }

    /// async function that handles all mnemonic commands
    pub async fn handle_mnemonic(self, cmd: &Cmd) -> MnemonicResult<Self> {
        let _ = match cmd {
            Cmd::Existing => self.handle_existing().await.map_err(ExistingErr),
            Cmd::Create => self.handle_create().await.map_err(CreateErr),
            Cmd::Import => self.handle_import().await.map_err(ImportErr),
            Cmd::Export => self.handle_export().await.map_err(ExportErr),
        };
        Ok(self)
    }

    /// use the existing mnemonic to spin up a tofnd deamon.
    /// if an export file exists in the default path, returns an error.
    /// if an no mnemonic record exists in the kv-store, returns an error.
    async fn handle_existing(&self) -> InnerMnemonicResult<()> {
        // if there is an exported mnemonic, raise an error and don't start the daemon.
        // we do this to prevent users from accidentally leave their mnemonic on disk in plain text
        self.io().check_if_not_exported()?;

        // try to get mnemonic from kv-store
        match self.kv().exists(MNEMONIC_KEY).await? {
            true => Ok(()),
            false => Err(KvErr(KvError::ExistsErr(InnerKvError::LogicalErr(
                "Mnemonic not found".to_string(),
            )))),
        }
    }

    /// inserts entropy to the kv-store
    /// takes ownership of entropy to delegate zeroization.
    async fn handle_insert(&self, entropy: Entropy) -> InnerMnemonicResult<()> {
        // Don't use `map_err` to make it more readable.
        let reservation = self.kv().reserve_key(MNEMONIC_KEY.to_owned()).await;
        match reservation {
            // if we can reserve, try put
            Ok(reservation) => match self.kv().put(reservation, entropy.to_owned().into()).await {
                // if put is ok, write the phrase to a file
                Ok(()) => {
                    info!("Mnemonic successfully added in kv store. Use the `-m export` command to retrieve it.");
                    Ok(())
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

    /// Creates a new entropy, inserts the entropy in the kv-store and exports it to a file
    /// If a mnemonic already exists in the kv store or an exported file already exists in
    /// the default path, an error is produced
    async fn handle_create(&self) -> InnerMnemonicResult<()> {
        info!("Creating mnemonic");
        // create a new entropy
        let new_entropy = bip39_new_w24();
        self.handle_insert(new_entropy.clone()).await?;
        Ok(self.io().entropy_to_file(new_entropy)?)
    }

    /// Inserts a new mnemonic to the kv-store.
    /// If a mnemonic already exists in the kv store, an error is produced by sled
    /// trying to reserve an existing mnemonic key
    async fn handle_import(&self) -> InnerMnemonicResult<()> {
        info!("Importing mnemonic");
        let imported_phrase = Password(read_password().map_err(|e| PasswordErr(e.to_string()))?);
        let imported_entropy = bip39_from_phrase(imported_phrase)?;
        self.handle_insert(imported_entropy).await
    }

    /// Exports the current mnemonic to a file
    async fn handle_export(&self) -> InnerMnemonicResult<()> {
        info!("Exporting mnemonic");

        // try to get mnemonic from kv-store
        let entropy = self
            .kv()
            .get(MNEMONIC_KEY)
            .await
            .map_err(|err| {
                error!("Did not find mnemonic in kv store {:?}", err);
                err
            })?
            .try_into()?;

        // write to file
        info!("Mnemonic found in kv store");
        Ok(self.io().entropy_to_file(entropy)?)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use testdir::testdir;

    use crate::{
        encrypted_sled::get_test_password,
        gg20::mnemonic::results::{file_io::FileIoError, mnemonic::InnerMnemonicError},
        kv_manager::{
            error::{InnerKvError, KvError},
            KvManager,
        },
    };

    use super::*;
    use tracing_test::traced_test;

    // create a service
    fn get_kv_manager(testdir: PathBuf) -> KvManager {
        // create test dirs
        let kv_path = testdir.to_str().unwrap();
        KvManager::new(kv_path, get_test_password()).unwrap()
    }

    #[traced_test]
    #[tokio::test]
    async fn test_create() {
        let testdir = testdir!();
        // create a service
        let kv = get_kv_manager(testdir);
        // first attempt should succeed
        assert!(kv.handle_create().await.is_ok());
        // second attempt should fail
        assert!(matches!(
            kv.handle_create().await,
            Err(InnerMnemonicError::KvErr(KvError::ReserveErr(
                InnerKvError::LogicalErr(_)
            )))
        ));
    }

    #[traced_test]
    #[tokio::test]
    async fn test_insert() {
        let testdir = testdir!();
        // create a service
        let kv = get_kv_manager(testdir.clone());
        // insert should succeed
        assert!(kv.handle_insert(bip39_new_w24()).await.is_ok());
        // insert should fail
        assert!(matches!(
            kv.handle_insert(bip39_new_w24()).await,
            Err(InnerMnemonicError::KvErr(KvError::ReserveErr(
                InnerKvError::LogicalErr(_)
            )))
        ));
    }

    #[traced_test]
    #[tokio::test]
    async fn test_export() {
        let testdir = testdir!();
        // create a service
        let kv = get_kv_manager(testdir.clone());
        // handle existing should fail
        assert!(matches!(
            kv.handle_existing().await,
            Err(InnerMnemonicError::KvErr(KvError::ExistsErr(
                InnerKvError::LogicalErr(_)
            )))
        ));
        // mnemonic should not be exported
        assert!(kv.io().check_if_not_exported().is_ok());
        // create a new mnemonic
        assert!(kv.handle_create().await.is_ok());
        // mnemonic should now be exported
        assert!(kv.io().check_if_not_exported().is_err());
        // export should fail because create also exports
        assert!(matches!(
            kv.handle_export().await,
            Err(InnerMnemonicError::FileIoErr(FileIoError::Exists(_)))
        ));
        // handle existing should fail because export file exists
        assert!(matches!(
            kv.handle_existing().await,
            Err(InnerMnemonicError::FileIoErr(FileIoError::Exists(_)))
        ));
    }

    #[traced_test]
    #[tokio::test]
    async fn test_existing() {
        let testdir = testdir!();
        // create a service
        let kv = get_kv_manager(testdir.clone());
        // create a new mnemonic
        assert!(kv.handle_create().await.is_ok());
        // handle_existing should fail because export file exists
        assert!(matches!(
            kv.handle_existing().await,
            Err(InnerMnemonicError::FileIoErr(FileIoError::Exists(_)))
        ));
        // export should fail because export file exists
        assert!(matches!(
            kv.handle_export().await,
            Err(InnerMnemonicError::FileIoErr(FileIoError::Exists(_)))
        ));
    }
}
