use super::{
    bip39_bindings::{bip39_from_phrase, bip39_new_w24, bip39_seed},
    results::mnemonic::{
        InnerMnemonicError::*, InnerMnemonicResult, MnemonicError::*, MnemonicResult, SeedResult,
    },
};
use crate::{
    gg20::{
        service::Gg20Service,
        types::{Entropy, Password},
    },
    kv_manager::error::{InnerKvError, KvError},
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
impl Gg20Service {
    /// get mnemonic seed from kv-store
    pub async fn seed(&self) -> SeedResult<SecretRecoveryKey> {
        let mnemonic = self.mnemonic_kv.get(MNEMONIC_KEY).await?;
        // A user may decide to protect their mnemonic with a passphrase. We pass an empty password for now.
        // https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
        Ok(bip39_seed(mnemonic, Password("".to_owned()))?
            .as_bytes()
            .try_into()?)
    }

    /// async function that handles all mnemonic commands
    pub async fn handle_mnemonic(&self) -> MnemonicResult<()> {
        match self.cfg.mnemonic_cmd {
            Cmd::Existing => self.handle_existing().await.map_err(ExistingErr),
            Cmd::Create => self.handle_create().await.map_err(CreateErr),
            Cmd::Import => self.handle_import().await.map_err(ImportErr),
            Cmd::Export => self.handle_export().await.map_err(ExportErr),
        }
    }

    /// use the existing mnemonic to spin up a tofnd deamon.
    /// if an export file exists in the default path, returns an error.
    /// if an no mnemonic record exists in the kv-store, returns an error.
    async fn handle_existing(&self) -> InnerMnemonicResult<()> {
        // if there is an exported mnemonic, raise an error and don't start the daemon.
        // we do this to prevent users from accidentally leave their mnemonic on disk in plain text
        self.io.check_if_not_exported()?;

        // try to get mnemonic from kv-store
        match self.mnemonic_kv.exists(MNEMONIC_KEY).await? {
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
        let reservation = self.mnemonic_kv.reserve_key(MNEMONIC_KEY.to_owned()).await;
        match reservation {
            // if we can reserve, try put
            Ok(reservation) => match self.mnemonic_kv.put(reservation, entropy.to_owned()).await {
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
        Ok(self.io.entropy_to_file(new_entropy)?)
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
        let entropy = self.mnemonic_kv.get(MNEMONIC_KEY).await.map_err(|err| {
            error!("Did not find mnemonic in kv store {:?}", err);
            err
        })?;

        // write to file
        info!("Mnemonic found in kv store");
        Ok(self.io.entropy_to_file(entropy)?)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use testdir::testdir;

    use crate::{
        config::Config,
        gg20::{
            mnemonic::{
                file_io::FileIo,
                results::{file_io::FileIoError, mnemonic::InnerMnemonicError},
            },
            types::{KeySharesKv, MnemonicKv},
        },
        kv_manager::error::{InnerKvError, KvError},
    };

    use super::*;
    use tracing_test::traced_test;

    // create a service
    fn get_service(testdir: PathBuf) -> Gg20Service {
        // create test dirs for kvstores
        let shares_kv_path = testdir.join("shares");
        let shares_kv_path = shares_kv_path.to_str().unwrap();
        let mnemonic_kv_path = testdir.join("mnemonic");
        let mnemonic_kv_path = mnemonic_kv_path.to_str().unwrap();

        Gg20Service {
            shares_kv: KeySharesKv::with_db_name(shares_kv_path.to_owned()).unwrap(),
            mnemonic_kv: MnemonicKv::with_db_name(mnemonic_kv_path.to_owned()).unwrap(),
            io: FileIo::new(testdir),
            cfg: Config::default(),
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_create() {
        let testdir = testdir!();
        // create a service
        let gg20 = get_service(testdir);
        // first attempt should succeed
        assert!(gg20.handle_create().await.is_ok());
        // second attempt should fail
        assert!(matches!(
            gg20.handle_create().await,
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
        let gg20 = get_service(testdir.clone());
        // insert should succeed
        assert!(gg20.handle_insert(bip39_new_w24()).await.is_ok());
        // insert should fail
        assert!(matches!(
            gg20.handle_insert(bip39_new_w24()).await,
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
        let gg20 = get_service(testdir.clone());
        // handle existing should fail
        assert!(matches!(
            gg20.handle_existing().await,
            Err(InnerMnemonicError::KvErr(KvError::ExistsErr(
                InnerKvError::LogicalErr(_)
            )))
        ));
        // mnemonic should not be exported
        assert!(gg20.io.check_if_not_exported().is_ok());
        // create a new mnemonic
        assert!(gg20.handle_create().await.is_ok());
        // mnemonic should now be exported
        assert!(gg20.io.check_if_not_exported().is_err());
        // export should fail because create also exports
        assert!(matches!(
            gg20.handle_export().await,
            Err(InnerMnemonicError::FileIoErr(FileIoError::Exists(_)))
        ));
        // handle existing should fail because export file exists
        assert!(matches!(
            gg20.handle_existing().await,
            Err(InnerMnemonicError::FileIoErr(FileIoError::Exists(_)))
        ));
    }

    #[traced_test]
    #[tokio::test]
    async fn test_existing() {
        let testdir = testdir!();
        // create a service
        let gg20 = get_service(testdir.clone());
        // create a new mnemonic
        assert!(gg20.handle_create().await.is_ok());
        // create should fail because export file exists
        assert!(matches!(
            gg20.handle_existing().await,
            Err(InnerMnemonicError::FileIoErr(FileIoError::Exists(_)))
        ));
        // export should fail because export file exists
        assert!(matches!(
            gg20.handle_export().await,
            Err(InnerMnemonicError::FileIoErr(FileIoError::Exists(_)))
        ));
    }
}
