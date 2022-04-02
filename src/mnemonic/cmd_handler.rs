// TODO: consider moving cmd_handler in KvManager

use super::{
    bip39_bindings::{bip39_from_phrase, bip39_new_w24, bip39_seed},
    results::mnemonic::{
        InnerMnemonicError::*, InnerMnemonicResult, MnemonicError::*, MnemonicResult, SeedResult,
    },
};
use crate::{
    gg20::types::{Entropy, Password}, // TODO: move from gg20::types
    kv_manager::{
        error::{InnerKvError, KvError},
        KeyReservation, KvManager,
    },
};
use tofn::{
    gg20::keygen::SecretRecoveryKey,
    sdk::api::{deserialize, serialize},
};

use rpassword::read_password;
use std::convert::TryInto;
use tracing::{error, info};

// default key to store mnemonic
const MNEMONIC_KEY: &str = "mnemonic";

// key to store mnemonic count
const MNEMONIC_COUNT_KEY: &str = "mnemonic_count";

// A user may decide to protect their mnemonic with a passphrase.
// We pass an empty password since the mnemonic has sufficient entropy and will be backed up.
// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
const MNEMONIC_PASSWORD: &str = "";

#[derive(Clone, Debug)]
pub enum Cmd {
    Existing,
    Create,
    Import,
    Export,
    Rotate,
}

impl Cmd {
    pub fn from_string(cmd_str: &str) -> MnemonicResult<Self> {
        let cmd = match cmd_str {
            "existing" => Self::Existing,
            "create" => Self::Create,
            "import" => Self::Import,
            "export" => Self::Export,
            "rotate" => Self::Rotate,
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
            Cmd::Rotate => true,
        }
    }
}

/// implement mnemonic-specific functions for KvManager
impl KvManager {
    /// get mnemonic seed from kv-store
    pub async fn seed(&self) -> SeedResult<SecretRecoveryKey> {
        self.get_seed(MNEMONIC_KEY).await
    }

    /// Get mnemonic seed under key
    pub async fn get_seed(&self, key: &str) -> SeedResult<SecretRecoveryKey> {
        let mnemonic = self
            .kv()
            .get(key)
            .await?
            .try_into()
            .map_err(KvError::GetErr)?;

        Ok(
            bip39_seed(mnemonic, Password(MNEMONIC_PASSWORD.to_owned()))?
                .as_bytes()
                .try_into()?,
        )
    }

    pub async fn seed_key_iter(&self) -> InnerMnemonicResult<impl Iterator<Item = String>> {
        let count = self.seed_count().await?;

        // The old mnemonics are stored in descending order
        let range = (0..1).chain(count..0).map(|i| {
            match i {
                0 => String::from(MNEMONIC_KEY), // latest mnemonic is preserved in the original key
                _ => std::format!("{}_{}", MNEMONIC_KEY, i), // i is 0-indexed
            }
        });

        Ok(range)
    }

    /// async function that handles all mnemonic commands
    pub async fn handle_mnemonic(self, cmd: &Cmd) -> MnemonicResult<Self> {
        let _ = match cmd {
            Cmd::Existing => self.handle_existing().await.map_err(ExistingErr)?,
            Cmd::Create => self.handle_create().await.map_err(CreateErr)?,
            Cmd::Import => self.handle_import().await.map_err(ImportErr)?,
            Cmd::Export => self.handle_export().await.map_err(ExportErr)?,
            Cmd::Rotate => self.handle_rotate().await.map_err(RotateErr)?,
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

    /// Get the mnemonic count in the kv store.
    pub async fn seed_count(&self) -> InnerMnemonicResult<u32> {
        match self.kv().get(MNEMONIC_COUNT_KEY).await {
            Ok(encoded_count) => Ok(deserialize(&encoded_count)
                .ok_or(KvErr(KvError::GetErr(InnerKvError::DeserializationErr)))?),
            // if MNEMONIC_COUNT_KEY does not exist then mnemonic count is either 0 or 1
            Err(KvError::GetErr(_)) => Ok(match self.kv().exists(MNEMONIC_KEY).await? {
                true => 1,
                false => 0,
            }),
            Err(_) => {
                error!("");
                Err(PasswordErr(String::from("")))
            }
        }
    }

    /// Get the next mnemonic key id.
    async fn get_next_key(&self) -> InnerMnemonicResult<(String, u32)> {
        let count = self.seed_count().await?;

        let key = match count {
            0 => String::from(MNEMONIC_KEY), // latest mnemonic is preserved in the original key
            _ => std::format!("{}_{}", MNEMONIC_KEY, count), // count is 0-indexed
        };

        Ok((key, count))
    }

    /// inserts entropy to the kv-store
    /// takes ownership of entropy to delegate zeroization.
    async fn put_entropy(
        &self,
        reservation: KeyReservation,
        entropy: Entropy,
    ) -> InnerMnemonicResult<()> {
        match self
            .kv()
            .put(reservation, entropy.try_into().map_err(KvError::PutErr)?)
            .await
        {
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
        }
    }

    /// inserts entropy to the kv-store
    /// takes ownership of entropy to delegate zeroization.
    async fn handle_insert(&self, entropy: Entropy) -> InnerMnemonicResult<()> {
        let (key, count) = self.get_next_key().await?;

        info!(
            "Inserting mnemonic under key '{}' with total count '{}'",
            key, count
        );

        let reservation = self.kv().reserve_key(key).await.map_err(|err| {
            error!("Cannot reserve mnemonic key: {:?}", err);
            KvErr(err)
        })?;

        self.put_entropy(reservation, entropy).await?;

        self.kv().delete(MNEMONIC_COUNT_KEY).await.map_err(|err| {
            error!("could not delete mnemonic count: {:?}", err);
            KvErr(err)
        })?;

        let count_reservation = self
            .kv()
            .reserve_key(MNEMONIC_COUNT_KEY.to_owned())
            .await
            .map_err(|err| {
                error!("Cannot reserve mnemonic count key: {:?}", err);
                KvErr(err)
            })?;

        let encoded_count = serialize(&(count + 1))
            .map_err(|_| KvErr(KvError::PutErr(InnerKvError::SerializationErr)))?;

        self.kv()
            .put(count_reservation, encoded_count)
            .await
            .map_err(|err| {
                error!("Could not update the mnemonic count in kv store: {:?}", err);
                KvErr(err)
            })
    }

    /// Creates a new entropy, inserts the entropy in the kv-store and exports it to a file
    /// If a mnemonic already exists in the kv store or an exported file already exists in
    /// the default path, an error is produced
    async fn handle_create(&self) -> InnerMnemonicResult<()> {
        info!("Creating mnemonic");

        // create a new entropy
        let new_entropy = bip39_new_w24();
        if self.kv().exists(MNEMONIC_KEY).await? {
            error!("Mnemonic was already created");
            return Err(KvErr(KvError::ReserveErr(InnerKvError::LogicalErr(
                "mnemonic was already present".to_owned(),
            ))));
        }

        self.handle_insert(new_entropy.clone()).await?;
        Ok(self.io().entropy_to_file(new_entropy)?)
    }

    /// Inserts a new mnemonic to the kv-store.
    /// If a mnemonic already exists in the kv store, a new entry is created
    /// storing it as a rotated out mnemonic.
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
            .try_into()
            .map_err(KvError::GetErr)?;

        // write to file
        info!("Mnemonic found in kv store");
        Ok(self.io().entropy_to_file(entropy)?)
    }

    /// Rotates out existing mnemonic for new one in the kv-store and exports it to a file
    /// If an exported file already exists in the default path, an error is produced
    async fn handle_rotate(&self) -> InnerMnemonicResult<()> {
        info!("Rotating mnemonic");
        // create a new entropy
        let new_entropy = bip39_new_w24();

        self.io().entropy_to_file(new_entropy.clone())?;

        let current_entropy: Entropy = self
            .kv()
            .get(MNEMONIC_KEY)
            .await?
            .try_into()
            .map_err(KvError::GetErr)?;

        self.handle_insert(current_entropy.clone()).await?;

        info!("reserving mnemonic");

        self.kv().delete(MNEMONIC_KEY).await.map_err(|err| {
            error!("could not delete mnemonic being rotated out: {:?}", err);
            KvErr(err)
        })?;

        let reservation = self
            .kv()
            .reserve_key(MNEMONIC_KEY.to_owned())
            .await
            .map_err(|err| {
                error!("Cannot reserve mnemonic key: {:?}", err);
                KvErr(err)
            })?;

        self.put_entropy(reservation, new_entropy).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use testdir::testdir;

    use crate::{
        encrypted_sled::get_test_password,
        kv_manager::{
            error::{InnerKvError, KvError},
            KvManager,
        },
        mnemonic::results::{file_io::FileIoError, mnemonic::InnerMnemonicError},
    };

    use super::*;
    use tracing_test::traced_test;

    // create a service
    fn get_kv_manager(testdir: PathBuf) -> KvManager {
        // create test dirs
        KvManager::new(testdir, get_test_password()).unwrap()
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
        // insert should succeed again
        assert!(kv.handle_insert(bip39_new_w24()).await.is_ok());
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
