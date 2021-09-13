//! This mod includes the service implementation derived from

use super::mnemonic::{file_io::FileIo, Cmd};
use super::proto;
use super::types::{KeySharesKv, MnemonicKv, DEFAULT_MNEMONIC_KV_NAME, DEFAULT_SHARE_KV_NAME};
use crate::DEFAULT_PATH_ROOT;
use std::path::PathBuf;

// error handling
use crate::TofndResult;
use anyhow::anyhow;

#[cfg(feature = "malicious")]
pub mod malicious;

/// Gg20Service
#[derive(Clone)]
pub struct Gg20Service {
    pub(super) shares_kv: KeySharesKv,
    pub(super) mnemonic_kv: MnemonicKv,
    pub(super) io: FileIo,
    pub(super) safe_keygen: bool,
    #[cfg(feature = "malicious")]
    pub(super) behaviours: malicious::Behaviours,
}

/// create a new Gg20 gRPC server
pub async fn new_service(
    safe_keygen: bool,
    mnemonic_cmd: Cmd,
    #[cfg(feature = "malicious")] behaviours: malicious::Behaviours,
) -> TofndResult<impl proto::gg20_server::Gg20> {
    // TODO: do we need to encrypt share kv store?
    // 1. tofn already encrypts the shares. THere is no point at encrypting them twice.
    // 2. we should keep tofn's encryption
    // 3. we should be able to optionally enrypt kv stores. Not possible with encrypted_sled
    //    1. should we have both kind of stores? sled + enrypted sled? Doesn't seem like a good idea
    let shares_kv = KeySharesKv::new(DEFAULT_SHARE_KV_NAME).map_err(|err| {
        anyhow!(
            "Shares kvstore is corrupted. Please remove it and recover your shares. Error: {}",
            err
        )
    })?;
    let mnemonic_kv = MnemonicKv::new(DEFAULT_MNEMONIC_KV_NAME).map_err(|err| {
        anyhow!(
            "Your mnemonic kv store is corrupted. Please remove it and import your mnemonic again. Error: {}", err
        )
    })?;
    let io = FileIo::new(PathBuf::from(DEFAULT_PATH_ROOT));

    let gg20 = Gg20Service {
        shares_kv,
        mnemonic_kv,
        io,
        safe_keygen,
        #[cfg(feature = "malicious")]
        behaviours,
    };

    gg20.handle_mnemonic(mnemonic_cmd).await?;
    Ok(gg20)
}

#[cfg(test)]
pub mod tests {
    use super::{FileIo, Gg20Service, KeySharesKv, MnemonicKv};
    use crate::{proto, TofndResult};
    use std::path::PathBuf;

    #[cfg(feature = "malicious")]
    use super::malicious::Behaviours;

    // append a subfolder name to db path.
    // this will allows the creaton of two distict kv stores under 'db_path'
    fn create_db_names(db_path: &str) -> (String, String) {
        (
            db_path.to_owned() + "/shares",
            db_path.to_owned() + "/mnemonic",
        )
    }

    pub async fn with_db_name(
        db_path: &str,
        mnemonic_cmd: crate::gg20::mnemonic::Cmd,
        #[cfg(feature = "malicious")] behaviours: Behaviours,
    ) -> TofndResult<impl proto::gg20_server::Gg20> {
        let (shares_db_name, mnemonic_db_name) = create_db_names(db_path);
        let mut path = PathBuf::new();
        path.push(db_path);

        let gg20 = Gg20Service {
            shares_kv: KeySharesKv::with_db_name(shares_db_name.to_owned()).unwrap(),
            mnemonic_kv: MnemonicKv::with_db_name(mnemonic_db_name.to_owned()).unwrap(),
            io: FileIo::new(path),
            safe_keygen: false,
            #[cfg(feature = "malicious")]
            behaviours,
        };

        gg20.handle_mnemonic(mnemonic_cmd).await?;
        Ok(gg20)
    }

    pub fn get_db_path(name: &str) -> std::path::PathBuf {
        KeySharesKv::get_db_path(name)
    }
}
