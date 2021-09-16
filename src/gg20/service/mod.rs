//! This mod includes the service implementation derived from

use super::mnemonic::file_io::FileIo;
use super::proto;
use super::types::{KeySharesKv, MnemonicKv, DEFAULT_MNEMONIC_KV_NAME, DEFAULT_SHARE_KV_NAME};
use crate::config::Config;
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
    pub(super) cfg: Config,
}

/// create a new Gg20 gRPC server
pub async fn new_service(cfg: Config) -> TofndResult<impl proto::gg20_server::Gg20> {
    let shares_kv =
        KeySharesKv::new(cfg.tofnd_path.as_str(), DEFAULT_SHARE_KV_NAME).map_err(|err| {
            anyhow!(
                "Shares kvstore is corrupted. Please remove it and recover your shares. Error: {}",
                err
            )
        })?;
    let mnemonic_kv = MnemonicKv::new(cfg.tofnd_path.as_str(), DEFAULT_MNEMONIC_KV_NAME).map_err(|err| {
        anyhow!(
            "Your mnemonic kv store is corrupted. Please remove it and import your mnemonic again. Error: {}", err
        )
    })?;
    let io = FileIo::new(PathBuf::from(&cfg.tofnd_path));

    let gg20 = Gg20Service {
        shares_kv,
        mnemonic_kv,
        io,
        cfg,
    };

    gg20.handle_mnemonic().await?;
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
