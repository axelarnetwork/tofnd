use super::mnemonic::{file_io::FileIo, Cmd};
use super::proto;
use super::types::{KeySharesKv, MnemonicKv, DEFAULT_MNEMONIC_KV_NAME, DEFAULT_SHARE_KV_NAME};
use std::path::PathBuf;
use tofn::protocol::gg20::{MessageDigest, SecretKeyShare};

#[cfg(feature = "malicious")]
use tofn::protocol::gg20::keygen::malicious::Behaviour as KeygenBehaviour;
#[cfg(feature = "malicious")]
use tofn::protocol::gg20::sign::malicious::BadSign;
#[cfg(feature = "malicious")]
use tofn::protocol::gg20::sign::malicious::Behaviour as SignBehaviour;
use tofn::protocol::gg20::sign::ParamsError as SignErr;
#[cfg(not(feature = "malicious"))]
use tofn::protocol::gg20::sign::Sign;

/// Gg20Service
#[derive(Clone)]
pub struct Gg20Service {
    pub(super) shares_kv: KeySharesKv,
    pub(super) mnemonic_kv: MnemonicKv,
    pub(super) io: FileIo,
    #[cfg(feature = "malicious")]
    pub(super) keygen_behaviour: KeygenBehaviour,
    #[cfg(feature = "malicious")]
    pub(super) sign_behaviour: SignBehaviour,
}

pub async fn new_service(
    mnemonic_cmd: Cmd,
    #[cfg(feature = "malicious")] keygen_behaviour: KeygenBehaviour,
    #[cfg(feature = "malicious")] sign_behaviour: SignBehaviour,
) -> impl proto::gg20_server::Gg20 {
    let mut gg20 = Gg20Service {
        shares_kv: KeySharesKv::new(DEFAULT_SHARE_KV_NAME),
        mnemonic_kv: MnemonicKv::new(DEFAULT_MNEMONIC_KV_NAME),
        io: FileIo::new(PathBuf::new()),
        #[cfg(feature = "malicious")]
        keygen_behaviour,
        #[cfg(feature = "malicious")]
        sign_behaviour,
    };

    gg20.handle_mnemonic(mnemonic_cmd)
        .await
        .expect("Unable to complete mnemonic command.");
    gg20
}

impl Gg20Service {
    // get regular sign
    #[cfg(not(feature = "malicious"))]
    pub fn get_sign(
        &self,
        my_secret_key_share: &SecretKeyShare,
        participant_indices: &[usize],
        msg_to_sign: &MessageDigest,
    ) -> Result<Sign, SignErr> {
        Sign::new(
            &my_secret_key_share.group,
            &my_secret_key_share.share,
            participant_indices,
            msg_to_sign,
        )
    }

    // get malicious sign
    #[cfg(feature = "malicious")]
    pub fn get_sign(
        &self,
        my_secret_key_share: &SecretKeyShare,
        participant_indices: &[usize],
        msg_to_sign: &MessageDigest,
    ) -> Result<BadSign, SignErr> {
        let behaviour = self.sign_behaviour.clone();

        BadSign::new(
            &my_secret_key_share.group,
            &my_secret_key_share.share,
            participant_indices,
            msg_to_sign,
            behaviour,
        )
    }
}

#[cfg(test)]
pub mod tests {
    use super::{FileIo, Gg20Service, KeySharesKv, MnemonicKv};
    use crate::proto;
    use std::path::PathBuf;

    #[cfg(feature = "malicious")]
    use tofn::protocol::gg20::keygen::malicious::Behaviour as KeygenBehaviour;
    #[cfg(feature = "malicious")]
    use tofn::protocol::gg20::sign::malicious::Behaviour as SignBehaviour;

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
        #[cfg(feature = "malicious")] keygen_behaviour: KeygenBehaviour,
        #[cfg(feature = "malicious")] sign_behaviour: SignBehaviour,
    ) -> impl proto::gg20_server::Gg20 {
        let (shares_db_name, mnemonic_db_name) = create_db_names(db_path);
        let mut path = PathBuf::new();
        path.push(db_path);

        let mut gg20 = Gg20Service {
            shares_kv: KeySharesKv::with_db_name(&shares_db_name),
            mnemonic_kv: MnemonicKv::with_db_name(&mnemonic_db_name),
            io: FileIo::new(path),
            #[cfg(feature = "malicious")]
            keygen_behaviour,
            #[cfg(feature = "malicious")]
            sign_behaviour,
        };

        gg20.handle_mnemonic(mnemonic_cmd)
            .await
            .expect("Unable to complete mnemonic command.");
        gg20
    }

    pub fn get_db_path(name: &str) -> std::path::PathBuf {
        KeySharesKv::get_db_path(name)
    }
}
