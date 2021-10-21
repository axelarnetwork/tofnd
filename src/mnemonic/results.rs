//! Custom error types for [mnemonic].

/// Note: While tofnd generally uses the [anyhow] crate for error handling, we
/// use the [thiserror] crate here for two reasons:
/// 1. Mnemonic errors can be potentially consumed by the caller of tofnd, so an
/// analytical display of errors might be helpful in the future
/// 2. This can be used as an example on how analytical error handling can be
/// incorporated in other modules
/// For more info, see discussion in https://github.com/axelarnetwork/tofnd/issues/28

pub(super) mod bip39 {
    #[derive(thiserror::Error, Debug)]
    pub enum Bip39Error {
        #[error("invalid entropy")]
        FromEntropy,
        #[error("invalid phrase")]
        FromPhrase,
    }
    pub type Bip39Result<Success> = Result<Success, Bip39Error>;
}

pub(super) mod file_io {
    #[derive(thiserror::Error, Debug)]
    pub enum FileIoError {
        #[error("Bip39 error: {0}")]
        Bip39(#[from] super::bip39::Bip39Error),
        #[error("File IO error {0}")]
        FileIo(#[from] std::io::Error),
        #[error(
            "File {0} already exists. Remove file to use `-m existing` or `-m export` commands."
        )]
        Exists(std::path::PathBuf),
    }
    pub type FileIoResult<Success> = Result<Success, FileIoError>;
}

pub(super) mod mnemonic {
    #[derive(thiserror::Error, Debug)]
    pub enum InnerMnemonicError {
        #[error("File IO error: {0}")]
        FileIoErr(#[from] super::file_io::FileIoError),
        #[error("KvStore error: {0}")]
        KvErr(#[from] crate::kv_manager::error::KvError),
        #[error("Invalid mnemonic. See https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki. Bip39 error: {0}")]
        Bip39Error(#[from] super::bip39::Bip39Error),
        #[error("Failed to convert to SecretRecoveryKey")]
        IntoSecretRecoveryKey(#[from] std::array::TryFromSliceError),
        #[error("Password error: {0}")]
        PasswordErr(String),
    }
    pub type InnerMnemonicResult<Success> = Result<Success, InnerMnemonicError>;

    #[derive(thiserror::Error, Debug)]
    pub enum MnemonicError {
        #[error("Command not found: {0}")]
        WrongCommand(String),
        #[error("Cannot not use existing mnemonic: {0}")]
        ExistingErr(InnerMnemonicError),
        #[error("Cannot create mnemonic: {0}")]
        CreateErr(InnerMnemonicError),
        #[error("Cannot import mnemonic: {0}")]
        ImportErr(InnerMnemonicError),
        #[error("Cannot export mnemonic: {0}")]
        ExportErr(InnerMnemonicError),
    }
    pub type MnemonicResult<Success> = Result<Success, MnemonicError>;
    pub type SeedResult<Success> = Result<Success, InnerMnemonicError>;
}
