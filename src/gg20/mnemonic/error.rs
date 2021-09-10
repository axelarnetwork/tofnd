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
        #[error("Bip39 error: {0}")]
        Bip39Error(#[from] super::bip39::Bip39Error),
        #[error("Failed to convert to SecretRecoveryKey")]
        IntoSecretRecoveryKey(#[from] std::array::TryFromSliceError),
    }
    pub type InnerMnemonicResult<Success> = Result<Success, InnerMnemonicError>;

    #[derive(thiserror::Error, Debug)]
    pub enum MnemonicError {
        #[error("Command not found: {0}")]
        WrongCommand(String),
        #[error("Cannot create mnemonic: {0}")]
        CreateErr(InnerMnemonicError),
        #[error("Cannot import mnemonic: {0}")]
        ImportErr(InnerMnemonicError),
        #[error("Cannot export mnemonic: {0}")]
        ExportErr(InnerMnemonicError),
        #[error("Cannot update mnemonic: {0}")]
        UpdateErr(InnerMnemonicError),
    }
    pub type MnemonicResult<Success> = Result<Success, MnemonicError>;
    pub type SeedResult<Success> = Result<Success, InnerMnemonicError>;
}
