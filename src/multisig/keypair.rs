use crate::{proto::Algorithm, TofndResult};
use anyhow::anyhow;
use tofn::{
    ecdsa, ed25519,
    sdk::api::{MessageDigest, SecretRecoveryKey},
};

pub enum KeyPair {
    Ecdsa(ecdsa::KeyPair),
    Ed25519(ed25519::KeyPair),
}

impl KeyPair {
    /// Create a new `KeyPair` from the provided `SecretRecoveryKey` and `session_nonce` deterministically, for the given `algorithm`.
    pub fn new(
        secret_recovery_key: &SecretRecoveryKey,
        session_nonce: &[u8],
        algorithm: Algorithm,
    ) -> TofndResult<Self> {
        Ok(match algorithm {
            Algorithm::Ecdsa => {
                let key_pair = ecdsa::keygen(secret_recovery_key, session_nonce)
                    .map_err(|_| anyhow!("Cannot generate keypair"))?;

                Self::Ecdsa(key_pair)
            }

            Algorithm::Ed25519 => {
                let key_pair = ed25519::keygen(secret_recovery_key, session_nonce)
                    .map_err(|_| anyhow!("Cannot generate keypair"))?;

                Self::Ed25519(key_pair)
            }
        })
    }

    pub fn encoded_verifying_key(&self) -> Vec<u8> {
        match self {
            Self::Ecdsa(key_pair) => key_pair.encoded_verifying_key().into(),
            Self::Ed25519(key_pair) => key_pair.encoded_verifying_key().into(),
        }
    }

    pub fn sign(&self, msg_to_sign: &MessageDigest) -> TofndResult<Vec<u8>> {
        match self {
            Self::Ecdsa(key_pair) => ecdsa::sign(key_pair.signing_key(), msg_to_sign),
            Self::Ed25519(key_pair) => ed25519::sign(key_pair, msg_to_sign),
        }
        .map_err(|_| anyhow!("signing failed"))
    }
}
