use crate::{proto::Algorithm, TofndResult};
use anyhow::anyhow;
use tofn::{
    ecdsa, ed25519,
    multisig::{keygen::SecretRecoveryKey, sign::MessageDigest},
};

pub enum KeyPair {
    Ecdsa(ecdsa::KeyPair),
    Ed25519(ed25519::KeyPair),
}

impl KeyPair {
    pub fn generate(
        secret_recovery_key: &SecretRecoveryKey,
        session_nonce: &[u8],
        algorithm: Algorithm,
    ) -> TofndResult<Self> {
        Ok(match algorithm {
            Algorithm::Ecdsa => {
                let key_pair = ecdsa::keygen(&secret_recovery_key, session_nonce)
                    .map_err(|_| anyhow!("Cannot generate keypair"))?;

                Self::Ecdsa(key_pair)
            }

            Algorithm::Ed25519 => {
                let key_pair = ed25519::keygen(&secret_recovery_key, session_nonce)
                    .map_err(|_| anyhow!("Cannot generate keypair"))?;

                Self::Ed25519(key_pair)
            }
        })
    }

    pub fn encoded_verifying_key(&self) -> Vec<u8> {
        match self {
            Self::Ecdsa(key_pair) => key_pair.encoded_verifying_key().to_vec(),
            Self::Ed25519(key_pair) => key_pair.encoded_verifying_key().to_vec(),
        }
    }

    pub fn sign(&self, msg_to_sign: &MessageDigest) -> TofndResult<Vec<u8>> {
        match self {
            Self::Ecdsa(key_pair) => ecdsa::sign(key_pair.signing_key(), msg_to_sign)
                .map_err(|_| anyhow!("signing failed")),
            Self::Ed25519(key_pair) => {
                ed25519::sign(key_pair, msg_to_sign).map_err(|_| anyhow!("signing failed"))
            }
        }
    }
}
