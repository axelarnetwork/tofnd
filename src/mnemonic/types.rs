//! Mnemonic types

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Mnemonic type needs to be known globaly to create/access the mnemonic kv store
#[derive(Zeroize, Debug, Clone, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct Entropy(pub Vec<u8>);

#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct Password(pub String);
