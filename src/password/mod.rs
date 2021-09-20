mod constants;
mod password_methods;
mod result;

/// zeroize Entropy and Password
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
/// store mnemonic entropy safely
#[derive(Zeroize, Debug, Clone, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct Entropy(pub Vec<u8>);

/// store strings safely
#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct Password(pub String);

pub use password_methods::PasswordMethod;
