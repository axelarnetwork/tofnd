use super::constants::*;

/// prompt user for a password and hash it. Password needs to be at least
/// [MINIMUM_LENGTH] characters. The user has [MAX_TRIES] to provide a valid
/// password. The password is hashed using [HashAlgo].
fn prompt(msg: &str) -> EncryptionResult<String> {}
