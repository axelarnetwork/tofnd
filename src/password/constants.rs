//! Constants for [crate::password]

/// prevent rainbow attacks. Use sha3 of "tofnd" as salt
pub(super) const DEFAULT_SALT: &[u8; 128] = b"f0e740929cd80bdf1a672567874d997a36463b85aa53ae37ab0f7840c657f05de7c4e71a28f53e6a8d6e78a8ba654424627ff0218bb87ba33b66c9d4e6d15fbc";
/// default entropy used in [super::PasswordMethod::DefaultPassword] option. BEWARE!! It is **NOT** safe to use this entropy.
pub(super) const UNSAFE_ENTROPY: &[u8; 32] = b"12345678901234567890123456789012";
