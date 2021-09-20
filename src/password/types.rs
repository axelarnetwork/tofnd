/// Types
use zeroize::Zeroize;

/// Safely store strings
#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct Password(pub String);
