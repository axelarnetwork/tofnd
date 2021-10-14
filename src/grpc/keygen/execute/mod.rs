//! This module creates and executes the keygen protocol
//! On success it returns [self::base::KeygenOutput]. A successful [Keygen] can produce either an Ok(SecretKeyShare) of an Err(Vec<Vec<Crime>>).
//! On failure it returns [anyhow::anyhow!] error if [Keygen] struct cannot be instantiated.

mod base;
mod gg20;
mod multisig;

pub(super) use base::KeygenOutput;
