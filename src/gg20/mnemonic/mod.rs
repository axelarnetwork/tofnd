//! This module handles mnemonic-related commands. A kv-store is used to insert and retrieve an [crate::gg20::Entropy].
//!
//! Currently, the API supports the following [Cmd] commands:
//!     [Cmd::Existing]: Uses the existing mnemonic; Fails if mnemonic does not exist.
//!     [Cmd::Create]: Creates a new mnemonic and inserts it in the kv-store; Fails if a mnemonic exists.
//!     [Cmd::Import]: Prompts user to give a new mnemonic and inserts it in the kv-store; Fails if a mnemonic exists or if the provided string is not a valid bip39 mnemonic.
//!     [Cmd::Export]: Writes the existing mnemonic to a file; Succeeds when there is an existing mnemonic, fails otherwise.

mod bip39_bindings;
mod cmd_handler;
mod error;
mod file_io;

pub use cmd_handler::Cmd;
pub use file_io::FileIo;
