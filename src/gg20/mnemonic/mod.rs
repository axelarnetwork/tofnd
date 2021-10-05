//! This module handles mnemonic-related commands. A kv-store is used to insert and retrieve an [crate::gg20::Entropy].
//!
//! Currently, the API supports the following [Cmd] commands:
//!     [Cmd::Existing]: Starts the gRPC daemon existing mnemonic; Fails if mnemonic does not exist.
//!     [Cmd::Create]: Creates a new mnemonic, inserts it in the kv-store, exports it to a file and exits; Fails if a mnemonic exists.
//!     [Cmd::Import]: Prompts user to give a new mnemonic, inserts it in the kv-store and exits; Fails if a mnemonic exists or if the provided string is not a valid bip39 mnemonic.
//!     [Cmd::Export]: Writes the existing mnemonic to a file and exits; Succeeds when there is an existing mnemonic, fails otherwise.

mod bip39_bindings;
mod cmd_handler;
mod file_io;
mod results;

pub use cmd_handler::Cmd;
pub use file_io::FileIo;
