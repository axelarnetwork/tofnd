//! Handles the keygen streaming gRPC for one party.
//!
//! Protocol is executed in [handler] module:
//!   1. [init] First, the initialization message [crate::proto::KeygenInit] is received from the client.
//!      This message describes the execution of the protocol (i.e. number of participants, share counts, etc).
//!   2. [execute] Then, the party starts to generate messages by invoking calls of the [tofn] library until the protocol is completed.
//!      These messages are send to the client using the gRPC stream, and are broadcasted to all participating parties by the client.
//!   3. [result] Finally, the party receives the result of the protocol, which is also send to the client through the gRPC stream. Afterwards, the stream is closed.
//!
//! Shares:
//!   Each party might have multiple shares. A single thread is created for each share.
//!   We keep this information agnostic to the client, and we use the [crate::grpc::broadcast] layer to distribute the messages to each share.
//!   The result of the protocol is common across all shares, and unique for each party. We make use of [result] layer to aggregate and process the result.
//!
//! All relevant helper structs and types are defined in [types]

mod execute;
mod handler;
mod init;
mod result;
mod types;

pub use types::common::KeygenInitSanitized;
