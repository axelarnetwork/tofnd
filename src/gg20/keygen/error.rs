use thiserror::Error;

pub(super) mod init {
    use super::*;
    #[derive(Error, Debug)]
    pub enum Error {
        #[error("stream closed by client")]
        StreamClosedByClient,
        #[error("stream closed by server: {0}")]
        StreamClosedByServer(#[from] tonic::Status),
        #[error("received `None` message from client")]
        NoneMessage,
        #[error("failed to sanitize KeygenInit message: {0}")]
        Sanitize(String),
        #[error("expected keygen init message")]
        WrongMessageType,
        #[error("key reservation error: {0}")]
        Reserve(String),
    }
    pub type InitResult<Success> = Result<Success, Error>;
}
