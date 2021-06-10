use super::{
    proto::{
        mnemonic_request::Cmd, mnemonic_response::Response, MnemonicRequest, MnemonicResponse,
    },
    Gg20Service, TofndError,
};
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tonic::Status;
use tracing::{error, info};

// default key to store mnemonic
const MNEMONIC_KEY: &str = "mnemonic";

// Mnemonic type needs to be known globaly to create/access the kv store
// TODO: This might be better to be defined in tofn
pub type Mnemonic = Vec<u8>;

// Create separate type for response data bytes to avoid conflicts with other byte arrays
#[derive(Clone)]
struct ResponseData(Vec<u8>);
impl ResponseData {
    // return empty ResponseData
    fn empty() -> ResponseData {
        ResponseData(Vec::<u8>::with_capacity(0))
    }
    // convert ResponseData into raw bytes. Used to create eventual MnemonicResponse
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl MnemonicResponse {
    fn new(response: Response, response_data: ResponseData) -> MnemonicResponse {
        MnemonicResponse {
            // the prost way to convert enums back to i32
            // https://github.com/danburkert/prost/blob/master/README.md#enumerations
            response: response as i32,
            data: response_data.to_bytes(),
        }
    }
    // import does not send response_data back
    fn import(response: Response) -> MnemonicResponse {
        Self::new(response, ResponseData::empty())
    }
}

impl Gg20Service {
    pub async fn handle_mnemonic(
        &mut self,
        mut request_stream: tonic::Streaming<MnemonicRequest>,
        response_stream: mpsc::UnboundedSender<Result<MnemonicResponse, Status>>,
    ) -> Result<(), TofndError> {
        info!("Importing mnemonic");

        // read mnemonic message
        let msg = request_stream
            .next()
            .await
            .ok_or("keygen: stream closed by client without sending a message")??;

        // prost way to get an enum type from i32
        // https://github.com/danburkert/prost/blob/master/README.md#enumerations
        let cmd = Cmd::from_i32(msg.cmd)
            .ok_or(format!("unable to convert {} to a Cmd type.", msg.cmd))?;

        let response = match cmd {
            // proto::mnemonic_request::Cmd::Unknown => todo!(),
            Cmd::Import => self.handle_import(msg.data).await,
            // Cmd::Update => self.handle_update(msg.data).await,
            // proto::mnemonic_request::Cmd::Export => handle_export(),
            // proto::mnemonic_request::Cmd::Delete => handle_delete(),
            _ => todo!(),
        };

        let _ = response_stream.send(Ok(response));
        Ok(())
    }

    async fn handle_import(&mut self, data: Mnemonic) -> MnemonicResponse {
        info!("Importing mnemonic");

        // try to reserve the mnemonic value
        let reservation = self.mnemonic_kv.reserve_key(MNEMONIC_KEY.to_owned()).await;

        match reservation {
            // if we can reserve, try put
            // TODO: if put fails, do we have to unreserve the key?
            Ok(reservation) => match self.mnemonic_kv.put(reservation, data).await {
                // if put is ok return success
                Ok(()) => {
                    info!("Mnemonic successfully added in kv store");
                    MnemonicResponse::import(Response::Success)
                }
                // else return failure
                Err(_) => {
                    error!("Cannot put mnemonic in kv store");
                    MnemonicResponse::import(Response::Failure)
                }
            },
            // if we cannot reserve, return failure
            Err(_) => {
                error!("Cannot reserve mnemonic");
                MnemonicResponse::import(Response::Failure)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gg20::{KeySharesKv, MnemonicKv};
    use crate::proto::mnemonic_response::Response;
    use testdir::testdir;
    use tracing_test::traced_test; // logs for tests

    #[cfg(feature = "malicious")]
    use tofn::protocol::gg20::keygen::malicious::Behaviour as KeygenBehaviour;
    #[cfg(feature = "malicious")]
    use tofn::protocol::gg20::sign::malicious::Behaviour as SignBehaviour;

    #[traced_test]
    #[tokio::test]
    async fn test_import() {
        // create test dirs for kvstores
        let testdir = testdir!();
        let shares_kv_path = testdir.join("shares");
        let shares_kv_path = shares_kv_path.to_str().unwrap();
        let mnemonic_kv_path = testdir.join("mnemonic");
        let mnemonic_kv_path = mnemonic_kv_path.to_str().unwrap();

        // create a service
        let mut gg20 = Gg20Service {
            kv: KeySharesKv::with_db_name(shares_kv_path),
            mnemonic_kv: MnemonicKv::with_db_name(mnemonic_kv_path),
            // must enable test for all features. if we use
            // #[cfg(not(feature = "malicious"))] tests won't be executed '--all-features' flag is on. yikes
            #[cfg(feature = "malicious")]
            keygen_behaviour: KeygenBehaviour::Honest,
            #[cfg(feature = "malicious")]
            sign_behaviour: SignBehaviour::Honest,
        };

        // add some data to the kv store
        let mnemonic: Mnemonic = vec![42; 32];
        // import does not send data back
        let response_data = ResponseData::empty();

        // first attempt should succeed
        assert_eq!(
            gg20.handle_import(mnemonic.clone()).await,
            MnemonicResponse::new(Response::Success, response_data.clone())
        );

        // second attempt should succeed
        assert_eq!(
            gg20.handle_import(mnemonic).await,
            MnemonicResponse::new(Response::Failure, response_data)
        );
    }
}
