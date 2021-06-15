//! This module handles mnemonic-related commands. A kv-store is used to import, edit and export an [Entropy].
//!
//! Currently, the API supports the following [Cmd] commands:
//!     [Cmd::Noop]: does nothing; Always succeeds. useful when the container restarts with the same mnemonic.
//!     [Cmd::Create]: creates a new mnemonic; Succeeds when there is no other mnemonic already imported, fails otherwise.
//!     [Cmd::Import]: adds a new mnemonic from "import" file; Succeeds when there is no other mnemonic already imported, fails otherwise.
//!     [Cmd::Export]: writes the existing mnemonic to a file; Succeeds when there is an existing mnemonic, fails otherwise.
//!     [Cmd::Update]: updates existing mnemonic from file "import"; Succeeds when there is an existing mnemonic, fails otherwise.
//!     In [Cmd::Create], [Cmd::Export] commands, a new "export" file is created that contains the current phrase.
//!     In [Cmd::Update] command, a new "export" file is created that contains the replaced pasphrase.

pub mod bip39_bindings;
use bip39_bindings::{bip39_new_w12, bip39_seed, bip39_validate};
use std::convert::TryInto;

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

// implement convenient wrappers for responses
impl MnemonicResponse {
    // basic constructor
    fn new(response: Response, response_data: ResponseData) -> MnemonicResponse {
        MnemonicResponse {
            // the prost way to convert enums back to i32
            // https://github.com/danburkert/prost/blob/master/README.md#enumerations
            response: response as i32,
            data: response_data.to_bytes(),
        }
    }
    fn import_success() -> MnemonicResponse {
        Self::new(Response::Success, ResponseData::empty())
    }
    fn export_success(response_data: ResponseData) -> MnemonicResponse {
        Self::new(Response::Success, response_data)
    }
    fn delete_success() -> MnemonicResponse {
        Self::new(Response::Success, ResponseData::empty())
    }
    fn fail() -> MnemonicResponse {
        Self::new(Response::Failure, ResponseData::empty())
    }
}

// implement mnemonic-specific functions for Gg20Service
impl Gg20Service {
    // async function that handles all mnemonic commands
    pub async fn handle_mnemonic(
        &mut self,
        mut request_stream: tonic::Streaming<MnemonicRequest>,
        response_stream: mpsc::UnboundedSender<Result<MnemonicResponse, Status>>,
    ) -> Result<(), TofndError> {
        // read mnemonic message from stream
        let msg = request_stream
            .next()
            .await
            .ok_or("keygen: stream closed by client without sending a message")??;

        // prost way to get an enum type from i32
        // https://github.com/danburkert/prost/blob/master/README.md#enumerations
        let cmd = Cmd::from_i32(msg.cmd)
            .ok_or(format!("unable to convert {} to a Cmd type.", msg.cmd))?;

        // check if message bytes create a valid bip39 mnemonic
        bip39_validate(&msg.data)?;

        // retireve response
        let response = match cmd {
            // TODO: do we need Unknown?
            Cmd::Unknown => todo!(),
            Cmd::Create => self.handle_create().await,
            Cmd::Import => self.handle_import(msg.data).await,
            Cmd::Update => self.handle_update(msg.data).await,
            Cmd::Export => self.handle_export().await,
            Cmd::Delete => self.handle_delete().await,
        };

        // send response
        let _ = response_stream.send(Ok(response));
        Ok(())
    }

    // adds a new mnemonic; returns a MnemonicResponse with Response::Success when
    // there is no other mnemonic already imported, or with Response::Failure otherwise.
    // The 'data' field of MnemonicResponse is empty. Also caches mneminic seed into Self
    async fn handle_import(&mut self, data: Mnemonic) -> MnemonicResponse {
        info!("Importing mnemonic");

        // try to reserve the mnemonic value
        let reservation = self.mnemonic_kv.reserve_key(MNEMONIC_KEY.to_owned()).await;

        match reservation {
            // if we can reserve, try put
            Ok(reservation) => match self.mnemonic_kv.put(reservation, data).await {
                // if put is ok return success
                Ok(()) => {
                    info!("Mnemonic successfully added in kv store");
                    MnemonicResponse::import_success()
                }
                // else return failure
                Err(err) => {
                    error!("Cannot put mnemonic in kv store: {:?}", err);
                    MnemonicResponse::fail()
                }
            },
            // if we cannot reserve, return failure
            Err(err) => {
                error!("Cannot reserve mnemonic: {:?}", err);
                MnemonicResponse::fail()
            }
        }
    }

    // create a new mnemonic; returns a MnemonicResponse with Response::Success when
    // there is no other mnemonic already imported, or with Response::Failure otherwise.
    // The 'data' field of MnemonicResponse contain the new mnemonic.
    // Caches mneminic seed into Self.
    async fn handle_create(&mut self) -> MnemonicResponse {
        info!("Creating mnemonic");
        let mnemonic = bip39_new_w12();
        self.handle_import(mnemonic).await
    }

    // updates mnemonic; returns a MnemonicResponse with Response::Success a mnemonic
    // already exists and is successfully updated, or with Response::Failure otherwise.
    // The 'data' field of MnemonicResponse is empty
    async fn handle_update(&mut self, mnemonic: Mnemonic) -> MnemonicResponse {
        info!("Updating mnemonic");

        // try to delete the old mnemonic
        let removed = self.mnemonic_kv.remove(MNEMONIC_KEY).await;

        match removed {
            // if succeed, try to import and return whatever import returns
            Ok(_) => self.handle_import(mnemonic).await,
            // if failed, return failure
            Err(err) => {
                error!(
                    "Cannot find existing mnemonic {:?} with error {:?}",
                    mnemonic, err
                );
                MnemonicResponse::fail()
            }
        }
    }

    // gets the existing mnemonic; returns a MnemonicResponse with Response::Success when
    // a mnemonic already exists, or with Response::Failure otherwise.
    // The 'data' field of MnemonicResponse contains the exported mnemonic
    async fn handle_export(&mut self) -> MnemonicResponse {
        info!("Exporting mnemonic");

        // try to get mnemonic from kv-store
        match self.mnemonic_kv.get(MNEMONIC_KEY).await {
            // if get is ok return success
            Ok(mnemonic) => {
                info!("Mnemonic found in kv store");
                MnemonicResponse::export_success(ResponseData(mnemonic))
            }
            // else return failure
            Err(err) => {
                error!("Did not find mnemonic in kv store {:?}", err);
                MnemonicResponse::fail()
            }
        }
    }

    // deletes the existing mnemonic from the kv-store;
    // returns a MnemonicResponse with Response::Success when a mnemonic already exists,
    // or with Response::Failure otherwise.
    // The 'data' field of MnemonicResponse is empty
    async fn handle_delete(&mut self) -> MnemonicResponse {
        info!("Deleting mnemonic");

        // try to delete mnemonic from kv-store
        match self.mnemonic_kv.remove(MNEMONIC_KEY).await {
            // if deletion is ok return success
            Ok(mnemonic) => {
                info!("Mnemonic {:?} deleted from kv store", mnemonic);
                MnemonicResponse::delete_success()
            }
            // else return failure
            Err(err) => {
                error!("Did not find mnemonic in kv store {:?}", err);
                MnemonicResponse::fail()
            }
        }
    }
}

use tofn::protocol::gg20::keygen::PrfSecretKey;
// ease tofn API
impl Gg20Service {
    pub async fn seed(&self) -> Result<PrfSecretKey, TofndError> {
        let mnemonic = self.mnemonic_kv.get(MNEMONIC_KEY).await?;
        // A user may decide to protect their mnemonic with a passphrase. If not, pass an empty password
        // https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
        Ok(bip39_seed(&mnemonic, "")?.as_bytes().try_into()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gg20::{KeySharesKv, MnemonicKv};
    use testdir::testdir;
    use tracing_test::traced_test; // logs for tests

    #[cfg(feature = "malicious")]
    use tofn::protocol::gg20::keygen::malicious::Behaviour as KeygenBehaviour;
    #[cfg(feature = "malicious")]
    use tofn::protocol::gg20::sign::malicious::Behaviour as SignBehaviour;

    // create a service
    fn get_service() -> Gg20Service {
        // create test dirs for kvstores
        let testdir = testdir!();
        let shares_kv_path = testdir.join("shares");
        let shares_kv_path = shares_kv_path.to_str().unwrap();
        let mnemonic_kv_path = testdir.join("mnemonic");
        let mnemonic_kv_path = mnemonic_kv_path.to_str().unwrap();

        Gg20Service {
            shares_kv: KeySharesKv::with_db_name(shares_kv_path),
            mnemonic_kv: MnemonicKv::with_db_name(mnemonic_kv_path),
            // must enable test for all features. if we use
            // #[cfg(not(feature = "malicious"))] tests won't be executed '--all-features' flag is on. yikes
            #[cfg(feature = "malicious")]
            keygen_behaviour: KeygenBehaviour::Honest,
            #[cfg(feature = "malicious")]
            sign_behaviour: SignBehaviour::Honest,
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_import() {
        // create a service
        let mut gg20 = get_service();

        // add some data to the kv store
        let mnemonic: Mnemonic = vec![42; 32];

        // first attempt should succeed
        assert_eq!(
            gg20.handle_import(mnemonic.clone()).await,
            MnemonicResponse::import_success()
        );
        // second attempt should succeed
        assert_eq!(gg20.handle_import(mnemonic).await, MnemonicResponse::fail());
    }

    #[traced_test]
    #[tokio::test]
    async fn test_create() {
        // create a service
        let mut gg20 = get_service();

        // first attempt should succeed
        assert_eq!(
            gg20.handle_create().await,
            MnemonicResponse::import_success()
        );
        // second attempt should succeed
        assert_eq!(gg20.handle_create().await, MnemonicResponse::fail());
    }

    #[traced_test]
    #[tokio::test]
    async fn test_update() {
        // create a service
        let mut gg20 = get_service();
        // add some data to the kv store
        let mnemonic: Mnemonic = vec![42; 32];

        // first attempt to update should fail
        assert_eq!(
            gg20.handle_update(mnemonic.clone()).await,
            MnemonicResponse::fail()
        );
        // import should succeed
        assert_eq!(
            gg20.handle_import(mnemonic.clone()).await,
            MnemonicResponse::import_success()
        );
        // second attempt to update should succeed
        assert_eq!(
            gg20.handle_update(mnemonic.clone()).await,
            MnemonicResponse::import_success()
        );
        // export should succeed
        assert_eq!(
            gg20.handle_export().await,
            MnemonicResponse::export_success(ResponseData(mnemonic))
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn test_export() {
        // create a service
        let mut gg20 = get_service();
        // add some data to the kv store
        let mnemonic: Mnemonic = vec![42; 32];

        // export should fail
        assert_eq!(gg20.handle_export().await, MnemonicResponse::fail());
        // import should succeed
        assert_eq!(
            gg20.handle_import(mnemonic.clone()).await,
            MnemonicResponse::import_success()
        );
        // export should now succeed
        assert_eq!(
            gg20.handle_export().await,
            MnemonicResponse::export_success(ResponseData(mnemonic))
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn test_delete() {
        // create a service
        let mut gg20 = get_service();
        // add some data to the kv store
        let mnemonic: Mnemonic = vec![42; 32];

        // delete should fail
        assert_eq!(gg20.handle_delete().await, MnemonicResponse::fail());
        // import should succeed
        assert_eq!(
            gg20.handle_import(mnemonic.clone()).await,
            MnemonicResponse::import_success()
        );
        // delete should succeed
        assert_eq!(
            gg20.handle_delete().await,
            MnemonicResponse::delete_success()
        );
        // export should now fail
        assert_eq!(gg20.handle_export().await, MnemonicResponse::fail());
        // delete should now fail
        assert_eq!(gg20.handle_delete().await, MnemonicResponse::fail());
    }
}
