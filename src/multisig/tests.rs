use crate::{addr, encrypted_sled::get_test_password, kv_manager::KvManager, proto};
use tokio::{self, net::TcpListener, sync::oneshot};
use tokio_stream::wrappers::TcpListenerStream;

use super::service::new_service;

use testdir::testdir;
use tracing::{info, warn};
use tracing_test::traced_test;

#[traced_test]
#[tokio::test]
async fn test_multisig() {
    let root = testdir!();
    let kv_manager = KvManager::new(root.to_str().unwrap(), get_test_password())
        .unwrap()
        .handle_mnemonic(&crate::mnemonic::Cmd::Create)
        .await
        .unwrap();

    let service = new_service(kv_manager);
    let service = proto::multisig_server::MultisigServer::new(service);

    let incoming = TcpListener::bind(addr(0)).await.unwrap(); // use port 0 and let the OS decide
    let server_addr = incoming.local_addr().unwrap();

    let (shutdown_sender, shutdown_receiver) = oneshot::channel::<()>();

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(incoming), async {
                shutdown_receiver.await.unwrap();
            })
            .await
            .unwrap();
    });

    let mut client =
        proto::multisig_client::MultisigClient::connect(format!("http://{}", server_addr))
            .await
            .unwrap();

    let request = proto::KeygenRequest {
        key_uid: "some key".to_string(),
        party_uid: "party".to_string(),
    };

    let response = client.keygen(request).await.unwrap().into_inner();

    match response.keygen_response {
        Some(proto::keygen_response::KeygenResponse::PubKey(_)) => {
            info!("Got pub key!")
        }
        Some(proto::keygen_response::KeygenResponse::Error(err)) => {
            warn!("Got error from keygen: {}", err)
        }
        None => {
            panic!("Invalid keygen response. Could not convert i32 to enum")
        }
    }

    let _ = shutdown_sender.send(()).unwrap();
}
