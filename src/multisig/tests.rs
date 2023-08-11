use crate::{
    addr,
    encrypted_sled::get_test_password,
    kv_manager::KvManager,
    proto::Algorithm,
    tests::{DEFAULT_TEST_IP, DEFAULT_TEST_PORT},
};
use tokio::{
    self,
    net::TcpListener,
    sync::oneshot::{channel, Sender},
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Channel;

use super::service::new_service;

use testdir::testdir;
use tracing::error;
use tracing_test::traced_test;

use std::convert::TryInto;

use crate::proto::{
    key_presence_response::Response::Present, keygen_response::KeygenResponse,
    multisig_client::MultisigClient, multisig_server::MultisigServer, sign_response::SignResponse,
    KeyPresenceRequest, KeygenRequest, SignRequest,
};

// set up tests
async fn spin_test_service_and_client() -> (MultisigClient<Channel>, Sender<()>) {
    // create root directory for service
    let root = testdir!();

    // create a kv_manager
    let kv_manager = KvManager::new(root, get_test_password())
        .unwrap()
        .handle_mnemonic(&crate::mnemonic::Cmd::Create)
        .await
        .unwrap();

    // create service
    let service = new_service(kv_manager);
    let service = MultisigServer::new(service);

    // create incoming tcp server for service
    let incoming = TcpListener::bind(addr(DEFAULT_TEST_IP, DEFAULT_TEST_PORT).unwrap())
        .await
        .unwrap();

    // create shutdown channels
    let (shutdown_sender, shutdown_receiver) = channel::<()>();

    // get server's address
    let server_addr = incoming.local_addr().unwrap();

    // spin up multisig gRPC server with incoming shutdown
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(incoming), async {
                shutdown_receiver.await.unwrap();
            })
            .await
            .unwrap();
    });

    // create a client to multisig service
    let client = MultisigClient::connect(format!("http://{}", server_addr))
        .await
        .unwrap();

    // return the client and the shutdown channel for the service
    (client, shutdown_sender)
}

// dummy ctor for KeygenResult
impl KeygenRequest {
    fn new(key_uid: &str, algorithm: Algorithm) -> KeygenRequest {
        KeygenRequest {
            key_uid: key_uid.to_string(),
            party_uid: String::default(),
            algorithm: algorithm as i32,
        }
    }
}

// dummy ctor for KeygenResult
impl SignRequest {
    fn new(key_uid: &str, algorithm: Algorithm) -> SignRequest {
        SignRequest {
            key_uid: key_uid.to_string(),
            msg_to_sign: vec![32; 32],
            party_uid: String::default(),
            pub_key: vec![],
            algorithm: algorithm as i32,
        }
    }
}

// vec to array
fn to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

#[traced_test]
#[tokio::test]
async fn test_multisig_ecdsa_keygen_sign() {
    let key = "multisig key";
    let (mut client, shutdown_sender) = spin_test_service_and_client().await;

    let request = KeygenRequest::new(key, Algorithm::Ecdsa);

    let response = client.keygen(request).await.unwrap().into_inner();
    let pub_key = match response.keygen_response.unwrap() {
        KeygenResponse::PubKey(pub_key) => pub_key,
        KeygenResponse::Error(err) => {
            panic!("Got error from keygen: {}", err);
        }
    };

    let request = SignRequest::new(key, Algorithm::Ecdsa);
    let msg_digest = request.msg_to_sign.as_slice().try_into().unwrap();
    let response = client.sign(request).await.unwrap().into_inner();
    let signature = match response.sign_response.unwrap() {
        SignResponse::Signature(signature) => signature,
        SignResponse::Error(err) => {
            panic!("Got error from sign: {}", err)
        }
    };

    shutdown_sender.send(()).unwrap();

    assert!(tofn::ecdsa::verify(&to_array(pub_key), &msg_digest, &signature,).unwrap());
}

#[traced_test]
#[tokio::test]
async fn test_multisig_ed25519_keygen_sign() {
    let key = "multisig key";
    let (mut client, shutdown_sender) = spin_test_service_and_client().await;

    let request = KeygenRequest::new(key, Algorithm::Ed25519);

    let response = client.keygen(request).await.unwrap().into_inner();
    let pub_key = match response.keygen_response.unwrap() {
        KeygenResponse::PubKey(pub_key) => pub_key,
        KeygenResponse::Error(err) => {
            panic!("Got error from keygen: {}", err);
        }
    };

    let request = SignRequest::new(key, Algorithm::Ed25519);
    let msg_digest = request.msg_to_sign.as_slice().try_into().unwrap();
    let response = client.sign(request).await.unwrap().into_inner();
    let signature = match response.sign_response.unwrap() {
        SignResponse::Signature(signature) => signature,
        SignResponse::Error(err) => {
            panic!("Got error from sign: {}", err)
        }
    };

    shutdown_sender.send(()).unwrap();

    assert!(tofn::ed25519::verify(&to_array(pub_key), &msg_digest, &signature,).unwrap());
}

#[traced_test]
#[tokio::test]
async fn test_multisig_keygen_deterministic_and_unique_keys() {
    let key = "multisig key";
    let (mut client, shutdown_sender) = spin_test_service_and_client().await;

    let mut seen_pub_keys = std::collections::HashSet::new();

    for algorithm in [Algorithm::Ecdsa, Algorithm::Ed25519] {
        let request = KeygenRequest::new(key, algorithm);

        let response = client.keygen(request.clone()).await.unwrap().into_inner();
        let pub_key1 = match response.keygen_response.unwrap() {
            KeygenResponse::PubKey(pub_key) => pub_key,
            KeygenResponse::Error(err) => {
                panic!("Got error from keygen: {}", err);
            }
        };

        let response = client.keygen(request).await.unwrap().into_inner();
        let pub_key2 = match response.keygen_response.unwrap() {
            KeygenResponse::PubKey(pub_key) => pub_key,
            KeygenResponse::Error(err) => {
                panic!("Got error from keygen: {}", err);
            }
        };

        assert_eq!(pub_key1, pub_key2);

        assert!(seen_pub_keys.insert(pub_key1));
    }

    shutdown_sender.send(()).unwrap();
}

#[traced_test]
#[tokio::test]
async fn test_multisig_only_sign() {
    let key = "multisig key";
    let (mut client, shutdown_sender) = spin_test_service_and_client().await;

    for algorithm in [Algorithm::Ecdsa, Algorithm::Ed25519] {
        let request = SignRequest::new(key, algorithm);
        let response = client.sign(request).await.unwrap().into_inner();
        let _ = match response.sign_response.unwrap() {
            SignResponse::Signature(signature) => signature,
            SignResponse::Error(err) => {
                panic!("Got error from sign: {}", err)
            }
        };
    }

    shutdown_sender.send(()).unwrap();
}

#[traced_test]
#[tokio::test]
async fn test_multisig_short_key_fail() {
    let key = "k"; // too short key
    let (mut client, shutdown_sender) = spin_test_service_and_client().await;

    for algorithm in [Algorithm::Ecdsa, Algorithm::Ed25519] {
        let keygen_request = KeygenRequest::new(key, algorithm);
        let keygen_response = client.keygen(keygen_request).await.unwrap().into_inner();

        if let KeygenResponse::Error(err) = keygen_response.clone().keygen_response.unwrap() {
            error!("{}", err);
        }
        assert!(matches!(
            keygen_response.keygen_response.unwrap(),
            KeygenResponse::Error(_)
        ));

        let sign_request = SignRequest::new(key, algorithm);
        let sign_response = client.sign(sign_request).await.unwrap().into_inner();

        if let SignResponse::Error(err) = sign_response.clone().sign_response.unwrap() {
            error!("{}", err);
        }
        assert!(matches!(
            sign_response.sign_response.unwrap(),
            SignResponse::Error(_)
        ));
    }

    shutdown_sender.send(()).unwrap();
}

#[traced_test]
#[tokio::test]
async fn test_multisig_truncated_msg_fail() {
    let key = "key-uid";
    let (mut client, shutdown_sender) = spin_test_service_and_client().await;

    for algorithm in [Algorithm::Ecdsa, Algorithm::Ed25519] {
        // attempt sign with truncated msg digest
        let mut request = SignRequest::new(key, algorithm);
        request.msg_to_sign = vec![32; 31];
        let response = client.sign(request.clone()).await.unwrap().into_inner();
        if let SignResponse::Error(err) = response.clone().sign_response.unwrap() {
            error!("{}", err);
        }
        assert!(matches!(
            response.sign_response.unwrap(),
            SignResponse::Error(_)
        ));
    }

    shutdown_sender.send(()).unwrap();
}

#[traced_test]
#[tokio::test]
async fn test_key_presence() {
    let (mut client, shutdown_sender) = spin_test_service_and_client().await;

    for algorithm in [Algorithm::Ecdsa, Algorithm::Ed25519] {
        let presence_request = KeyPresenceRequest {
            key_uid: "key_uid".to_string(),
            pub_key: vec![],
            algorithm: algorithm as i32,
        };

        let response = client
            .key_presence(presence_request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.response, Present as i32);
    }

    shutdown_sender.send(()).unwrap();
}
