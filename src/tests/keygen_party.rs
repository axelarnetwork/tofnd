use super::{
    addr, gg20,
    mock::{self, Party, PartyMap},
    proto,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
};
use tonic::Request;

// TODO temporary to satisfy clippy
type ServerPair = (
    JoinHandle<Result<(), tonic::transport::Error>>,
    tokio::sync::oneshot::Sender<()>,
);

// #[derive(Debug)]
pub struct KeygenParty {
    party_map: Option<PartyMap>,
    // shutdown_sender: tokio::sync::oneshot::Sender<()>,
    // server_handle: JoinHandle<Result<(), tonic::transport::Error>>,
    server: Option<ServerPair>, // (server_handle, shutdown_sender)
    server_addr: SocketAddr,
    keygen_init: proto::KeygenInit,
    my_id_index: usize, // sanitized from keygen_init
    tx: Sender<proto::MessageIn>,
    rx: Option<Receiver<proto::MessageIn>>,
}

impl KeygenParty {
    pub async fn new(init: &proto::KeygenInit) -> KeygenParty {
        use std::convert::TryFrom;
        let my_id_index = usize::try_from(init.my_party_index).unwrap();

        // start server
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        // TODO set port 0 and let the OS decide
        let server_addr = addr(50051 + my_id_index).unwrap();
        println!(
            "party [{}] grpc addr {:?}",
            init.party_uids[my_id_index], server_addr
        );
        let my_service = gg20::new_service();
        let proto_service = proto::gg20_server::Gg20Server::new(my_service);
        let server_handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(proto_service)
                .serve_with_shutdown(server_addr, async {
                    shutdown_receiver.await.ok();
                })
                .await
        });

        let (tx, rx) = tokio::sync::mpsc::channel(4);

        // TODO get the server to notify us after it's started, or perhaps just "yield" here
        println!(
            "party [{}] TODO sleep waiting for server to start...",
            init.party_uids[my_id_index]
        );
        tokio::time::delay_for(std::time::Duration::from_millis(100)).await;

        Self {
            party_map: None,
            server: Some((server_handle, shutdown_sender)),
            // shutdown_sender,
            // server_handle,
            server_addr,
            keygen_init: init.clone(),
            my_id_index,
            tx,
            rx: Some(rx),
        }
    }
}

#[tonic::async_trait]
impl Party for KeygenParty {
    fn get_id(&self) -> &str {
        &self.keygen_init.party_uids[self.my_id_index]
    }
    fn get_tx(&self) -> Sender<proto::MessageIn> {
        self.tx.clone()
    }
    fn set_party_map(&mut self, party_map: PartyMap) {
        self.party_map = Some(party_map);
    }

    async fn execute(&mut self) {
        assert!(self.party_map.is_some());
        assert!(self.rx.is_some());
        println!("party [{}] connect to server...", self.get_id());
        let mut client =
            proto::gg20_client::Gg20Client::connect(format!("http://{}", self.server_addr))
                .await
                .unwrap();

        let mut from_server = client
            .keygen(Request::new(self.rx.take().unwrap()))
            .await
            .unwrap()
            .into_inner();

        // the first outbound message is keygen init info
        self.tx
            .send(proto::MessageIn {
                data: Some(proto::message_in::Data::KeygenInit(
                    self.keygen_init.clone(), // TODO clone
                )),
            })
            .await
            .unwrap();

        while let Some(msg) = from_server.message().await.unwrap() {
            let msg_type = msg.data.as_ref().expect("missing data");

            match msg_type {
                proto::message_out::Data::Traffic(_) => {
                    mock::deliver(
                        Arc::clone(&self.party_map.as_ref().unwrap()),
                        &msg,
                        &self.get_id().to_string(), // TODO clone
                    )
                    .await;
                }
                proto::message_out::Data::KeygenResult(_) => {
                    println!("party [{}] keygen finished!", self.get_id());
                    break;
                }
                _ => panic!("bad outgoing message type"),
            };
        }
        println!("party [{}] execution complete", self.get_id());
    }

    // async fn msg_in(&mut self, msg: &proto::MessageIn) {
    //     // sanity checks and debug info
    //     {
    //         let msg = msg.data.as_ref().expect("missing data");
    //         let msg = match msg {
    //             proto::message_in::Data::Traffic(t) => t,
    //             _ => panic!("all incoming messages must be traffic in"),
    //         };
    //         println!(
    //             "incoming msg from [{}] to me [{}] broadcast? [{}]",
    //             msg.from_party_uid,
    //             self.get_id(),
    //             msg.is_broadcast
    //         );
    //     }
    //     self.tx.send(msg.clone()).await.unwrap();
    // }

    async fn close(&mut self) {
        let my_id = self.get_id().to_string(); // fighting the borrow checker
        let (server_handle, shutdown_sender) = self.server.take().expect("missing server");
        shutdown_sender.send(()).unwrap(); // tell the server to shut down
        server_handle.await.unwrap().unwrap(); // wait for server to shut down
        println!("party [{}] shutdown success", my_id);
    }
}
